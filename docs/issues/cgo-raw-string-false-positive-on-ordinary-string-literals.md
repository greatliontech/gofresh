# `cgoNativeFileHasRawString` false-positives on ordinary C string literals ending in `R`

Lands: next `closure` C/cgo include-scanner fix (`closure/closure.go`); self-contained reproducer and acceptance criteria below require no external repository checkout.

## Problem statement

In `closure/closure.go` (`cgoEscapingInclude`, lines 922–945, and `cgoNativeFileHasRawString`, lines 1043–1045):

```go
text = spliceCPreprocessorLines(text)
if cgoNativeFileHasRawString(rel, text) {
	return "", fmt.Errorf("closure: unsupported cgo raw string in %s", path)
}
lines := strings.Split(text, "\n")
if !goFile {
	lines = stripCBlockComments(lines)
}
```

where `cgoNativeFileHasRawString` is currently:

```go
func cgoNativeFileHasRawString(_ string, text string) bool {
	return strings.Contains(text, "R\"")
}
```

### Intended invariant (`REQ-closure-coverage`)

`cgoEscapingInclude` scans native C/C++/Objective-C source and header files in a cgo package to ensure no `#include` or `#import` directive escapes the package directory (`p.Dir`). Because C++11 raw string literals (`R"delimiter(raw_characters)delimiter"`, plus encoding-prefixed forms `u8R"`, `uR"`, `UR"`, `LR"`) can embed arbitrary `/*`, `*/`, `//`, and newline sequences without escaping, `stripCBlockComments` and `stripCLineComments` (which only track ordinary `"..."` strings and `'...'` character literals) could be desynchronized by a raw string literal containing `/*` or `*/` around an `#include "../cfg.h"` line (pinned by `TestContributionCgoSourceRawStringFailsClosed` and `TestContributionCgoHeaderRawStringFailsClosed` in `closure/closure_test.go:784–833`). Failing closed when a native file actually uses a C++ raw string literal is sound.

### Demonstrated fault

`strings.Contains(text, "R\"")` performs an unlexed substring search over the entire file before comment or string tokenization. Any two-byte sequence `R"` anywhere in a `.c`, `.h`, `.cc`, `.cpp`, `.cxx`, `.hh`, `.hpp`, `.m`, `.mm`, or cgo preamble triggers `closure: unsupported cgo raw string in <path>`, even when no raw string literal is present:

1. **Ordinary string literals whose content ends with uppercase `R`**:
   ```c
   fprintf(stderr, "META_DOLLAR");
   #define STR_R "R"
   static const char *names[] = { "\\R", "OR", "XOR" };
   ```
   Here `R` is the last character inside a standard `"..."` string literal and `"` is the **closing quote** of that string literal.
2. **Escaped quotes following `R` inside an ordinary string literal**:
   ```c
   const char *msg = "expected \"R\" token";
   ```
3. **Line or block comments containing `R"`**:
   ```c
   /* See C++11 R"(...)" syntax or token "OR" */
   // returns "ERR" on failure
   ```

When a workspace or module contains a cgo package with any C source or header containing a string literal ending in `R` (for example, standard C libraries with token names like `"META_DOLLAR"` or `"R"`), `Hasher.contribution` fails with `closure: unsupported cgo raw string in <path>`. Downstream consumers (`stipulator` resolution and certificate opening/publishing) then degrade every operation to typed resolution:

```text
resolution degraded to typed: opening "default": closure: unsupported cgo raw string in <path>.c
```

## Self-contained reproducer

No external repository is needed. In `closure/closure_test.go`, a standard C file with an ordinary string literal ending in `R` currently fails `h.contribution(pkg)`:

```go
func TestContributionCgoOrdinaryStringEndingInRAllowed(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	writeFile(t, dir, "cg.go", "package cgotest\nimport \"C\"\n")
	writeFile(t, dir, "bridge.c", `
#include <stdio.h>
/* Comment mentioning "OR" and R" inside a block comment */
// Line comment mentioning "ERR"
#define STR_R "R"
void bridge(void) {
	fprintf(stderr, "META_DOLLAR");
	const char *escaped = "quoted \"R\" inside string";
	(void)escaped;
}
`)
	h := &Hasher{modCache: filepath.FromSlash("/gomodcache"), ctx: context.Background()}
	pkg := listPkg{
		ImportPath: "example/cgotest",
		Dir:        dir,
		CgoFiles:   []string{"cg.go"},
		CFiles:     []string{"bridge.c"},
		Module:     &listMod{Main: true, Dir: dir},
	}
	if _, err := h.contribution(pkg); err != nil {
		t.Fatalf("contribution error = %v, want nil for ordinary C strings and comments", err)
	}
}
```

## Root cause and lexical requirements

Whether `"` opens a string literal or closes an already-open ordinary string literal depends on lexical state. A single lexical scan over the spliced text (or integrated into comment stripping) must track:

1. **Block comments (`/* ... */`)** and **line comments (`// ... \n`)**: `R"` inside a comment is not a token.
2. **Ordinary string literals (`"..."`)** and **character literals (`'...'`)** with backslash escapes (`\\`, `\"`, `\'`): `R"` inside an ordinary string or formed by the last character `R` + the closing `"` of an ordinary string is not a raw string opener.
3. **Raw string literal openers outside comments, strings, and char literals**:
   In C++11+, a raw string literal begins with a prefix token (`R`, `u8R`, `uR`, `UR`, or `LR`) immediately followed by `"`. Critically:
   - The `"` must **open** a string literal (i.e., the scanner is currently outside any comment, ordinary string literal, or character literal), and
   - The preceding character (or prefix `R` / `u8R` / `uR` / `UR` / `LR`) must not be part of a longer identifier or preprocessing number (or, conservatively and still without false positives on valid C/C++ code, any opening `"` in normal code state that is immediately preceded by `R` plays the role of a raw-string opener because `ident"..."` is only valid in C/C++ when `ident` is a string-literal encoding prefix ending in `R`).

Notice that the conservative rule in (3) — **an opening `"` encountered outside comments, ordinary string literals, and character literals whose immediately preceding byte is `'R'`** — has zero false positives on valid C/C++ ordinary strings, character literals, and comments (because in `fprintf(stderr, "META_DOLLAR")`, the `"` after `R` is a *closing* quote inside `inString == true`, never an *opening* quote in normal code state!), while still catching every `R"...`, `u8R"...`, `uR"...`, `UR"...`, and `LR"...` raw string opener.

Wait: one edge case in (3) to verify is macro concatenation or adjacent tokens in C where an identifier ending in `R` is immediately followed by an opening quote with no whitespace, e.g. `#define FOO(x) ...` or `#define STR_R"foo"` (or `case MACRO_R"literal":`). In C99/C11, `#define NAME"value"` without whitespace between the macro name `NAME` and replacement `"value"` is valid preprocessor syntax (though rare), and in C++11 user-defined literals/macros an identifier ending in `R` could precede `"`. Checking whether the identifier token immediately preceding the opening `"` is specifically one of the five C++ raw-string prefixes (`R`, `u8R`, `uR`, `UR`, `LR`) — i.e., `R` (possibly preceded by `u8`, `u`, `U`, or `L`) not preceded by another `[A-Za-z0-9_]` byte — is equally simple (a 5-line check on the preceding 1–3 bytes) and exact.

## Acceptance criteria

1. **Preserve fail-closed raw-string rejection (`REQ-closure-coverage`)**:
   - `TestContributionCgoSourceRawStringFailsClosed` and `TestContributionCgoHeaderRawStringFailsClosed` continue to fail closed on `R"..."`, as well as encoding-prefixed `u8R"..."`, `uR"..."`, `UR"..."`, and `LR"..."`, and raw strings in `.go` cgo preamble comments.
   - A raw string opened after an ordinary string on the same line (e.g., `const char *a = "ok"; const char *b = R"raw(/*)raw";`) still fails closed.
2. **Eliminate false positives on ordinary strings, char literals, and comments**:
   - Ordinary C/C++ string literals ending in `R` (`"META_DOLLAR"`, `"R"`, `"\\R"`, `"META_ECLASS_OR"`, `"META_ECLASS_XOR"`) in `.c`, `.h`, `.cc`, and cgo preambles succeed without error.
   - Ordinary string literals containing escaped `\"` after `R` (`"foo R\" bar"`) succeed.
   - Line comments (`// ... R" ...`) and block comments (`/* ... R" ... */`) containing `R"` succeed (including in `.go` cgo preambles after comment-marker stripping).
   - Character literals (`'R'` followed by `"..."` or `'\"'`) succeed.
3. **Verification**:
   - Add unit and fixture tests in `closure/closure_test.go` covering all cases above.
   - Run `stipulator check --full` and mutation probes on the scanner in `closure/closure.go`.
