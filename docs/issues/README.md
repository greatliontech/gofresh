# Open issues

- [cgo-raw-string-false-positive-on-ordinary-string-literals](cgo-raw-string-false-positive-on-ordinary-string-literals.md)
  — `cgoNativeFileHasRawString` uses `strings.Contains(text, "R\"")` before lexical scanning, false-positiving on any ordinary C string literal ending in `R` (e.g. `"META_DOLLAR"`, `"R"`) or comment containing `R"`; includes a self-contained reproducer and lexical specification.
