# A range-over-func iterator call and a standard-library interface dispatch open the subject's closure

Lands: cross-tool train chunk 260 (the iterator half); the invoke half rides invoke-targets-narrowed-by-operand's landing

Field report (greatliontech/pb, gofresh v0.102.0 through gomutant):
two subjects' observations are refused as "subject reachability is
not closed":

- `internal/archive.validatePath` — "computed function call in
  validatePath": the call is `strings.SplitSeq(p, "/")` consumed by
  a range statement, the standard library's own iterator; the
  analyzer's computed-call arm (`closure/analyzer.go`, the
  `requestWiden("computed function call in …")` route) treats the
  range statement's call of the yielded function as an unresolved
  computed call.
- `internal/archive.writeMember` — "interface invoke outside RTA:
  writeMember dispatches hash.Hash.Sum": the hash is a
  `crypto/sha256` value constructed in the same binary; the invoke
  arm reports it outside the program's type analysis.

Both are stable standard-library shapes a subject cannot restructure
away from — every range over a `Seq` and every `hash.Hash` use opens
the closure the same way — so the refusal is the analyzer's to
close: the iterator's yield bound by the subject's range statement
(closure.md already names that binding) and a std-constructed
concrete type behind an interface operand resolved through the
program's method sets (the invoke narrowing sketched in
`invoke-targets-narrowed-by-operand`).
