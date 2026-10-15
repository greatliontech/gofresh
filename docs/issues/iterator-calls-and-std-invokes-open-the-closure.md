# A range-over-func iterator call and a standard-library interface dispatch open the subject's closure

Lands: docs/plans/tooling-redesign.md 7.8.

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

The report does not establish a general failure of range-over-function or
hash interfaces. The current parameter-crossing analysis and SSA-handle
fixtures already include a positive iterator path. The exact `SplitSeq`
return-flow and SHA interface-invoke shapes remain unresolved here; reproduce
those source shapes against current analysis before attributing the refusal.

Any refinement must preserve operand closedness, target completeness and the
standard-library audit boundary. Coordinate the invoke case with
`invoke-targets-narrowed-by-operand.md`; a stable library API alone supplies
neither a closed target set nor authority to ignore unknown behavior.
