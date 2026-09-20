# guidance — the fleet's tool-resident guidance format

The `guidance` package parses and renders the structured guidance
document every surfaced tool in the fleet embeds and serves: the
single source for what a verb does, what a knob controls, and when
to use which — answered FROM the tool, over both its surfaces,
MCP-first. A consuming tool embeds its guidance source at build
time (the tool's repository is absent where its binary runs),
derives its tool-level served prose from the parsed document at
initialization, and binds a coverage requirement so the wire
surface and the document cannot drift.

## Vocabulary

**guidance document** (term): one dedicated markdown file per tool
(`docs/guidance.md`), the single home of verb-level guidance prose.
The document is repository documentation first; the tool serves the
same bytes. Because `//go:embed` cannot traverse upward, the
embedding package sits at or above the document's directory —
repo-root packages embed `docs/guidance.md` directly; a repo whose
layout cannot satisfy that places the document beside its embedding
package, never a build-time copy (a copy is the second home this
format exists to delete).

**verb section** (term): the per-verb unit of the document — the
verb's surfaces, one-line purpose, knobs, decision guidance, and
example.

**surface** (term): one of the tool's serving faces, `mcp` or
`cli`. A verb section — and each knob item — names the surfaces it
exists on and may name a per-surface spelling (an MCP tool named
`attest_requirement` may be the CLI's `attest requirement`; an MCP
parameter `test_pkg` may be the CLI's `test-pkg` flag); absent a
declaration, both surfaces under the canonical name. Per-surface
verb spellings are unique across the document — two sections
resolving to one spelling on one surface refuse at parse, exactly
as duplicate headings do.

**decision map** (term): the document's cross-verb section — "use
X when …, prefer Y when …" — served whole where a caller asks for
orientation rather than a specific verb.

## Format

**REQ-guidance-format** (wire): A guidance document MUST parse as
markdown with this structure, the parser refusing — with the first
offending heading or field named — any document that does not:
carriage returns normalize away first; a top-level `# ` title with
non-empty text; one `## verbs` section containing one `### <verb>`
subsection per verb, verb headings unique and per-surface spellings
unique per surface; one final `## decision map` section whose
entire non-empty body is the decision map. Each verb subsection
carries these fields, in order, each a bolded label starting a
line: optionally `**surfaces:**` followed by a same-line
comma-separated list of `mcp` or `cli` entries, each optionally
`<surface> as <name>` (unknown surfaces, duplicate surfaces, an
empty list, a dangling `as`, and continuation lines refuse; the
field absent means both surfaces under the heading name);
`**does:**` with the non-empty one-line purpose beginning on the
label's own line; `**knobs:**` followed by zero or more single-line
items of the form `` - `name` (surfaces) — prose `` — the
parenthesized surface list optional with the verb-level grammar and
meaning, leading indentation tolerated, the em-dash separator
literal — with knob names unique per verb and their per-surface
spellings unique per verb and surface, or the literal `none`;
`**when:**` followed by non-empty prose to the next field;
`**example:**` followed by non-empty prose or fenced code to the
end of the subsection. Fenced code follows the markdown rules the
document renders under: a fence opens on a line indented at most
three spaces carrying three or more backticks (an info string may
follow), closes only on a line indented at most three spaces
carrying at least as many backticks and nothing else, and while
open no line terminates a field or section; a field or document
ending inside an open fence refuses, naming the field. Headings
and field labels share the same indentation rule — up to three
leading spaces tolerated, four or more making the line field
content. A per-surface name may be backtick-wrapped; a half-wrapped
or empty-wrapped name refuses, and an alias equal to the canonical
name refuses as redundant.

**REQ-guidance-render** (behavior): Rendering MUST be a projection of
the parsed document with no synthesized prose, addressed per surface by
the surface's own spelling: the one-line purpose renders verbatim as the
tool-level description (an MCP tool's `Description`, a CLI command's
`Short`); the long rendering of a verb is, in order, the purpose, a
`knobs:` block listing each knob on that surface as its surface spelling
`— prose` (or `knobs: none`), a `when:` block, and an `example:` block
whose body starts on its own line so fenced code stays column-zero —
exactly those labels, no others; the orientation rendering is the
decision map's body verbatim; the knob projection serves one knob of a
verb, the verb addressed by its spelling on the surface and the knob by
its own, the knob verbatim — a knob the verb documents on the other
surface only, an unknown knob, and an unknown verb are refused by name;
and the help rendering is the long rendering without its knobs: block —
for a surface that renders its own knob list (a CLI's flag help), where
the block would print every knob twice in two wordings; and the terse
rendering of a knob the knob projection answered is its first clause —
the prose up to the first semicolon outside parentheses, surrounding
whitespace and a trailing period trimmed, the whole prose where no such
semicolon exists — for a surface rendering one line per knob, which
surface renders the clause and which the whole prose being the consuming
tool's contract; the usage rendering of a knob is its terse clause in a
flag library's usage grammar — code spans lose their back-quotes (a
back-quoted word reads as the flag's value name) and every "(default X)"
parenthetical goes, matched by parenthesis depth so a default naming a
call keeps its own parentheses inside (the library prints a non-zero
default itself), so a knob whose CLI default is non-zero spells it as
"(default X)" and no other default, in any spelling of the word, in its
first clause — the CLI coverage judgment, told which flags carry a
non-zero default, reports any other spelling there as a defect
(REQ-guidance-coverage), a parenthetical that never closes rendering
unchanged and counting as one such spelling; the schema rendering
describes every property of a served input schema at every depth — a
nested object's properties and an array's items alike — with the verb's
knob of the property's own name, its terse clause, refusing by name a
property the document does not knob (the first in the walk's order —
each node's names sorted, its properties before its items), a named
property without a node still requiring its knob and taking no
description, a nil root describing nothing, and it answers the sorted
names it visited — the one enumeration a consumer's coverage judgment
reads, so descriptions and coverage never walk at two depths; and the
registration rendering of a verb on a surface is its spelling, its
purpose, its help, its long rendering, every knob on the surface with
its clause and, on the CLI, its usage (the MCP serves the clause; its
usage is empty there), and the pointer to the knobs' whole prose in the
surface's own form — on the CLI the guidance command under the verb's
CLI spelling, quoted where it carries whitespace ("The knobs' whole
prose: <tool> guidance <verb>."), on the MCP the guidance tool under the
verb's MCP spelling ("The knobs' whole prose: the guidance tool, verb
<verb>.") — the one shape a face registers a command or a tool from. A
requested surface or name the document does not carry is an error, never
an empty rendering; a face's construction refuses such a request naming
the tool once ("<tool>: guidance: <cause>"), and a malformed document
with the embedded form's own refusal.

**REQ-guidance-coverage** (behavior): The package MUST provide the
per-surface coverage judgment a consuming tool's drift binding enforces:
given a surface and the surface's registered verb names each with its
served parameter or flag names, each name carrying whether its CLI
default is non-zero, report as defects — in a deterministic order —
every registered verb no section names on that surface, every registered
parameter or flag absent from its verb's knobs on that surface, every
knob on that surface naming no registered parameter or flag, and every
section on that surface naming no registered verb, and — on the CLI
surface, for the registered flags the caller names as carrying a
non-zero default — every knob whose first clause spells a default
outside the "(default X)" form the usage rendering strips
(REQ-guidance-render); a surface the format does not define is the
caller's error, distinct from the defect list. Coverage is exact in both
directions per surface; a knob the wire does not carry is a document
defect, not a tolerated extra.

## Consuming contract

The authoring convention the projections rely on: `**when:**` and
`**example:**` prose names knobs neutrally — "the check preview",
"the timeout" — never one surface's literal spelling or assignment
syntax, because the help rendering shows the prose beside only that
surface's own knob list; the knobs block owns names, and each
knob's own prose owns its per-surface spellings.

**REQ-guidance-single-source** (invariant): A consuming tool's
tool-level served prose MUST be read from the parsed document at
initialization — never a second literal. Per-parameter schema and flag
usage strings are the document's knob prose rendered by the package's
own projections — the schema rendering and the usage rendering over
the registration rendering, never a second literal and never a grammar
of the consuming tool's own —
and the coverage judgment, bound per surface in the consuming repo,
keeps them enumerated by the document. The drift guard is structural —
name coverage plus served-bytes identity, the consuming repo's binding
comparing each served knob string with the projection; prose accuracy
against the consuming repo's own spec is review's to hold, not a
mechanical judgment. The package provides the embedded form the tool
reads: its source parsed once, every face answering the one parse, and
a malformed document refused loudly at construction, naming the tool.
Enforced in each consuming repo by its guidance requirement and
binding; in this repo the format and projections are enforced by the
package's own tests.
