package guidance

import (
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const sample = `# gomutant — guidance

## verbs

### run
**does:** Measure mutants and update the findings document.
**knobs:**
- ` + "`changed`" + ` — target only symbols whose bodies differ from this git ref.
- ` + "`budget`" + ` — candidates per symbol; 0 is exhaustive.
**when:** use run for a judged campaign; prefer ephemeral for one
hand-written probe.
**example:** run with changed=HEAD~1 at a chunk gate.

### ephemeral
**does:** Run one manual mutant without persisting.
**knobs:**
- ` + "`test_pkg` (mcp, cli as `test-pkg`)" + ` — the deciding test's import path.
- ` + "`batch_edits` (mcp)" + ` — inline edits, MCP only.
- ` + "`batch` (cli)" + ` — the batch file path, CLI only.
**when:** use ephemeral inside the adversarial loop.
**example:**
` + "```sh" + `
gomutant ephemeral --batch probe.json
# the deciding test names the kill
` + "```" + `

### attest_requirement
**surfaces:** mcp, cli as attest requirement
**does:** Disposition an equivalent surviving mutant.
**knobs:** none
**when:** use after a survivor is judged equivalent.
**example:** attest with the reasoning on record.

### init
**surfaces:** cli
**does:** Initialize the working layout.
**knobs:** none
**when:** use once per repository.
**example:** run init at adoption.

### read_spec
**does:** Serve a requirement bundle as markdown.
**knobs:** none
**when:** use to orient on a requirement family.
**example:**
` + "````" + `
` + "```md" + `
## decision map
SAMPLE decision map from the example
` + "```" + `
` + "````" + `

## decision map

Use run for campaigns; use ephemeral for single probes.
`

// The format parses into the model and every projection is the
// document's own bytes; fenced examples — nested four-backtick
// wrappers included — swallow heading-like and label-like lines
// (REQ-guidance-format, REQ-guidance-render).
func TestParseAndRenderProjections(t *testing.T) {
	doc, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Title != "gomutant — guidance" || len(doc.Verbs) != 5 {
		t.Fatalf("doc = %+v", doc)
	}
	if got, _ := doc.Description("mcp", "run"); got != "Measure mutants and update the findings document." {
		t.Fatalf("Description(mcp, run) = %q", got)
	}
	// The aliased verb resolves per surface, under each spelling.
	if got, _ := doc.Description("cli", "attest requirement"); got != "Disposition an equivalent surviving mutant." {
		t.Fatalf("Description(cli, attest requirement) = %q", got)
	}
	if got, _ := doc.Description("mcp", "attest_requirement"); got != "Disposition an equivalent surviving mutant." {
		t.Fatalf("Description(mcp, attest_requirement) = %q", got)
	}
	if _, err := doc.Description("mcp", "attest requirement"); err == nil {
		t.Fatal("the cli spelling resolved on mcp")
	}
	if _, err := doc.Description("mcp", "init"); err == nil {
		t.Fatal("the cli-only verb resolved on mcp")
	}
	// Long renders knobs under the surface's spellings, and only the
	// surface's knobs.
	mcpLong, err := doc.Long("mcp", "ephemeral")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"test_pkg — the deciding test's import path.", "batch_edits — inline edits, MCP only."} {
		if !strings.Contains(mcpLong, want) {
			t.Errorf("Long(mcp, ephemeral) missing %q:\n%s", want, mcpLong)
		}
	}
	// The knobs block lists the surface's knobs in document order, whole.
	if want := "knobs:\n  test_pkg — the deciding test's import path.\n  batch_edits — inline edits, MCP only.\n\nwhen:"; !strings.Contains(mcpLong, want) {
		t.Errorf("Long(mcp, ephemeral) knobs block is not the document's order:\n%s", mcpLong)
	}
	if strings.Contains(mcpLong, "batch —") || strings.Contains(mcpLong, "test-pkg") {
		t.Errorf("Long(mcp, ephemeral) leaked cli spellings:\n%s", mcpLong)
	}
	cliLong, err := doc.Long("cli", "ephemeral")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"test-pkg — the deciding test's import path.", "batch — the batch file path, CLI only."} {
		if !strings.Contains(cliLong, want) {
			t.Errorf("Long(cli, ephemeral) missing %q:\n%s", want, cliLong)
		}
	}
	if strings.Contains(cliLong, "batch_edits") {
		t.Errorf("Long(cli, ephemeral) leaked the mcp-only knob:\n%s", cliLong)
	}
	if want := "knobs:\n  test-pkg — the deciding test's import path.\n  batch — the batch file path, CLI only.\n\nwhen:"; !strings.Contains(cliLong, want) {
		t.Errorf("Long(cli, ephemeral) knobs block is not the document's order:\n%s", cliLong)
	}
	// The fenced example survives whole, at column zero.
	if !strings.Contains(mcpLong, "example:\n```sh\ngomutant ephemeral --batch probe.json\n# the deciding test names the kill\n```") {
		t.Errorf("Long(mcp, ephemeral) fenced example mangled:\n%s", mcpLong)
	}
	// The nested four-backtick wrapper: the inner ``` lines do not
	// close the ```` fence, so the sample decision map stays inside
	// the example and the real one serves.
	rsLong, err := doc.Long("mcp", "read_spec")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rsLong, "SAMPLE decision map from the example") || !strings.Contains(rsLong, "````\n```md") {
		t.Errorf("Long(mcp, read_spec) nested fence mangled:\n%s", rsLong)
	}
	// The help rendering drops exactly the knobs block.
	help, err := doc.Help("mcp", "ephemeral")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(help, "knobs:") || strings.Contains(help, "test_pkg") {
		t.Errorf("Help(mcp, ephemeral) carries knobs:\n%s", help)
	}
	for _, want := range []string{"Run one manual mutant without persisting.", "when: use ephemeral", "example:\n```sh"} {
		if !strings.Contains(help, want) {
			t.Errorf("Help(mcp, ephemeral) missing %q:\n%s", want, help)
		}
	}
	if _, err := doc.Help("web", "run"); err == nil {
		t.Error("Help accepted an unknown surface")
	}
	if got := doc.Orientation(); got != "Use run for campaigns; use ephemeral for single probes." {
		t.Fatalf("Orientation() = %q — the sample decision map leaked", got)
	}
	if _, err := doc.Long("web", "run"); err == nil {
		t.Fatal("unknown surface rendered")
	}
}

// A knob is addressed per surface by the verb's and its own spelling
// there, the knob verbatim; a knob documented on the other surface
// only, a sibling verb's knob, an unknown knob, and an unknown verb are
// refused by name (REQ-guidance-render).
func TestKnobIsAddressedPerSurfaceWithItsTextVerbatim(t *testing.T) {
	doc, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	var knobbed []Verb
	for _, v := range doc.Verbs {
		if len(v.Knobs) > 0 {
			knobbed = append(knobbed, v)
		}
	}
	if len(knobbed) == 0 {
		t.Fatal("the sample documents no verb with knobs")
	}
	for _, verb := range knobbed {
		for _, surface := range []string{"mcp", "cli"} {
			vspell, vok := on(verb.Surfaces, verb.Name, surface)
			if !vok {
				continue
			}
			for _, k := range verb.Knobs {
				spelling, exists := on(k.Surfaces, k.Name, surface)
				got, err := doc.Knob(surface, vspell, spelling)
				if !exists {
					if err == nil {
						t.Fatalf("%s: knob %q is not on this surface, yet found: %+v", surface, k.Name, got)
					}
					continue
				}
				if err != nil || !reflect.DeepEqual(got, k) {
					t.Fatalf("%s %s %s: %+v, %v; want %+v", surface, vspell, spelling, got, err, k)
				}
			}
			if _, err := doc.Knob(surface, vspell, "no-such-knob"); err == nil || !strings.Contains(err.Error(), vspell) || !strings.Contains(err.Error(), "no-such-knob") {
				t.Fatalf("%s: an unknown knob: %v; want a refusal naming the verb and the knob", surface, err)
			}
			// A sibling verb's knob is not this verb's: a spelling only
			// the sibling documents on this surface refuses under this verb.
			mine := map[string]bool{}
			for _, kn := range knobsOn(&verb, surface) {
				mine[kn.spelling] = true
			}
			for _, other := range knobbed {
				if other.Name == verb.Name {
					continue
				}
				for _, kn := range knobsOn(&other, surface) {
					if mine[kn.spelling] {
						continue
					}
					if _, err := doc.Knob(surface, vspell, kn.spelling); err == nil {
						t.Fatalf("%s %s: %s's knob %q was served as this verb's", surface, vspell, other.Name, kn.spelling)
					}
				}
			}
		}
	}
	if _, err := doc.Knob("mcp", "no-such-verb", "x"); err == nil {
		t.Fatal("an unknown verb was found")
	}
	// A knob spelled differently per surface is addressed by its
	// spelling there and by nothing else: the mcp name is not a cli
	// spelling, nor the cli spelling an mcp name.
	var spelledVerb string
	for _, v := range doc.Verbs {
		for _, k := range v.Knobs {
			if k.Name == "test_pkg" {
				spelledVerb, _ = on(v.Surfaces, v.Name, "cli")
			}
		}
	}
	if spelledVerb == "" {
		t.Fatal("the sample no longer carries the per-surface-spelled knob")
	}
	if k, err := doc.Knob("cli", spelledVerb, "test-pkg"); err != nil || k.Name != "test_pkg" {
		t.Fatalf("cli spelling: %+v, %v", k, err)
	}
	if _, err := doc.Knob("cli", spelledVerb, "test_pkg"); err == nil {
		t.Fatal("the mcp name found a cli knob")
	}
	mcpVerb := ""
	for _, v := range doc.Verbs {
		if sp, ok := on(v.Surfaces, v.Name, "cli"); ok && sp == spelledVerb {
			mcpVerb, _ = on(v.Surfaces, v.Name, "mcp")
		}
	}
	if _, err := doc.Knob("mcp", mcpVerb, "test-pkg"); err == nil {
		t.Fatal("the cli spelling found an mcp knob")
	}
	if _, err := doc.Knob("web", knobbed[0].Name, "x"); err == nil {
		t.Fatal("an unknown surface was accepted")
	}
}

// Every malformed shape refuses with the offending heading or field
// named (REQ-guidance-format).
func TestParseRefusalsNameTheOffense(t *testing.T) {
	verb := func(bodyOverride string) string {
		return "# t\n\n## verbs\n\n" + bodyOverride + "\n## decision map\nd\n"
	}
	cases := []struct {
		name, src, wants string
	}{
		{"no title", "## verbs\n", "top-level title"},
		{"empty title", "# \n\n## verbs\n", "non-empty top-level title"},
		{"no verbs section", "# t\n\n### run\n", `"## verbs"`},
		{"no decision map", "# t\n\n## verbs\n\n### run\n**does:** x.\n**knobs:** none\n**when:** w\n**example:** e\n", "decision map"},
		{"empty decision map", "# t\n\n## verbs\n\n### run\n**does:** x.\n**knobs:** none\n**when:** w\n**example:** e\n\n## decision map\n\n", "empty decision map"},
		{"field order", verb("### run\n**knobs:** none\n"), "expected field **does:**"},
		{"empty does", verb("### run\n**does:**\n**knobs:** none\n**when:** w\n**example:** e\n"), "purpose on the label's line"},
		{"multiline does", verb("### run\n**does:** a\nb\n**knobs:** none\n**when:** w\n**example:** e\n"), "must be one line"},
		{"empty when", verb("### run\n**does:** x.\n**knobs:** none\n**when:**\n**example:** e\n"), "empty **when:**"},
		{"empty example", verb("### run\n**does:** x.\n**knobs:** none\n**when:** w\n**example:**\n"), "empty **example:**"},
		{"bad knob item", verb("### run\n**does:** x.\n**knobs:**\n- changed — no backticks\n**when:** w\n**example:** e\n"), "- `name` — prose"},
		{"knob without prose", verb("### run\n**does:** x.\n**knobs:**\n- `changed`\n**when:** w\n**example:** e\n"), "— prose"},
		{"duplicate knob", verb("### run\n**does:** x.\n**knobs:**\n- `a` — one.\n- `a` — two.\n**when:** w\n**example:** e\n"), `duplicate knob "a"`},
		{"knob spelling collision", verb("### run\n**does:** x.\n**knobs:**\n- `a` (cli as `x`) — one.\n- `b` (cli as `x`) — two.\n**when:** w\n**example:** e\n"), `cli spelling "x" collides`},
		{"knob bad surface", verb("### run\n**does:** x.\n**knobs:**\n- `a` (web) — one.\n**when:** w\n**example:** e\n"), `unknown surface "web"`},
		{"duplicate verb", verb("### run\n**does:** x.\n**knobs:** none\n**when:** w\n**example:** e\n\n### run\n**does:** x.\n**knobs:** none\n**when:** w\n**example:** e\n"), "duplicate verb"},
		{"alias collision", verb("### attest_requirement\n**surfaces:** mcp, cli as attest\n**does:** x.\n**knobs:** none\n**when:** w\n**example:** e\n\n### attest\n**surfaces:** cli\n**does:** y.\n**knobs:** none\n**when:** w\n**example:** e\n"), `cli spelling "attest" collides with verb "attest_requirement"`},
		{"unknown surface", verb("### run\n**surfaces:** web\n**does:** x.\n**knobs:** none\n**when:** w\n**example:** e\n"), `unknown surface "web"`},
		{"duplicate surface", verb("### run\n**surfaces:** mcp, mcp\n**does:** x.\n**knobs:** none\n**when:** w\n**example:** e\n"), `duplicate surface "mcp"`},
		{"empty surface alias trailing space", verb("### run\n**surfaces:** cli as \n**does:** x.\n**knobs:** none\n**when:** w\n**example:** e\n"), "empty name"},
		{"empty surface alias dangling", verb("### run\n**surfaces:** cli as\n**does:** x.\n**knobs:** none\n**when:** w\n**example:** e\n"), "empty name"},
		{"multi-line surfaces", verb("### run\n**surfaces:** mcp,\ncli\n**does:** x.\n**knobs:** none\n**when:** w\n**example:** e\n"), "one line"},
		{"empty surfaces list", verb("### run\n**surfaces:**\n**does:** x.\n**knobs:** none\n**when:** w\n**example:** e\n"), "empty **surfaces:** list"},
		{"half-wrapped alias", verb("### run\n**does:** x.\n**knobs:**\n- `a` (cli as `x) — one.\n**when:** w\n**example:** e\n"), "malformed backtick-wrapped name"},
		{"empty-wrapped alias", verb("### run\n**does:** x.\n**knobs:**\n- `a` (cli as ``) — one.\n**when:** w\n**example:** e\n"), "malformed backtick-wrapped name"},
		{"double-wrapped alias", verb("### run\n**does:** x.\n**knobs:**\n- `a` (cli as ``x``) — one.\n**when:** w\n**example:** e\n"), "malformed backtick-wrapped name"},
		{"double-wrapped verb alias", verb("### run\n**surfaces:** mcp, cli as ``go run``\n**does:** x.\n**knobs:** none\n**when:** w\n**example:** e\n"), "malformed backtick-wrapped name"},
		{"redundant alias", verb("### run\n**surfaces:** cli as run\n**does:** x.\n**knobs:** none\n**when:** w\n**example:** e\n"), "equals the canonical name"},
		{"unterminated fence in example", "# t\n\n## verbs\n\n### run\n**does:** x.\n**knobs:** none\n**when:** w\n**example:**\n```sh\nnever closed\n\n## decision map\nd\n", "**example:** ends inside an open fenced code block"},
		{"unterminated fence in when", "# t\n\n## verbs\n\n### run\n**does:** x.\n**knobs:** none\n**when:**\nprose\n```sh\nnever closed\n**example:** e\n\n## decision map\nd\n", "**when:** ends inside an open fenced code block"},
		{"trailing section", "# t\n\n## verbs\n\n### run\n**does:** x.\n**knobs:** none\n**when:** w\n**example:** e\n\n## decision map\nd\n\n## extra\n", "final section"},
		{"no verbs at all", "# t\n\n## verbs\n\n## decision map\nd\n", "no verb sections"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.src))
			if err == nil || !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("Parse err = %v, want containing %q", err, tc.wants)
			}
		})
	}
	// Firstness with two simultaneous offenses: the earlier one names
	// the refusal.
	_, err := Parse([]byte("# t\n\n## verbs\n\n### run\n**knobs:** none\n**does:**\n**when:** w\n**example:** e\n\n## decision map\nd\n"))
	if err == nil || !strings.Contains(err.Error(), "expected field **does:**") {
		t.Fatalf("two offenses: err = %v, want the first (field order)", err)
	}
}

// The fence model is the markdown one: a 4-space-indented backtick
// line is indented code (no fence opens; the following heading
// terminates normally), and a fence line indented up to three
// spaces toggles (REQ-guidance-format).
func TestFenceIndentationFollowsMarkdown(t *testing.T) {
	// A SINGLE indented backtick line: under the markdown rule it is
	// inert content; a parser that treated it as a fence opener would
	// swallow the next section whole.
	src := "# t\n\n## verbs\n\n### run\n**does:** x.\n**knobs:** none\n**when:** w\n**example:**\nindented sample:\n\n    ```\n\n### walk\n**does:** y.\n**knobs:** none\n**when:** w\n**example:** e\n\n## decision map\nd\n"
	doc, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("indented code refused: %v", err)
	}
	if len(doc.Verbs) != 2 {
		t.Fatalf("verbs = %d, want 2 — the indented backticks swallowed a section", len(doc.Verbs))
	}
	if ex := doc.Verbs[0].Example; !strings.Contains(ex, "    ```") {
		t.Fatalf("indented code lost from the example: %q", ex)
	}
}

// Headings and field labels share the fence's indentation rule: up
// to three leading spaces are structural, four or more are content
// — so an indented section is a verb, never silently swallowed
// prose (REQ-guidance-format).
func TestIndentedStructureFollowsMarkdown(t *testing.T) {
	src := "# t\n\n## verbs\n\n### run\n**does:** x.\n**knobs:** none\n**when:** w\n**example:** e\n\n  ### walk\n  **does:** y.\n  **knobs:** none\n  **when:** w\n  **example:** e\n\n## decision map\nd\n"
	doc, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("indented section refused: %v", err)
	}
	if len(doc.Verbs) != 2 {
		t.Fatalf("verbs = %d, want 2 — the indented section was swallowed", len(doc.Verbs))
	}
	if got, err := doc.Description("mcp", "walk"); err != nil || got != "y." {
		t.Fatalf("Description(mcp, walk) = %q, %v", got, err)
	}
	// Four-plus spaces are content, not structure.
	deep := "# t\n\n## verbs\n\n### run\n**does:** x.\n**knobs:** none\n**when:** w\n**example:** e\n\n    ### not a heading\n\n## decision map\nd\n"
	doc, err = Parse([]byte(deep))
	if err != nil || len(doc.Verbs) != 1 {
		t.Fatalf("deep-indented heading: verbs=%d err=%v", len(doc.Verbs), err)
	}
	if !strings.Contains(doc.Verbs[0].Example, "### not a heading") {
		t.Fatalf("deep-indented content lost: %q", doc.Verbs[0].Example)
	}
	// An indented trailing section refuses exactly as the unindented
	// form does — never swallowed into the orientation.
	trailing := "# t\n\n## verbs\n\n### run\n**does:** x.\n**knobs:** none\n**when:** w\n**example:** e\n\n## decision map\nd\n\n  ## extra\n"
	if _, err := Parse([]byte(trailing)); err == nil || !strings.Contains(err.Error(), "final section") {
		t.Fatalf("indented trailing section: err = %v", err)
	}
}

// Carriage returns normalize away before parsing; served prose
// carries none (REQ-guidance-format).
func TestParseNormalizesCarriageReturns(t *testing.T) {
	crlf := strings.ReplaceAll(sample, "\n", "\r\n")
	doc, err := Parse([]byte(crlf))
	if err != nil {
		t.Fatal(err)
	}
	long, _ := doc.Long("mcp", "run")
	if strings.Contains(long, "\r") || strings.Contains(doc.Orientation(), "\r") {
		t.Fatalf("carriage return leaked into served prose: %q", long)
	}
}

// Coverage judges the document against one surface — verb and knob
// spellings resolve per surface, divergences report in both
// directions, and the defect order is deterministic and pinned
// (REQ-guidance-coverage).
func TestCoverageIsExactPerSurface(t *testing.T) {
	doc, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	exact := func(surface string, registered map[string]Registered) {
		t.Helper()
		defects, err := doc.Coverage(surface, registered)
		if err != nil || len(defects) != 0 {
			t.Fatalf("exact %s surface: defects=%v err=%v", surface, defects, err)
		}
	}
	exact("mcp", map[string]Registered{
		"run":                knobs("changed", "budget"),
		"ephemeral":          knobs("test_pkg", "batch_edits"),
		"attest_requirement": knobs(),
		"read_spec":          knobs(),
	})
	exact("cli", map[string]Registered{
		"run":                knobs("budget", "changed"),
		"ephemeral":          knobs("test-pkg", "batch"),
		"attest requirement": knobs(),
		"init":               knobs(),
		"read_spec":          knobs(),
	})
	// Divergences, both directions, exact deterministic order —
	// six registered verbs and three undocumented knobs on one verb so
	// a neutered sort has no lucky escape; the registration is a map,
	// so the order is the judgment's own and the call repeats to catch
	// a map-order leak.
	want := []string{
		`registered mcp verb "discover" has no guidance section`,
		`registered mcp verb "explain" has no guidance section`,
		`registered mcp verb "findings" has no guidance section`,
		`registered mcp verb "prune" has no guidance section`,
		`verb "run": registered knob "aaa" undocumented`,
		`verb "run": registered knob "jobs" undocumented`,
		`verb "run": registered knob "zzz" undocumented`,
		`verb "run": documented knob "budget" not registered`,
		`guidance section "ephemeral" (as mcp "ephemeral") names no registered verb`,
		`guidance section "attest_requirement" (as mcp "attest_requirement") names no registered verb`,
	}
	for i := 0; i < 20; i++ {
		got, err := doc.Coverage("mcp", map[string]Registered{
			"run":       knobs("changed", "jobs", "zzz", "aaa"),
			"discover":  knobs(),
			"findings":  knobs(),
			"explain":   knobs(),
			"prune":     knobs(),
			"read_spec": knobs(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("Coverage order/content:\ngot  %v\nwant %v", got, want)
		}
	}
	// The cli spelling of a knob is a defect when registered on mcp.
	defects, err := doc.Coverage("mcp", map[string]Registered{
		"run":                knobs("changed", "budget"),
		"ephemeral":          knobs("test-pkg", "batch_edits"),
		"attest_requirement": knobs(),
		"read_spec":          knobs(),
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(defects, "\n")
	for _, want := range []string{
		`verb "ephemeral": registered knob "test-pkg" undocumented`,
		`verb "ephemeral": documented knob "test_pkg" not registered`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("cross-surface knob spelling not caught: want %q in\n%s", want, joined)
		}
	}
	// An unknown surface is the caller's error, not a defect.
	if _, err := doc.Coverage("web", nil); err == nil || !strings.Contains(err.Error(), `unknown surface "web"`) {
		t.Fatalf("unknown surface: err = %v", err)
	}
	// The cli-only section never leaks onto the mcp judgment.
	defects, err = doc.Coverage("mcp", map[string]Registered{
		"run": knobs("changed", "budget"), "ephemeral": knobs("test_pkg", "batch_edits"),
		"attest_requirement": knobs(), "read_spec": knobs(), "init": knobs(),
	})
	if err != nil || len(defects) != 1 || !strings.Contains(defects[0], `registered mcp verb "init" has no guidance section`) {
		t.Fatalf("cli-only verb on mcp: %v err=%v", defects, err)
	}
	// Two documented knobs unregistered on one verb report in document
	// order — the one walk's order, pinned as a whole list.
	if got, err := doc.Coverage("mcp", map[string]Registered{"ephemeral": knobs()}); err != nil || len(got) < 2 || got[0] != `verb "ephemeral": documented knob "test_pkg" not registered` || got[1] != `verb "ephemeral": documented knob "batch_edits" not registered` {
		t.Errorf("two documented-side defects = %q, %v; want the registered verb's knobs first, in document order", got, err)
	}
}

// For any model-generated valid document — fenced examples, surface
// declarations, and knob spellings included — Parse reconstructs
// the model exactly and per-surface Coverage of the exact surface
// is empty: the format grammar's for-all pin, swept over a seeded
// generator (REQ-guidance-format, REQ-guidance-render,
// REQ-guidance-coverage). Standard library only: this repo carries
// no property-test dependency.
func TestParseReconstructsGeneratedDocuments(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	proseRunes := []rune("abcdefghij ,;=~/.()-XYZ")
	proseFrom := func(runes []rune) string {
		n := 1 + rng.Intn(50)
		r := make([]rune, n)
		for i := range r {
			r[i] = runes[rng.Intn(len(runes))]
		}
		return "A" + strings.TrimSpace(string(r)) + "z"
	}
	prose := func() string { return proseFrom(proseRunes) }
	// The prose alphabet cannot spell "default", so a knob's default
	// spelling is drawn apart and spliced at the head of its text —
	// inside the first clause whatever the prose's own separators do:
	// none; the one form the usage rendering strips; the word in
	// prose; the form unclosed (over a prose without parentheses, so
	// the prose cannot close it). With the registered printed fact
	// drawn per knob, the CLI coverage's row is predicted from the two
	// draws alone (REQ-guidance-coverage).
	const drawNone, drawForm, drawProse, drawUnclosed = 0, 1, 2, 3
	type knobDraw struct {
		shape   int
		printed bool
		omitted bool // left out of the registration: its one row the not-registered one
	}
	draws := map[string]knobDraw{}
	for iter := 0; iter < 250; iter++ {
		var b strings.Builder
		b.WriteString("# t\n\n## verbs\n")
		type model struct {
			surfaces []SurfaceName
			does     string
			knobs    []Knob
			when     string
			ex       string
		}
		models := map[string]model{}
		for vi := 0; vi < 1+rng.Intn(4); vi++ {
			name := fmt.Sprintf("v%d%c", vi, 'a'+rune(rng.Intn(26)))
			m := model{does: prose(), when: prose()}
			switch rng.Intn(4) {
			case 0:
				m.surfaces = []SurfaceName{{Surface: "mcp", Name: name}}
			case 1:
				m.surfaces = []SurfaceName{{Surface: "cli", Name: "x " + name}}
			case 2:
				m.surfaces = []SurfaceName{{Surface: "mcp", Name: name}, {Surface: "cli", Name: "x " + name}}
			}
			if rng.Intn(2) == 0 {
				m.ex = prose()
			} else {
				m.ex = "```sh\n# " + prose() + "\n**not a label**\n```"
			}
			for ki := 0; ki < rng.Intn(4); ki++ {
				k := Knob{Name: fmt.Sprintf("k%d", ki), Text: prose()}
				draw := knobDraw{shape: rng.Intn(4), printed: rng.Intn(2) == 0, omitted: rng.Intn(6) == 0}
				switch draw.shape {
				case drawForm:
					k.Text = "(default 3) " + k.Text
				case drawProse:
					k.Text = "default is 3 " + k.Text
				case drawUnclosed:
					k.Text = "(default 3 " + proseFrom([]rune("abcdefghij ,;=~/.-XYZ"))
				}
				draws[name+"\x00"+k.Name] = draw
				if rng.Intn(3) == 0 {
					// Spellings resolve at parse: the no-alias mcp
					// entry carries the canonical name.
					k.Surfaces = []SurfaceName{{Surface: "mcp", Name: k.Name}, {Surface: "cli", Name: k.Name + "-flag"}}
				}
				m.knobs = append(m.knobs, k)
			}
			models[name] = m
			b.WriteString("\n### " + name + "\n")
			if len(m.surfaces) > 0 {
				var entries []string
				for _, s := range m.surfaces {
					if s.Name == name {
						entries = append(entries, s.Surface)
					} else {
						entries = append(entries, s.Surface+" as "+s.Name)
					}
				}
				b.WriteString("**surfaces:** " + strings.Join(entries, ", ") + "\n")
			}
			b.WriteString("**does:** " + m.does + "\n")
			if len(m.knobs) == 0 {
				b.WriteString("**knobs:** none\n")
			} else {
				b.WriteString("**knobs:**\n")
				for _, k := range m.knobs {
					b.WriteString("- `" + k.Name + "`")
					if len(k.Surfaces) > 0 {
						b.WriteString(" (mcp, cli as `" + k.Surfaces[1].Name + "`)")
					}
					b.WriteString(" — " + k.Text + "\n")
				}
			}
			b.WriteString("**when:** " + m.when + "\n")
			if strings.HasPrefix(m.ex, "```") {
				b.WriteString("**example:**\n" + m.ex + "\n")
			} else {
				b.WriteString("**example:** " + m.ex + "\n")
			}
		}
		b.WriteString("\n## decision map\n\n" + prose() + "\n")
		doc, err := Parse([]byte(b.String()))
		if err != nil {
			t.Fatalf("iter %d: generated document refused: %v\n%s", iter, err, b.String())
		}
		if len(doc.Verbs) != len(models) {
			t.Fatalf("iter %d: verbs = %d, want %d", iter, len(doc.Verbs), len(models))
		}
		registered := map[string]map[string]Registered{"mcp": {}, "cli": {}}
		expected := map[string][]string{}
		for name, m := range models {
			effective := m.surfaces
			if len(effective) == 0 {
				effective = []SurfaceName{{Surface: "mcp", Name: name}, {Surface: "cli", Name: name}}
			}
			for _, s := range effective {
				got, err := doc.Description(s.Surface, s.Name)
				if err != nil || got != m.does {
					t.Fatalf("iter %d: Description(%s, %s) = %q, %v; want %q", iter, s.Surface, s.Name, got, err, m.does)
				}
				reg := Registered{}
				for _, k := range m.knobs {
					if spelling, exists := on(k.Surfaces, k.Name, s.Surface); exists {
						draw := draws[name+"\x00"+k.Name]
						if draw.omitted {
							expected[s.Surface] = append(expected[s.Surface], fmt.Sprintf("verb %q: documented knob %q not registered", s.Name, spelling))
						} else {
							reg[spelling] = draw.printed
						}
						if s.Surface == "cli" && !draw.omitted {
							switch {
							case draw.printed && (draw.shape == drawProse || draw.shape == drawUnclosed):
								expected["cli"] = append(expected["cli"], fmt.Sprintf("verb %q: knob %q spells a default outside the (default X) form in its first clause", s.Name, spelling))
							case !draw.printed && (draw.shape == drawForm || draw.shape == drawUnclosed):
								expected["cli"] = append(expected["cli"], fmt.Sprintf("verb %q: knob %q spells a (default X) form in its first clause on a flag the library prints no default for", s.Name, spelling))
							}
						}
						// The knob projection over every generated knob: its
						// spelling on this surface resolves to the knob verbatim.
						if kn, err := doc.Knob(s.Surface, s.Name, spelling); err != nil || !reflect.DeepEqual(kn, k) {
							t.Fatalf("iter %d: Knob(%s, %s, %s) = %+v, %v; want %+v", iter, s.Surface, s.Name, spelling, kn, err, k)
						}
					}
				}
				registered[s.Surface][s.Name] = reg
			}
			vi := -1
			for i := range doc.Verbs {
				if doc.Verbs[i].Name == name {
					vi = i
				}
			}
			v := &doc.Verbs[vi]
			if len(v.Knobs) != len(m.knobs) {
				t.Fatalf("iter %d: %s knobs = %v, want %v", iter, name, v.Knobs, m.knobs)
			}
			for i, k := range m.knobs {
				if fmt.Sprint(v.Knobs[i]) != fmt.Sprint(k) {
					t.Fatalf("iter %d: %s knob %d = %+v, want %+v", iter, name, i, v.Knobs[i], k)
				}
			}
			if v.When != m.when || v.Example != m.ex {
				t.Fatalf("iter %d: %s when/example = %q/%q, want %q/%q", iter, name, v.When, v.Example, m.when, m.ex)
			}
		}
		// Each surface's rows are the predicted set — a knob left out of
		// the registration its not-registered row and nothing else, the
		// MCP never a default row, the CLI's default rows from the two
		// draws (the order is the example pins' concern).
		for _, surface := range []string{"mcp", "cli"} {
			defects, err := doc.Coverage(surface, registered[surface])
			if err != nil {
				t.Fatalf("iter %d: %s coverage: %v", iter, surface, err)
			}
			sort.Strings(defects)
			want := append([]string(nil), expected[surface]...)
			sort.Strings(want)
			if !reflect.DeepEqual(defects, want) {
				t.Fatalf("iter %d: %s rows = %v, want %v\n%s", iter, surface, defects, want, b.String())
			}
		}
	}
}

// TestKnobClauseIsTheFirstClauseOutsideParentheses pins the terse
// rendering: the prose up to the first semicolon at parenthesis depth
// zero, a semicolon inside a parenthesis never cutting, whitespace and
// one trailing period trimmed, and the whole prose where no clause
// boundary exists.
func TestKnobClauseIsTheFirstClauseOutsideParentheses(t *testing.T) {
	for _, c := range []struct{ text, want string }{
		{"candidates per symbol; 0 is exhaustive.", "candidates per symbol"},
		{"the ref (a tag; a sha; HEAD~1) to diff; absent means the tree.", "the ref (a tag; a sha; HEAD~1) to diff"},
		{"  spaced clause ; the rest", "spaced clause"},
		{"one clause with no boundary.", "one clause with no boundary"},
		{"unbalanced ) then; cut", "unbalanced ) then"},
		{"open (never closed; so no cut.", "open (never closed; so no cut"},
		{"  no boundary here  ", "no boundary here"},
		{"a clause.; the rest", "a clause"},
		{"foo . ; bar", "foo"},
		{"", ""},
	} {
		if got := (Knob{Text: c.text}).Clause(); got != c.want {
			t.Errorf("Clause(%q) = %q, want %q", c.text, got, c.want)
		}
	}
}

// TestEmbeddedParsesOnceAndFailsLoudly pins the embedded form: the
// source parses once (every Document call answers the one parse), and
// Must names the tool in the refusal of a malformed document.
func TestEmbeddedParsesOnceAndFailsLoudly(t *testing.T) {
	e := Embed("sometool", []byte(sample))
	first, err := e.Document()
	if err != nil {
		t.Fatal(err)
	}
	if again, err := e.Document(); err != nil || again != first {
		t.Fatalf("second Document = %p, %v; want the one parse %p", again, err, first)
	}
	if e.Must() != first {
		t.Fatal("Must answered a document other than the one parse")
	}
	bad := Embed("sometool", []byte("no title here"))
	if _, err := bad.Document(); err == nil {
		t.Fatal("a malformed source parsed")
	}
	defer func() {
		r := recover()
		msg, _ := r.(string)
		if !strings.HasPrefix(msg, "sometool: embedded guidance document malformed: ") {
			t.Fatalf("Must's refusal = %v; want the tool-named panic", r)
		}
	}()
	bad.Must()
	t.Fatal("Must returned on a malformed document")
}

// knobs is a registration of the named knobs with no non-zero default.
func knobs(names ...string) Registered {
	r := Registered{}
	for _, name := range names {
		r[name] = false
	}
	return r
}

const projectionSource = `# tool

## verbs

### run

**surfaces:** mcp as run_mcp, cli

**does:** Measure the tree.

**knobs:**
- ` + "`budget` (mcp, cli as `budget-cli`)" + ` — candidates per symbol (default 0) (0 means exhaustive); a second clause about ` + "`attest`" + `.
- ` + "`edits`" + ` (mcp) — the edit batch; each edit names a file.
- ` + "`file`" + ` (mcp) — the file an edit targets.

**when:** Always.

**example:**
run

### version

**does:** Print the version.

**knobs:** none

**when:** Never.

**example:**
version

## decision map

Start with run.
`

// TestKnobUsageIsThePflagGrammar pins the usage projection as pflag's
// grammar over the terse clause: code spans lose their back-quotes and
// every default parenthetical goes by depth, the clause otherwise
// verbatim; and the CLI coverage judgment refuses a default spelled
// outside that one form.
func TestKnobUsageIsThePflagGrammar(t *testing.T) {
	doc, err := Parse([]byte(projectionSource))
	if err != nil {
		t.Fatal(err)
	}
	k, err := doc.Knob("cli", "run", "budget-cli")
	if err != nil {
		t.Fatal(err)
	}
	if k.Clause() != "candidates per symbol (default 0) (0 means exhaustive)" {
		t.Fatalf("clause = %q", k.Clause())
	}
	if got := k.Usage(); got != "candidates per symbol (0 means exhaustive)" {
		t.Fatalf("usage = %q", got)
	}
	spanned := Knob{Text: "with `attest`: replace the row; the rest."}
	if got := spanned.Usage(); got != "with attest: replace the row" {
		t.Fatalf("usage over a code span = %q", got)
	}
	// The default parenthetical is matched by depth, so a default naming
	// a call keeps its own parentheses inside, and a clause that is the
	// parenthetical alone empties.
	for text, want := range map[string]string{
		"budget (default max(1, n)) per symbol":     "budget per symbol",
		"(default 0)":                               "",
		"width (default 4) of the pool (default 2)": "width of the pool",
		"width\t(default 4)":                        "width",
	} {
		if got := (Knob{Text: text}).Usage(); got != want {
			t.Errorf("Usage(%q) = %q, want %q", text, got, want)
		}
	}
	// The one default form is the CLI coverage's rule on a flag the
	// caller names as carrying a non-zero default (the library prints
	// that one itself): a colon form, a prose default, "defaults to", or
	// an unclosed parenthetical (rendered unchanged by Usage) in the
	// first clause is a defect there; on a zero-default flag the
	// stripped form itself is the defect (the library prints nothing in
	// its place, so the fact reaches no reader) — the unclosed form on
	// both — while a prose default or what zero means passes there; and
	// never on the MCP, whose schema serves the clause whole.
	nonZero := map[string]Registered{"run": {"budget-cli": true}, "version": {}}
	zero := map[string]Registered{"run": knobs("budget-cli"), "version": {}}
	const zeroDefect = `knob "budget-cli" spells a (default X) form in its first clause on a flag the library prints no default for`
	for clause, onZero := range map[string]int{
		"candidates per symbol (default: 3), the default unlimited": 0,
		"candidates per symbol, defaults to 3":                      0,
		"candidates per symbol (Default: 3)":                        0,
		"candidates per symbol (default 5 per symbol":               1,
	} {
		linted, err := Parse([]byte(strings.Replace(projectionSource, "candidates per symbol (default 0) (0 means exhaustive)", clause, 1)))
		if err != nil {
			t.Fatal(err)
		}
		defects, err := linted.Coverage("cli", nonZero)
		if err != nil {
			t.Fatal(err)
		}
		if len(defects) != 1 || !strings.Contains(defects[0], `knob "budget-cli" spells a default outside the (default X) form`) {
			t.Fatalf("cli coverage over %q = %v", clause, defects)
		}
		if defects, err := linted.Coverage("cli", zero); err != nil || len(defects) != onZero || (onZero == 1 && !strings.Contains(defects[0], zeroDefect)) {
			t.Fatalf("a zero-default flag linted over %q: %v, %v (want %d)", clause, defects, err, onZero)
		}
		// The MCP judgment never lints, even handed the CLI's default
		// facts: the schema serves the clause whole.
		if defects, _ := linted.Coverage("mcp", map[string]Registered{"run_mcp": {"budget": true, "edits": false, "file": false}, "version": {}}); len(defects) != 0 {
			t.Fatalf("mcp coverage lints the default form: %v", defects)
		}
	}
	if defects, err := doc.Coverage("cli", nonZero); err != nil || len(defects) != 0 {
		t.Fatalf("the well-formed default is a defect: %v, %v", defects, err)
	}
	// The same well-formed form on a zero-default flag is the dropped
	// form: a defect naming the knob; a derived default spelled in prose
	// passes, and so does what zero means.
	if defects, err := doc.Coverage("cli", zero); err != nil || len(defects) != 1 || !strings.Contains(defects[0], zeroDefect) {
		t.Fatalf("the dropped form on a zero-default flag: %v, %v", defects, err)
	}
	// A knob the caller never registered carries no default fact at
	// all: its one row is the not-registered one, never a default
	// spelling the author is told to delete.
	if defects, err := doc.Coverage("cli", map[string]Registered{"run": {}, "version": {}}); err != nil || len(defects) != 1 || !strings.Contains(defects[0], `documented knob "budget-cli" not registered`) {
		t.Fatalf("an unregistered knob's rows: %v, %v", defects, err)
	}
	for _, clause := range []string{
		"the module's benchmarks directory unless given (0 means exhaustive)",
		"candidates per symbol; the default is unbounded",
	} {
		prose, err := Parse([]byte(strings.Replace(projectionSource, "candidates per symbol (default 0) (0 means exhaustive)", clause, 1)))
		if err != nil {
			t.Fatal(err)
		}
		if defects, err := prose.Coverage("cli", zero); err != nil || len(defects) != 0 {
			t.Fatalf("a prose default on a zero-default flag linted over %q: %v, %v", clause, defects, err)
		}
	}
	// The unclosed parenthetical renders as it stands — the fail-safe
	// the lint above relies on.
	if got := (Knob{Text: "budget (default 5 per symbol"}).Usage(); got != "budget (default 5 per symbol" {
		t.Fatalf("an unclosed default rendered %q", got)
	}
}

// fakeNode is a schema a test adapts: property names and nodes, items,
// and the description the walk sets. Its receivers are never nil: the
// two-value answers keep a nil schema out of the interface.
type fakeNode struct {
	props map[string]*fakeNode
	items *fakeNode
	desc  string
}

func (n *fakeNode) Properties() []string {
	var names []string
	for name := range n.props {
		names = append(names, name)
	}
	return names
}

// Property answers the two-value form: a name mapped to no node is
// present in the schema's names and absent as a node.
func (n *fakeNode) Property(name string) (SchemaNode, bool) {
	p, ok := n.props[name]
	if !ok || p == nil {
		return nil, false
	}
	return p, true
}

func (n *fakeNode) Items() (SchemaNode, bool) {
	if n.items == nil {
		return nil, false
	}
	return n.items, true
}

func (n *fakeNode) Describe(text string) { n.desc = text }

// TestDescribeSchemaWalksEveryDepthAndRefusesAnUnknobbedProperty pins
// the one schema walk: every property at every depth — a nested
// object's properties and an array's items alike — takes the verb's
// knob by name; a property the document does not knob refuses by name,
// the first in the walk's order; a nil root describes nothing, a nil
// property still needs its knob; the visited names come back sorted.
func TestDescribeSchemaWalksEveryDepthAndRefusesAnUnknobbedProperty(t *testing.T) {
	doc, err := Parse([]byte(projectionSource))
	if err != nil {
		t.Fatal(err)
	}
	file := &fakeNode{}
	item := &fakeNode{props: map[string]*fakeNode{"file": file}}
	edits := &fakeNode{items: item}
	budget := &fakeNode{}
	root := &fakeNode{props: map[string]*fakeNode{"budget": budget, "edits": edits}}
	names, err := doc.DescribeSchema("mcp", "run_mcp", root)
	if err != nil {
		t.Fatal(err)
	}
	if budget.desc != "candidates per symbol (default 0) (0 means exhaustive)" || edits.desc != "the edit batch" || file.desc != "the file an edit targets" {
		t.Fatalf("descriptions = %q, %q, %q", budget.desc, edits.desc, file.desc)
	}
	// The names visited at every depth, sorted, for the coverage
	// judgment.
	if !reflect.DeepEqual(names, []string{"budget", "edits", "file"}) {
		t.Fatalf("visited = %v", names)
	}
	if names, err := doc.DescribeSchema("mcp", "run_mcp", nil); err != nil || len(names) != 0 {
		t.Fatalf("a nil root: %v, %v", names, err)
	}
	// A named property with no node still needs its knob and takes no
	// description; its name is visited.
	if names, err := doc.DescribeSchema("mcp", "run_mcp", &fakeNode{props: map[string]*fakeNode{"budget": nil}}); err != nil || !reflect.DeepEqual(names, []string{"budget"}) {
		t.Fatalf("a nil property with a knob: %v, %v", names, err)
	}
	if _, err := doc.DescribeSchema("mcp", "run_mcp", &fakeNode{props: map[string]*fakeNode{"stray": nil}}); err == nil {
		t.Fatal("a nil property without a knob described")
	}
	// Two unknobbed properties refuse the alphabetically first, whatever
	// the map order.
	unknobbed := &fakeNode{props: map[string]*fakeNode{"zzz": {}, "budget": {}, "stray": {}}}
	for i := 0; i < 20; i++ {
		if _, err := doc.DescribeSchema("mcp", "run_mcp", unknobbed); err == nil || !strings.Contains(err.Error(), `"stray"`) {
			t.Fatalf("an unknobbed property: err = %v", err)
		}
	}
	// Across depths the refusal is the first in the walk's order — the
	// sorted names per node, properties before items — not the
	// alphabetically first unknobbed name overall: edits' items are
	// walked before the root's stray.
	walkOrder := &fakeNode{props: map[string]*fakeNode{"edits": {items: &fakeNode{props: map[string]*fakeNode{"zzz": {}}}}, "stray": {}}}
	if _, err := doc.DescribeSchema("mcp", "run_mcp", walkOrder); err == nil || !strings.Contains(err.Error(), `"zzz"`) {
		t.Fatalf("the cross-depth refusal: err = %v", err)
	}
	nested := &fakeNode{props: map[string]*fakeNode{"edits": {items: &fakeNode{props: map[string]*fakeNode{"deep": {}}}}}}
	if _, err := doc.DescribeSchema("mcp", "run_mcp", nested); err == nil || !strings.Contains(err.Error(), `"deep"`) {
		t.Fatalf("an unknobbed nested item property: err = %v", err)
	}
	// A property the verb documents on the other surface only refuses.
	cliOnly := &fakeNode{props: map[string]*fakeNode{"edits": {}}}
	if _, err := doc.DescribeSchema("cli", "run", cliOnly); err == nil {
		t.Fatal("an mcp-only knob described on the cli")
	}
}

// TestRegistrationIsTheFaceNeutralProjection pins the registration
// projection: the verb's spelling, the purpose, the knobless help, the
// whole section, every knob on the surface with its clause and (on the
// CLI) usage, and the prose pointer in the surface's own form — a
// knobless verb with an empty knob list and the same pointer shape.
func TestRegistrationIsTheFaceNeutralProjection(t *testing.T) {
	e := Embed("tool", []byte(projectionSource))
	r, err := e.Registration("cli", "run")
	if err != nil {
		t.Fatal(err)
	}
	doc := e.Must()
	help, _ := doc.Help("cli", "run")
	long, _ := doc.Long("cli", "run")
	// The knob under its CLI spelling, the pointer under the verb's
	// CLI spelling — never the canonical names.
	want := Registration{
		Verb: "run", Description: "Measure the tree.", Help: help, Long: long,
		Knobs:        []KnobUsage{{Name: "budget-cli", Clause: "candidates per symbol (default 0) (0 means exhaustive)", Usage: "candidates per symbol (0 means exhaustive)"}},
		ProsePointer: "The knobs' whole prose: tool guidance run.",
		LongHelp:     help + "\n\nThe knobs' whole prose: tool guidance run.",
	}
	if !reflect.DeepEqual(r, want) {
		t.Fatalf("registration = %+v, want %+v", r, want)
	}
	if !strings.HasPrefix(help, "Measure the tree.\n\nwhen: Always.") || strings.Contains(help, "knobs:") || !strings.Contains(long, "knobs:\n  budget-cli — ") {
		t.Fatalf("help/long: %q / %q", help, long)
	}
	// On the MCP the verb is addressed and spelled run_mcp: the pointer
	// carries that spelling, the knob its own.
	m, err := e.Registration("mcp", "run_mcp")
	if err != nil {
		t.Fatal(err)
	}
	if m.Verb != "run_mcp" || m.ProsePointer != "The knobs' whole prose: the guidance tool, verb run_mcp." || len(m.Knobs) != 3 || m.Knobs[0].Name != "budget" || m.Knobs[1].Name != "edits" || m.Knobs[2].Name != "file" || m.Knobs[0].Usage != "" || m.LongHelp != "" {
		t.Fatalf("mcp registration = %+v", m)
	}
	// A CLI spelling with a space is quoted in the pointer, so the
	// command line it names resolves as one argument; a Document's own
	// projection carries no pointer (it knows no tool).
	spaced, err := Embed("tool", []byte(strings.Replace(projectionSource, "**surfaces:** mcp as run_mcp, cli", "**surfaces:** mcp as run_mcp, cli as run it", 1))).Registration("cli", "run it")
	if err != nil {
		t.Fatal(err)
	}
	if spaced.ProsePointer != `The knobs' whole prose: tool guidance "run it".` {
		t.Fatalf("spaced pointer = %q", spaced.ProsePointer)
	}
	tabbed, err := Embed("tool", []byte(strings.Replace(projectionSource, "**surfaces:** mcp as run_mcp, cli", "**surfaces:** mcp as run_mcp, cli as run\tit", 1))).Registration("cli", "run\tit")
	if err != nil {
		t.Fatal(err)
	}
	if tabbed.ProsePointer != `The knobs' whole prose: tool guidance "run\tit".` {
		t.Fatalf("tabbed pointer = %q", tabbed.ProsePointer)
	}
	bare, err := doc.Registration("cli", "run")
	if err != nil || bare.ProsePointer != "" || bare.Verb != "run" || bare.LongHelp != help {
		t.Fatalf("document registration = %+v, %v", bare, err)
	}
	if _, err := e.Registration("mcp", "run"); err == nil {
		t.Fatal("the canonical name addressed the verb on a surface that spells it otherwise")
	}
	v, err := e.Registration("cli", "version")
	if err != nil || len(v.Knobs) != 0 || v.ProsePointer != "The knobs' whole prose: tool guidance version." || v.LongHelp != v.Help+"\n\nThe knobs' whole prose: tool guidance version." {
		t.Fatalf("knobless registration = %+v, %v", v, err)
	}
	if _, err := e.Registration("cli", "nope"); err == nil {
		t.Fatal("an unknown verb registered")
	}
}

// TestMustRefusalsNameTheTool pins every construction-time refusal on
// one wording, "<tool>: guidance: <cause>", the package prefix folded,
// and a malformed document on the embedded form's own refusal.
func TestMustRefusalsNameTheTool(t *testing.T) {
	e := Embed("tool", []byte(projectionSource))
	refusal := func(f func()) (msg string) {
		defer func() { msg, _ = recover().(string) }()
		f()
		return ""
	}
	cases := map[string]struct {
		f    func()
		want string
	}{
		"knob":         {func() { e.MustKnob("cli", "run", "stray") }, `tool: guidance: verb "run" documents no knob "stray" on the cli surface`},
		"registration": {func() { e.MustRegistration("cli", "nope") }, `tool: guidance: no verb "nope" on the cli surface`},
		"schema":       {func() { e.MustDescribeSchema("mcp", "run_mcp", &fakeNode{props: map[string]*fakeNode{"stray": {}}}) }, `tool: guidance: verb "run_mcp" documents no knob "stray" on the mcp surface`},
	}
	for name, c := range cases {
		if msg := refusal(c.f); msg != c.want {
			t.Errorf("%s refusal = %q, want %q", name, msg, c.want)
		}
	}
	if k := e.MustKnob("cli", "run", "budget-cli"); k.Name != "budget" {
		t.Fatalf("a present knob refused: %+v", k)
	}
	// A malformed document refuses every Must the one way Must does —
	// never with the guidance prefix doubled.
	broken := Embed("tool", []byte("garbage"))
	for name, f := range map[string]func(){
		"registration": func() { broken.MustRegistration("cli", "run") },
		"knob":         func() { broken.MustKnob("cli", "run", "x") },
		"schema":       func() { broken.MustDescribeSchema("mcp", "run", nil) },
	} {
		if msg := refusal(f); !strings.HasPrefix(msg, "tool: embedded guidance document malformed: ") || strings.Contains(msg, "guidance: guidance:") {
			t.Errorf("%s over a malformed document = %q", name, msg)
		}
	}
	if r := e.MustRegistration("cli", "run"); r.ProsePointer != "The knobs' whole prose: tool guidance run." {
		t.Fatalf("MustRegistration's pointer = %q", r.ProsePointer)
	}
}

// TestPrintsDefaultIsPflagsRuleAtEveryCliff pins the fleet's one
// printed-default rule at every type's cliff — pflag's
// defaultIsZeroValue by type name: the boolean family's "false" and "",
// a duration's "0" and "0s", the integer and float family's "0", a
// string's "", the IP family's "<nil>", the slice family's "[]", and the
// fallback set for every other type (int16 among them, pflag's own case
// list omitting it) — the registration's fact a consumer hands
// Coverage with no flag-library dependency here
// (REQ-guidance-coverage).
func TestPrintsDefaultIsPflagsRuleAtEveryCliff(t *testing.T) {
	zero := map[string][]string{
		"bool": {"false", ""}, "boolfunc": {"false", ""},
		"duration": {"0", "0s"},
		"int":      {"0"}, "int8": {"0"}, "int32": {"0"}, "int64": {"0"}, "uint": {"0"}, "uint8": {"0"}, "uint16": {"0"}, "uint32": {"0"}, "uint64": {"0"}, "count": {"0"}, "float32": {"0"}, "float64": {"0"},
		"string": {""},
		"ip":     {"<nil>"}, "ipMask": {"<nil>"}, "ipNet": {"<nil>"},
		"intSlice": {"[]"}, "stringSlice": {"[]"}, "stringArray": {"[]"},
		// pflag's fallback set, for a type its case list does not name.
		"int16": {"false", "<nil>", "", "0"}, "custom": {"false", "<nil>", "", "0"}, "func": {"false", "<nil>", "", "0"},
	}
	printed := map[string][]string{
		"bool": {"true", "0"}, "boolfunc": {"true"},
		"duration": {"1s", "0ms", ""},
		"int":      {"1", "", "-1"}, "int64": {"00"}, "count": {"1"}, "float64": {"0.0", "1"},
		"string": {"0", "false", "<nil>", "[]", " "},
		"ip":     {"", "0", "1.2.3.4"}, "ipNet": {"10.0.0.0/8"},
		"intSlice": {"", "0", "[0]"}, "stringSlice": {"[a]"}, "stringArray": {"[]x"},
		"int16": {"1", "[]", "0s"}, "custom": {"x", "[]", "0s", "true"},
	}
	for flagType, values := range zero {
		for _, v := range values {
			if PrintsDefault(flagType, v) {
				t.Errorf("PrintsDefault(%q, %q) = true, want false: the library prints no zero", flagType, v)
			}
		}
	}
	for flagType, values := range printed {
		for _, v := range values {
			if !PrintsDefault(flagType, v) {
				t.Errorf("PrintsDefault(%q, %q) = false, want true: the library prints a non-zero default", flagType, v)
			}
		}
	}
}

// TestServedJudgmentComparesBytesWithTheProjection pins the served-bytes
// judgment: the usage on the CLI, the clause on the MCP, a served knob
// the document does not carry named, defects in name order, an unknown
// verb or surface the caller's error (REQ-guidance-coverage,
// REQ-guidance-single-source).
func TestServedJudgmentComparesBytesWithTheProjection(t *testing.T) {
	doc, err := Parse([]byte(projectionSource))
	if err != nil {
		t.Fatal(err)
	}
	usage := "candidates per symbol (0 means exhaustive)"
	clause := "candidates per symbol (default 0) (0 means exhaustive)"
	if defects, err := doc.Served("cli", "run", map[string]string{"budget-cli": usage}); err != nil || len(defects) != 0 {
		t.Fatalf("the projection served on the cli: %v, %v", defects, err)
	}
	if defects, err := doc.Served("mcp", "run_mcp", map[string]string{"budget": clause, "edits": "the edit batch"}); err != nil || len(defects) != 0 {
		t.Fatalf("the projection served on the mcp: %v, %v", defects, err)
	}
	// The MCP serves the clause, never the usage; the CLI the usage,
	// never the clause — each face's divergence names both strings.
	defects, err := doc.Served("cli", "run", map[string]string{"budget-cli": clause})
	if err != nil || len(defects) != 1 || defects[0] != `verb "run": knob "budget-cli" served "candidates per symbol (default 0) (0 means exhaustive)" where the document renders "candidates per symbol (0 means exhaustive)"` {
		t.Fatalf("the clause served on the cli: %v, %v", defects, err)
	}
	defects, err = doc.Served("mcp", "run_mcp", map[string]string{"budget": usage})
	if err != nil || len(defects) != 1 || !strings.HasSuffix(defects[0], `where the document renders "candidates per symbol (default 0) (0 means exhaustive)"`) {
		t.Fatalf("the usage served on the mcp: %v, %v", defects, err)
	}
	// Name order over a mixed set: an undocumented knob first by name,
	// the divergence second; a knob the verb documents on the other
	// surface only is undocumented here.
	defects, err = doc.Served("cli", "run", map[string]string{"zeta": usage, "budget-cli": "x", "budget": usage})
	if err != nil || len(defects) != 3 ||
		defects[0] != `verb "run": served knob "budget" is not documented on the cli surface` ||
		!strings.HasPrefix(defects[1], `verb "run": knob "budget-cli" served "x" where`) ||
		defects[2] != `verb "run": served knob "zeta" is not documented on the cli surface` {
		t.Fatalf("mixed served set: %v, %v", defects, err)
	}
	if _, err := doc.Served("cli", "nope", nil); err == nil {
		t.Fatal("an unknown verb judged")
	}
	if _, err := doc.Served("web", "run", nil); err == nil {
		t.Fatal("an unknown surface judged")
	}
	if defects, err := doc.Served("cli", "version", map[string]string{}); err != nil || len(defects) != 0 {
		t.Fatalf("a knobless verb with nothing served: %v, %v", defects, err)
	}
}

// FuzzGuidanceSingleSourceProjections is a property witness for
// REQ-guidance-single-source: across generated knob clauses and drifted
// served strings, every CLI and MCP registration, schema description, and
// served-bytes check projects directly from the parsed document and refuses
// any drifted literal or unknobbed schema property.
func FuzzGuidanceSingleSourceProjections(f *testing.F) {
	f.Add("candidates per symbol", "0", "stray", "drifted")
	f.Add("timeout in seconds", "30s", "extra", "other")
	f.Add("with `attest` enabled", "false", "unknown", "mismatch")
	f.Fuzz(func(t *testing.T, prefix, defVal, unknobbed, drift string) {
		sanitize := func(s, fallback string) string {
			var b strings.Builder
			for _, r := range s {
				if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == ' ' || r == '-' || r == '_' {
					b.WriteRune(r)
				}
			}
			out := strings.TrimSpace(b.String())
			if out == "" {
				return fallback
			}
			return out
		}
		p := sanitize(prefix, "candidates per symbol")
		d := sanitize(defVal, "0")
		u := sanitize(unknobbed, "stray")
		if u == "budget" || u == "budget-cli" || u == "edits" || u == "file" {
			u = "unknobbed_" + u
		}
		clause := p + " (default " + d + ")"
		src := strings.Replace(projectionSource, "candidates per symbol (default 0) (0 means exhaustive)", clause, 1)
		e := Embed("tool", []byte(src))
		doc, err := Parse([]byte(src))
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		cliReg, err := e.Registration("cli", "run")
		if err != nil {
			t.Fatalf("cli Registration: %v", err)
		}
		mcpReg, err := e.Registration("mcp", "run_mcp")
		if err != nil {
			t.Fatalf("mcp Registration: %v", err)
		}
		k, err := doc.Knob("cli", "run", "budget-cli")
		if err != nil {
			t.Fatalf("Knob: %v", err)
		}
		if k.Clause() != clause || k.Usage() != p {
			t.Fatalf("knob projections = (%q, %q), want (%q, %q)", k.Clause(), k.Usage(), clause, p)
		}
		if len(cliReg.Knobs) != 1 || cliReg.Knobs[0].Clause != k.Clause() || cliReg.Knobs[0].Usage != k.Usage() {
			t.Fatalf("cli registration drifted from knob projection: %+v", cliReg.Knobs)
		}
		if len(mcpReg.Knobs) != 3 || mcpReg.Knobs[0].Clause != k.Clause() || mcpReg.Knobs[0].Usage != "" {
			t.Fatalf("mcp registration drifted from knob projection: %+v", mcpReg.Knobs)
		}
		if defects, err := doc.Served("cli", "run", map[string]string{"budget-cli": k.Usage()}); err != nil || len(defects) != 0 {
			t.Fatalf("exact cli usage rejected: %v %v", defects, err)
		}
		if defects, err := doc.Served("mcp", "run_mcp", map[string]string{"budget": k.Clause()}); err != nil || len(defects) != 0 {
			t.Fatalf("exact mcp clause rejected: %v %v", defects, err)
		}
		drifted := drift
		if drifted == k.Usage() || drifted == k.Clause() {
			drifted += "!"
		}
		if defects, err := doc.Served("cli", "run", map[string]string{"budget-cli": drifted}); err != nil || len(defects) != 1 {
			t.Fatalf("drifted cli literal not refused: %v %v", defects, err)
		}
		if defects, err := doc.Served("mcp", "run_mcp", map[string]string{"budget": drifted}); err != nil || len(defects) != 1 {
			t.Fatalf("drifted mcp literal not refused: %v %v", defects, err)
		}
		budgetNode := &fakeNode{}
		root := &fakeNode{props: map[string]*fakeNode{"budget": budgetNode}}
		if _, err := doc.DescribeSchema("mcp", "run_mcp", root); err != nil || budgetNode.desc != k.Clause() {
			t.Fatalf("DescribeSchema = %q, %v; want %q", budgetNode.desc, err, k.Clause())
		}
		badSchema := &fakeNode{props: map[string]*fakeNode{"budget": {}, u: {}}}
		if _, err := doc.DescribeSchema("mcp", "run_mcp", badSchema); err == nil || !strings.Contains(err.Error(), u) {
			t.Fatalf("DescribeSchema accepted unknobbed property %q: %v", u, err)
		}
	})
}
