package guidance

import (
	"fmt"
	"math/rand"
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
	if got := doc.Orientation(); got != "Use run for campaigns; use ephemeral for single probes." {
		t.Fatalf("Orientation() = %q — the sample decision map leaked", got)
	}
	if _, err := doc.Long("web", "run"); err == nil {
		t.Fatal("unknown surface rendered")
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
	exact := func(surface string, registered map[string][]string) {
		t.Helper()
		defects, err := doc.Coverage(surface, registered)
		if err != nil || len(defects) != 0 {
			t.Fatalf("exact %s surface: defects=%v err=%v", surface, defects, err)
		}
	}
	exact("mcp", map[string][]string{
		"run":                {"changed", "budget"},
		"ephemeral":          {"test_pkg", "batch_edits"},
		"attest_requirement": nil,
		"read_spec":          nil,
	})
	exact("cli", map[string][]string{
		"run":                {"budget", "changed"},
		"ephemeral":          {"test-pkg", "batch"},
		"attest requirement": nil,
		"init":               nil,
		"read_spec":          nil,
	})
	// Divergences, both directions, exact deterministic order —
	// six registered verbs so a neutered sort has no lucky escape.
	got, err := doc.Coverage("mcp", map[string][]string{
		"run":       {"changed", "jobs", "jobs"},
		"discover":  nil,
		"findings":  nil,
		"explain":   nil,
		"prune":     nil,
		"read_spec": nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`registered mcp verb "discover" has no guidance section`,
		`registered mcp verb "explain" has no guidance section`,
		`registered mcp verb "findings" has no guidance section`,
		`registered mcp verb "prune" has no guidance section`,
		`verb "run": registered knob "jobs" undocumented`,
		`verb "run": documented knob "budget" not registered`,
		`guidance section "ephemeral" (as mcp "ephemeral") names no registered verb`,
		`guidance section "attest_requirement" (as mcp "attest_requirement") names no registered verb`,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("Coverage order/content:\ngot  %v\nwant %v", got, want)
	}
	// The cli spelling of a knob is a defect when registered on mcp.
	defects, err := doc.Coverage("mcp", map[string][]string{
		"run":                {"changed", "budget"},
		"ephemeral":          {"test-pkg", "batch_edits"},
		"attest_requirement": nil,
		"read_spec":          nil,
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
	defects, err = doc.Coverage("mcp", map[string][]string{
		"run": {"changed", "budget"}, "ephemeral": {"test_pkg", "batch_edits"},
		"attest_requirement": nil, "read_spec": nil, "init": nil,
	})
	if err != nil || len(defects) != 1 || !strings.Contains(defects[0], `registered mcp verb "init" has no guidance section`) {
		t.Fatalf("cli-only verb on mcp: %v err=%v", defects, err)
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
	prose := func() string {
		n := 1 + rng.Intn(50)
		r := make([]rune, n)
		for i := range r {
			r[i] = proseRunes[rng.Intn(len(proseRunes))]
		}
		return "A" + strings.TrimSpace(string(r)) + "z"
	}
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
		registered := map[string]map[string][]string{"mcp": {}, "cli": {}}
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
				var params []string
				for _, k := range m.knobs {
					if spelling, exists := on(k.Surfaces, k.Name, s.Surface); exists {
						params = append(params, spelling)
					}
				}
				registered[s.Surface][s.Name] = params
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
		for _, surface := range []string{"mcp", "cli"} {
			defects, err := doc.Coverage(surface, registered[surface])
			if err != nil || len(defects) != 0 {
				t.Fatalf("iter %d: exact %s surface: defects=%v err=%v", iter, surface, defects, err)
			}
		}
	}
}
