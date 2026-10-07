package guidance

import (
	"reflect"
	"strings"
	"testing"
)

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
//
//gofresh:pure
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
//
//gofresh:pure
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
//
//gofresh:pure
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
//
//gofresh:pure
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
//
//gofresh:pure
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
//
//gofresh:pure
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
