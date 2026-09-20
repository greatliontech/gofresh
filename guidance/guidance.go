// Package guidance parses and renders the fleet's tool-resident
// guidance documents (docs/specs/guidance.md): one structured
// markdown file per tool, embedded at build time and projected onto
// every surface at initialization, so a verb's served prose has
// exactly one home. The package is deliberately projection-only —
// rendering synthesizes no prose, and the per-surface coverage
// judgment is the hook a consuming repo's drift binding enforces.
// The per-surface name index is built at parse time and collisions
// refuse there, so a shadowed section is unrepresentable. Embedded is
// the once-parsed form a tool's faces read at construction.
package guidance

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

// Document is one tool's parsed guidance source.
type Document struct {
	Title       string
	Verbs       []Verb
	DecisionMap string

	// index maps surface → per-surface spelling → Verbs index; built
	// at parse, where a spelling collision refuses.
	index map[string]map[string]int
}

// Verb is one verb section: its surfaces, the one-line purpose, the
// knob list, the decision prose, and the example.
type Verb struct {
	Name string
	// Surfaces lists the faces this verb exists on, each with its
	// spelling there, resolved at parse (an undecorated entry carries
	// the canonical name); empty means both surfaces under Name.
	Surfaces []SurfaceName
	Does     string
	Knobs    []Knob
	When     string
	Example  string
}

// SurfaceName is one face a verb or knob exists on and its spelling
// there.
type SurfaceName struct {
	Surface string // "mcp" or "cli"
	Name    string
}

// Knob is one documented parameter or flag; Surfaces has the
// verb-level grammar and meaning.
type Knob struct {
	Name     string
	Surfaces []SurfaceName
	Text     string
}

// surfaces is the format's face set.
var surfaces = []string{"mcp", "cli"}

func knownSurface(s string) bool { return s == "mcp" || s == "cli" }

// on reports the spelling on a surface and whether the carrier
// exists there; empty declarations mean both surfaces under the
// canonical name.
func on(declared []SurfaceName, canonical, surface string) (string, bool) {
	if len(declared) == 0 {
		return canonical, true
	}
	for _, s := range declared {
		if s.Surface == surface {
			return s.Name, true
		}
	}
	return "", false
}

// parser walks the normalized document lines with fence awareness:
// inside a fenced code block no line is structural
// (REQ-guidance-format). Fences follow the markdown rules the
// document renders under — at most three spaces of indentation,
// three or more backticks to open (an info string may follow), and
// a close of at least the opening length with nothing else.
type parser struct {
	lines    []string
	i        int
	fenceLen int // 0 = no open fence
}

// unindent strips a structural line's tolerated indentation — up to
// three leading spaces, the CommonMark rule shared by fences,
// headings, and field labels; four or more make the line content
// (REQ-guidance-format).
func unindent(line string) (string, bool) {
	indent := 0
	for indent < len(line) && line[indent] == ' ' {
		indent++
	}
	if indent > 3 {
		return "", false
	}
	return line[indent:], true
}

// fenceMarker reports a line's fence backtick count — 0 for a
// non-fence line — and whether anything besides backticks follows.
func fenceMarker(line string) (int, bool) {
	rest, ok := unindent(line)
	if !ok {
		return 0, false
	}
	n := 0
	for n < len(rest) && rest[n] == '`' {
		n++
	}
	if n < 3 {
		return 0, false
	}
	return n, strings.TrimSpace(rest[n:]) != ""
}

// structural reports whether the current line opens a heading or a
// bolded field label — never inside a fence, and under the shared
// indentation rule.
func (p *parser) structural() bool {
	if p.fenceLen > 0 || p.i >= len(p.lines) {
		return false
	}
	l, ok := unindent(p.lines[p.i])
	return ok && (strings.HasPrefix(l, "#") || strings.HasPrefix(l, "**"))
}

// line is the current line under the shared indentation rule — what
// prefix cuts parse; head() stays raw for refusal messages.
func (p *parser) line() string {
	if p.i >= len(p.lines) {
		return ""
	}
	l, ok := unindent(p.lines[p.i])
	if !ok {
		return p.lines[p.i]
	}
	return l
}

// advance consumes the current line, updating fence state.
func (p *parser) advance() string {
	l := p.lines[p.i]
	if n, tail := fenceMarker(l); n > 0 {
		switch {
		case p.fenceLen == 0:
			p.fenceLen = n
		case n >= p.fenceLen && !tail:
			p.fenceLen = 0
		}
	}
	p.i++
	return l
}

func (p *parser) skipBlank() {
	for p.i < len(p.lines) && p.fenceLen == 0 && strings.TrimSpace(p.lines[p.i]) == "" {
		p.i++
	}
}

func (p *parser) head() string {
	if p.i >= len(p.lines) {
		return "end of document"
	}
	return p.lines[p.i]
}

// Parse reads a guidance document, refusing — with the first
// offending heading or field named — any document off the format
// (REQ-guidance-format).
func Parse(src []byte) (*Document, error) {
	normalized := strings.ReplaceAll(string(src), "\r", "")
	p := &parser{lines: strings.Split(normalized, "\n")}
	doc := &Document{index: map[string]map[string]int{}}
	for _, s := range surfaces {
		doc.index[s] = map[string]int{}
	}
	p.skipBlank()
	title, ok := strings.CutPrefix(p.line(), "# ")
	if p.i >= len(p.lines) || !ok || strings.TrimSpace(title) == "" {
		return nil, fmt.Errorf("guidance: document must open with a non-empty top-level title, got %q", p.head())
	}
	doc.Title = strings.TrimSpace(title)
	p.advance()
	p.skipBlank()
	if p.i >= len(p.lines) || strings.TrimSpace(p.line()) != "## verbs" {
		return nil, fmt.Errorf("guidance: expected \"## verbs\", got %q", p.head())
	}
	p.advance()
	headings := map[string]bool{}
	for {
		p.skipBlank()
		if p.i >= len(p.lines) {
			return nil, fmt.Errorf("guidance: missing \"## decision map\"")
		}
		if strings.TrimSpace(p.line()) == "## decision map" {
			p.advance()
			break
		}
		name, ok := strings.CutPrefix(p.line(), "### ")
		if !ok {
			return nil, fmt.Errorf("guidance: expected a \"### <verb>\" subsection or \"## decision map\", got %q", p.head())
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("guidance: empty verb heading at line %d", p.i+1)
		}
		if headings[name] {
			return nil, fmt.Errorf("guidance: duplicate verb section %q", name)
		}
		headings[name] = true
		p.advance()
		verb, err := parseVerb(name, p)
		if err != nil {
			return nil, err
		}
		doc.Verbs = append(doc.Verbs, *verb)
		vi := len(doc.Verbs) - 1
		for _, s := range surfaces {
			spelling, exists := on(verb.Surfaces, verb.Name, s)
			if !exists {
				continue
			}
			if prev, taken := doc.index[s][spelling]; taken {
				return nil, fmt.Errorf("guidance: verb %q: %s spelling %q collides with verb %q", verb.Name, s, spelling, doc.Verbs[prev].Name)
			}
			doc.index[s][spelling] = vi
		}
	}
	var body []string
	for p.i < len(p.lines) {
		if p.structural() && strings.HasPrefix(p.line(), "#") {
			return nil, fmt.Errorf("guidance: \"## decision map\" must be the final section, got %q", p.head())
		}
		body = append(body, p.advance())
	}
	if p.fenceLen > 0 {
		return nil, fmt.Errorf("guidance: document ends inside an open fenced code block")
	}
	doc.DecisionMap = strings.TrimSpace(strings.Join(body, "\n"))
	if doc.DecisionMap == "" {
		return nil, fmt.Errorf("guidance: empty decision map")
	}
	if len(doc.Verbs) == 0 {
		return nil, fmt.Errorf("guidance: no verb sections")
	}
	return doc, nil
}

// parseVerb reads one verb subsection's fields in the required
// order, stopping before the next heading.
func parseVerb(name string, p *parser) (*Verb, error) {
	v := &Verb{Name: name}
	label := func(want string) (string, bool) {
		p.skipBlank()
		if p.i >= len(p.lines) || !strings.HasPrefix(p.line(), "**"+want+":**") {
			return "", false
		}
		first := strings.TrimSpace(strings.TrimPrefix(p.line(), "**"+want+":**"))
		p.advance()
		return first, true
	}
	body := func(field string) (string, error) {
		var parts []string
		for p.i < len(p.lines) && !p.structural() {
			parts = append(parts, p.advance())
		}
		if p.fenceLen > 0 {
			return "", fmt.Errorf("guidance: verb %q: **%s:** ends inside an open fenced code block", name, field)
		}
		return strings.TrimRight(strings.Join(parts, "\n"), "\n \t"), nil
	}
	// surfaces — optional, same-line list.
	if first, ok := label("surfaces"); ok {
		extra, err := body("surfaces")
		if err != nil {
			return nil, err
		}
		if extra != "" {
			return nil, fmt.Errorf("guidance: verb %q: **surfaces:** must be one line", name)
		}
		v.Surfaces, err = parseSurfaceList(name, name, first)
		if err != nil {
			return nil, err
		}
	}
	// does — required, non-empty, on the label's own line.
	first, ok := label("does")
	if !ok {
		return nil, fmt.Errorf("guidance: verb %q: expected field **does:**, got %q", name, p.head())
	}
	if first == "" {
		return nil, fmt.Errorf("guidance: verb %q: **does:** must carry its one-line purpose on the label's line", name)
	}
	extra, err := body("does")
	if err != nil {
		return nil, err
	}
	if extra != "" {
		return nil, fmt.Errorf("guidance: verb %q: **does:** must be one line, got continuation %q", name, extra)
	}
	v.Does = first
	// knobs — required: "none" on the label line, or list items below.
	first, ok = label("knobs")
	if !ok {
		return nil, fmt.Errorf("guidance: verb %q: expected field **knobs:**, got %q", name, p.head())
	}
	if first != "none" {
		if first != "" {
			return nil, fmt.Errorf("guidance: verb %q: **knobs:** carries list items on following lines, or the literal none; got %q", name, first)
		}
		items, err := body("knobs")
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		spellings := map[string]map[string]bool{"mcp": {}, "cli": {}}
		for _, item := range strings.Split(items, "\n") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			knob, err := parseKnob(name, item)
			if err != nil {
				return nil, err
			}
			if seen[knob.Name] {
				return nil, fmt.Errorf("guidance: verb %q: duplicate knob %q", name, knob.Name)
			}
			seen[knob.Name] = true
			for _, s := range surfaces {
				spelling, exists := on(knob.Surfaces, knob.Name, s)
				if !exists {
					continue
				}
				if spellings[s][spelling] {
					return nil, fmt.Errorf("guidance: verb %q: knob %q: %s spelling %q collides with another knob", name, knob.Name, s, spelling)
				}
				spellings[s][spelling] = true
			}
			v.Knobs = append(v.Knobs, *knob)
		}
		if len(v.Knobs) == 0 {
			return nil, fmt.Errorf("guidance: verb %q: **knobs:** must list knobs or state none", name)
		}
	}
	// when — required, non-empty prose.
	first, ok = label("when")
	if !ok {
		return nil, fmt.Errorf("guidance: verb %q: expected field **when:**, got %q", name, p.head())
	}
	rest, err := body("when")
	if err != nil {
		return nil, err
	}
	v.When = joinField(first, rest)
	if v.When == "" {
		return nil, fmt.Errorf("guidance: verb %q: empty **when:**", name)
	}
	// example — required, prose or fenced code to the subsection end.
	first, ok = label("example")
	if !ok {
		return nil, fmt.Errorf("guidance: verb %q: expected field **example:**, got %q", name, p.head())
	}
	rest, err = body("example")
	if err != nil {
		return nil, err
	}
	v.Example = joinField(first, rest)
	if v.Example == "" {
		return nil, fmt.Errorf("guidance: verb %q: empty **example:**", name)
	}
	return v, nil
}

// parseSurfaceList reads a comma-separated surface list, each entry
// `mcp`/`cli` optionally `<surface> as <name>` (the name may be
// backtick-wrapped, the knob spelling form).
func parseSurfaceList(owner, canonical, list string) ([]SurfaceName, error) {
	if strings.TrimSpace(list) == "" {
		return nil, fmt.Errorf("guidance: verb %q: empty **surfaces:** list", owner)
	}
	var out []SurfaceName
	seen := map[string]bool{}
	for _, entry := range strings.Split(list, ",") {
		entry = strings.TrimSpace(entry)
		surface, alias, hasAlias := strings.Cut(entry, " as ")
		if !hasAlias {
			if s, dangling := strings.CutSuffix(entry, " as"); dangling {
				return nil, fmt.Errorf("guidance: verb %q: empty name after %q as", owner, strings.TrimSpace(s))
			}
		}
		surface = strings.TrimSpace(surface)
		if !knownSurface(surface) {
			return nil, fmt.Errorf("guidance: verb %q: unknown surface %q", owner, surface)
		}
		if seen[surface] {
			return nil, fmt.Errorf("guidance: verb %q: duplicate surface %q", owner, surface)
		}
		seen[surface] = true
		name := canonical
		if hasAlias {
			name = strings.TrimSpace(alias)
			hasTick := strings.HasPrefix(name, "`") || strings.HasSuffix(name, "`")
			if hasTick {
				inner, ok := strings.CutPrefix(name, "`")
				if ok {
					inner, ok = strings.CutSuffix(inner, "`")
				}
				if !ok || inner == "" {
					return nil, fmt.Errorf("guidance: verb %q: malformed backtick-wrapped name %q after %q as", owner, name, surface)
				}
				name = inner
			}
			if name == "" {
				return nil, fmt.Errorf("guidance: verb %q: empty name after %q as", owner, surface)
			}
			if strings.Contains(name, "`") {
				return nil, fmt.Errorf("guidance: verb %q: malformed backtick-wrapped name %q after %q as", owner, name, surface)
			}
			if name == canonical {
				return nil, fmt.Errorf("guidance: verb %q: alias %q equals the canonical name; omit the alias", owner, name)
			}
		}
		out = append(out, SurfaceName{Surface: surface, Name: name})
	}
	return out, nil
}

// joinField joins a field's label-line remainder and its
// continuation body.
func joinField(first, rest string) string {
	switch {
	case first == "":
		return strings.TrimSpace(rest)
	case rest == "":
		return first
	}
	return first + "\n" + rest
}

// parseKnob reads one single-line "- `name` (surfaces) — prose"
// list item, the parenthesized surface list optional.
func parseKnob(verb, item string) (*Knob, error) {
	rest, ok := strings.CutPrefix(item, "- `")
	if !ok {
		return nil, fmt.Errorf("guidance: verb %q: knob item must be \"- `name` — prose\", got %q", verb, item)
	}
	name, rest, ok := strings.Cut(rest, "`")
	if !ok || name == "" {
		return nil, fmt.Errorf("guidance: verb %q: unterminated knob name in %q", verb, item)
	}
	knob := &Knob{Name: name}
	rest = strings.TrimSpace(rest)
	if list, tail, ok := cutParens(rest); ok {
		declared, err := parseSurfaceList(verb, name, list)
		if err != nil {
			return nil, fmt.Errorf("%w (knob %q)", err, name)
		}
		knob.Surfaces = declared
		rest = strings.TrimSpace(tail)
	}
	text, ok := strings.CutPrefix(rest, "— ")
	if !ok || strings.TrimSpace(text) == "" {
		return nil, fmt.Errorf("guidance: verb %q: knob %q needs \"— prose\"", verb, name)
	}
	knob.Text = strings.TrimSpace(text)
	return knob, nil
}

// cutParens splits "(list) tail" into list and tail.
func cutParens(s string) (string, string, bool) {
	inner, ok := strings.CutPrefix(s, "(")
	if !ok {
		return "", "", false
	}
	list, tail, ok := strings.Cut(inner, ")")
	if !ok {
		return "", "", false
	}
	return list, tail, true
}

// resolve finds the verb addressed by a surface's spelling.
func (d *Document) resolve(surface, name string) (*Verb, error) {
	if !knownSurface(surface) {
		return nil, fmt.Errorf("guidance: unknown surface %q", surface)
	}
	i, ok := d.index[surface][name]
	if !ok {
		return nil, fmt.Errorf("guidance: no verb %q on the %s surface", name, surface)
	}
	return &d.Verbs[i], nil
}

// Description is the verb's one-line purpose, verbatim — the
// tool-level description — addressed per surface by the surface's
// spelling (REQ-guidance-render).
func (d *Document) Description(surface, name string) (string, error) {
	v, err := d.resolve(surface, name)
	if err != nil {
		return "", err
	}
	return v.Does, nil
}

// Knob is one knob of a verb addressed per surface — the verb by its
// spelling on that surface, the knob by its own — with the knob's text
// verbatim: the one read a consumer rendering per-parameter prose (a
// schema description, a flag's usage) takes, so the document stays the
// single source of every knob's words (REQ-guidance-render). A knob
// the verb documents on the other surface only is not found.
func (d *Document) Knob(surface, verb, name string) (Knob, error) {
	v, err := d.resolve(surface, verb)
	if err != nil {
		return Knob{}, err
	}
	for _, kn := range knobsOn(v, surface) {
		if kn.spelling == name {
			return kn.Knob, nil
		}
	}
	return Knob{}, fmt.Errorf("guidance: verb %q documents no knob %q on the %s surface", verb, name, surface)
}

// spelledKnob is a knob under its spelling on one surface.
type spelledKnob struct {
	Knob
	spelling string
}

// knobsOn is the verb's knobs on one surface, each under its spelling
// there, in document order — the one walk the knob projection, the
// long rendering, and the coverage judgment share.
func knobsOn(v *Verb, surface string) []spelledKnob {
	var out []spelledKnob
	for _, k := range v.Knobs {
		if spelling, exists := on(k.Surfaces, k.Name, surface); exists {
			out = append(out, spelledKnob{Knob: k, spelling: spelling})
		}
	}
	return out
}

// Long is the verb's full rendering on a surface: the purpose, the
// knobs: block under the surface's knob spellings, the when: block,
// and the example: block — the example body on its own lines so
// fenced code stays at column zero — exactly those labels
// (REQ-guidance-render).
func (d *Document) Long(surface, name string) (string, error) {
	v, err := d.resolve(surface, name)
	if err != nil {
		return "", err
	}
	return longOf(v, surface), nil
}

// longOf is the long rendering of a resolved verb on a surface.
func longOf(v *Verb, surface string) string {
	var b strings.Builder
	b.WriteString(v.Does)
	b.WriteString("\n\nknobs:")
	listed := false
	for _, kn := range knobsOn(v, surface) {
		fmt.Fprintf(&b, "\n  %s — %s", kn.spelling, kn.Text)
		listed = true
	}
	if !listed {
		b.WriteString(" none")
	}
	b.WriteString("\n\nwhen: ")
	b.WriteString(v.When)
	b.WriteString("\n\nexample:\n")
	b.WriteString(v.Example)
	return b.String()
}

// Help is the long rendering without its knobs: block — for a
// surface that renders its own knob list, a CLI's flag help, where
// the block would print every knob twice in two wordings
// (REQ-guidance-render).
func (d *Document) Help(surface, name string) (string, error) {
	v, err := d.resolve(surface, name)
	if err != nil {
		return "", err
	}
	return helpOf(v), nil
}

// helpOf is the knobless long rendering of a resolved verb.
func helpOf(v *Verb) string {
	var b strings.Builder
	b.WriteString(v.Does)
	b.WriteString("\n\nwhen: ")
	b.WriteString(v.When)
	b.WriteString("\n\nexample:\n")
	b.WriteString(v.Example)
	return b.String()
}

// Orientation is the decision map's body, verbatim
// (REQ-guidance-render).
func (d *Document) Orientation() string {
	return d.DecisionMap
}

// Registered is one registered verb on a surface: its served
// parameter or flag names, each mapped to whether its default is
// non-zero on the CLI — the flags a flag library prints a default for,
// so the coverage judgment holds the one default form the usage
// rendering strips to exactly the knobs where a second spelling would
// print twice (REQ-guidance-render). One map, so a default fact can
// name only a registered knob; the value is read on the CLI surface
// alone and ignored on the MCP, so one registration per verb serves
// both faces.
type Registered map[string]bool

// Coverage judges the document against one surface's registered
// verbs — surface spellings mapped to their registrations — and
// reports every divergence in both directions, in a deterministic
// order: registered verbs sorted; per verb the registered knobs
// undocumented, sorted by name, then the documented knobs in document
// order, each contributing its not-registered row and, on the CLI for
// a knob registered with a non-zero default, its default-spelling row
// (REQ-guidance-render); unregistered sections last in document order
// (REQ-guidance-coverage). An unknown surface is the caller's error,
// distinct from the defect list; an empty defect list is the drift
// binding's pass condition.
func (d *Document) Coverage(surface string, registered map[string]Registered) ([]string, error) {
	if !knownSurface(surface) {
		return nil, fmt.Errorf("guidance: unknown surface %q", surface)
	}
	var defects []string
	verbs := make([]string, 0, len(registered))
	for verb := range registered {
		verbs = append(verbs, verb)
	}
	sort.Strings(verbs)
	matched := map[string]bool{}
	for _, verb := range verbs {
		vi, ok := d.index[surface][verb]
		if !ok {
			defects = append(defects, fmt.Sprintf("registered %s verb %q has no guidance section", surface, verb))
			continue
		}
		matched[verb] = true
		v := &d.Verbs[vi]
		documented := map[string]bool{}
		for _, kn := range knobsOn(v, surface) {
			documented[kn.spelling] = true
		}
		nonZero := registered[verb]
		params := make([]string, 0, len(nonZero))
		for p := range nonZero {
			params = append(params, p)
		}
		sort.Strings(params)
		for _, p := range params {
			if !documented[p] {
				defects = append(defects, fmt.Sprintf("verb %q: registered knob %q undocumented", verb, p))
			}
		}
		for _, kn := range knobsOn(v, surface) {
			if _, ok := nonZero[kn.spelling]; !ok {
				defects = append(defects, fmt.Sprintf("verb %q: documented knob %q not registered", verb, kn.spelling))
			}
			// The usage grammar strips one default form; a flag library
			// prints a non-zero default itself, so on such a flag a default
			// spelled any other way in the first clause prints twice — the
			// CLI coverage refuses it (REQ-guidance-render). A zero default
			// prints nothing, and its clause may say what zero means.
			if surface == "cli" && nonZero[kn.spelling] && spellsDefaultOutsideTheForm(kn.Clause()) {
				defects = append(defects, fmt.Sprintf("verb %q: knob %q spells a default outside the (default X) form in its first clause", verb, kn.spelling))
			}
		}
	}
	for i := range d.Verbs {
		name, ok := on(d.Verbs[i].Surfaces, d.Verbs[i].Name, surface)
		if ok && !matched[name] {
			defects = append(defects, fmt.Sprintf("guidance section %q (as %s %q) names no registered verb", d.Verbs[i].Name, surface, name))
		}
	}
	return defects, nil
}

// Clause is the knob's terse rendering: its prose up to the first
// semicolon outside parentheses — a semicolon inside a parenthesis
// separates that parenthesis's alternatives, not the clauses —
// surrounding whitespace and a trailing period trimmed, the whole
// prose where no such semicolon exists. A surface rendering one line
// per knob (a served schema description, a flag usage) takes it for a
// knob the knob projection answered; which surface renders the clause
// and which the whole prose is the consuming tool's contract
// (REQ-guidance-render).
func (k Knob) Clause() string {
	depth := 0
	for i, r := range k.Text {
		switch r {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 {
				return trimClause(k.Text[:i])
			}
		}
	}
	return trimClause(k.Text)
}

// trimClause trims a clause's surrounding whitespace and its trailing
// period, whitespace between the two included.
func trimClause(s string) string {
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// Embedded is a tool's embedded guidance source parsed once for every
// surface to project from: the tool's repository is absent where its
// binary runs, so the document travels in the binary and every face
// reads the one parse at initialization; a malformed document refuses
// loudly at construction, naming the tool (REQ-guidance-single-source).
type Embedded struct {
	tool string
	src  []byte
	once sync.Once
	doc  *Document
	err  error
}

// Embed wraps a tool's embedded guidance source; tool names the tool
// in the refusal Must raises.
func Embed(tool string, src []byte) *Embedded {
	return &Embedded{tool: tool, src: src}
}

// Document parses the source once and answers the same document and
// error on every call.
func (e *Embedded) Document() (*Document, error) {
	e.once.Do(func() { e.doc, e.err = Parse(e.src) })
	return e.doc, e.err
}

// Must is the document a face reads at construction: a malformed
// embedded document is a build defect the consuming tool's parse pin
// surfaces, so construction fails loudly rather than serving nothing.
func (e *Embedded) Must() *Document {
	doc, err := e.Document()
	if err != nil {
		panic(e.tool + ": embedded guidance document malformed: " + err.Error())
	}
	return doc
}

// refuse is the one refusal every face raises at construction over a
// document that does not carry what the face registers: the tool
// named, then the cause — the package's own prefix folded, so the
// wording is "<tool>: guidance: <cause>" exactly once.
func (e *Embedded) refuse(err error) {
	panic(e.tool + ": guidance: " + strings.TrimPrefix(err.Error(), "guidance: "))
}

// MustKnob is the knob projection at a face's construction: a knob the
// document does not carry is a build defect the coverage judgment also
// names, refused loudly rather than served empty.
func (e *Embedded) MustKnob(surface, verb, name string) Knob {
	k, err := e.Must().Knob(surface, verb, name)
	if err != nil {
		e.refuse(err)
	}
	return k
}

// MustRegistration is Registration at a face's construction: a
// malformed document refuses as Must does, a verb the document does not
// carry on the surface as every other refusal.
func (e *Embedded) MustRegistration(surface, verb string) Registration {
	e.Must()
	r, err := e.Registration(surface, verb)
	if err != nil {
		e.refuse(err)
	}
	return r
}

// MustDescribeSchema is DescribeSchema at a face's construction: a
// property the document does not knob refuses loudly. The names the
// walk visited are returned for the face's coverage judgment.
func (e *Embedded) MustDescribeSchema(surface, verb string, root SchemaNode) []string {
	names, err := e.Must().DescribeSchema(surface, verb, root)
	if err != nil {
		e.refuse(err)
	}
	return names
}

// Registration is the face-neutral projection a consumer registers a
// verb from — on the CLI a cobra command's Short, Long, and flag
// usages; on the MCP a tool's description and its schema's property
// descriptions — every string the document's, the face holding no
// grammar of its own (REQ-guidance-render, REQ-guidance-single-source).
type Registration struct {
	// Verb is the verb's spelling on the surface.
	Verb string
	// Description is the one-line purpose (a command's Short, a tool's
	// description).
	Description string
	// Help is the knobless long rendering — a surface rendering its own
	// knob list (a CLI's flag help) sets it as the long help.
	Help string
	// Long is the whole section — the guidance verb's answer.
	Long string
	// Knobs are the verb's knobs on the surface, in document order,
	// each under its spelling with its clause and, on the CLI, its
	// usage (the MCP serves the clause; Usage is empty there).
	Knobs []KnobUsage
	// ProsePointer names the served path to the knobs' whole prose on
	// the surface the registration was projected for: on the CLI the
	// guidance command under the verb's CLI spelling (quoted where it
	// carries whitespace), on the MCP the guidance tool under the verb's
	// MCP spelling. Empty on a Document's own projection, which knows
	// no tool name; Embedded's carries it.
	ProsePointer string
}

// KnobUsage is one knob's served forms on a surface.
type KnobUsage struct {
	Name   string
	Clause string
	Usage  string
}

// Registration projects the verb's registration on a surface with the
// prose pointer naming the tool the embedded document belongs to.
func (e *Embedded) Registration(surface, verb string) (Registration, error) {
	doc, err := e.Document()
	if err != nil {
		return Registration{}, err
	}
	r, err := doc.Registration(surface, verb)
	if err != nil {
		return Registration{}, err
	}
	r.ProsePointer = e.prosePointer(surface, r.Verb)
	return r, nil
}

// prosePointer is the pointer's wording per surface over the verb's
// spelling there.
func (e *Embedded) prosePointer(surface, spelling string) string {
	if surface == "mcp" {
		return "The knobs' whole prose: the guidance tool, verb " + spelling + "."
	}
	if strings.IndexFunc(spelling, unicode.IsSpace) >= 0 {
		spelling = strconv.Quote(spelling)
	}
	return "The knobs' whole prose: " + e.tool + " guidance " + spelling + "."
}

// Registration projects the verb's registration on a surface: the
// verb's spelling there, the purpose, the knobless help, the whole
// section, and every knob on the surface with its clause and (on the
// CLI) its usage; the prose pointer is Embedded's, since it names the
// tool.
func (d *Document) Registration(surface, verb string) (Registration, error) {
	v, err := d.resolve(surface, verb)
	if err != nil {
		return Registration{}, err
	}
	spelling, _ := on(v.Surfaces, v.Name, surface)
	r := Registration{Verb: spelling, Description: v.Does, Help: helpOf(v), Long: longOf(v, surface)}
	for _, kn := range knobsOn(v, surface) {
		usage := ""
		if surface == "cli" {
			usage = kn.Usage()
		}
		r.Knobs = append(r.Knobs, KnobUsage{Name: kn.spelling, Clause: kn.Clause(), Usage: usage})
	}
	return r, nil
}

// Usage is the knob's clause in pflag's usage grammar: pflag reads the
// first back-quoted word of a usage string as the flag's value name (a
// `attest` span would print a boolean flag as value-taking), so the
// document's code spans lose their quotes; and cobra appends a flag's
// non-zero default itself, so the clause's own "(default X)"
// parenthetical goes — matched by parenthesis depth, so a default
// naming a call keeps its own parentheses inside — or the default
// prints twice. The document's rule for a knob whose CLI default is
// non-zero: spell the default as "(default X)" — the one form this
// grammar strips — and no other default, in any spelling of the word,
// in the first clause; the coverage judgment on the CLI surface, told
// which flags carry a non-zero default, refuses any other spelling
// there (REQ-guidance-render, REQ-guidance-coverage).
func (k Knob) Usage() string {
	return strings.ReplaceAll(strings.TrimSpace(stripDefault(k.Clause())), "`", "")
}

// stripDefault removes every "(default …)" parenthetical, matched by
// depth, with the blank before it. A parenthetical that never closes
// is left as it stands — the clause renders unchanged, its "default"
// word intact, so on a non-zero-default flag the coverage judgment
// refuses it rather than a mangled usage being served.
func stripDefault(clause string) string {
	for {
		start := strings.Index(clause, "(default ")
		if start < 0 {
			return clause
		}
		depth, end := 0, -1
		for i := start; i < len(clause); i++ {
			switch clause[i] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					end = i
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			return clause
		}
		before := strings.TrimRight(clause[:start], " \t")
		clause = before + clause[end+1:]
	}
}

// spellsDefaultOutsideTheForm reports a first clause that names a
// default other than in the "(default X)" form the usage grammar
// strips — a colon form, a prose default, "defaults to" — in any
// spelling of the word, since every one would print beside the
// library's own on a non-zero-default flag.
func spellsDefaultOutsideTheForm(clause string) bool {
	return strings.Contains(strings.ToLower(stripDefault(clause)), "default")
}

// SchemaNode is the shape DescribeSchema walks: a consumer adapts its
// schema type (an object's property names and nodes, an array's item
// schema, the description setter) so the package owns the walk without
// a schema dependency. Every node answer is the two-value form —
// Property and Items report presence beside the node — so an adapter
// never wraps a nil schema pointer in the interface (a typed nil
// behind SchemaNode would pass a nil check and dereference at the
// walk): a name the schema lists with no node answers false — the
// adapter's own nil check, never its map's presence alone. The walk
// is over a finite tree: an adapter resolving references cuts its own
// cycles.
type SchemaNode interface {
	// Properties returns the node's property names in any order.
	Properties() []string
	// Property returns the named property's node and whether the schema
	// carries one.
	Property(name string) (SchemaNode, bool)
	// Items returns an array node's item schema and whether it has one.
	Items() (SchemaNode, bool)
	// Describe sets the node's description.
	Describe(text string)
}

// DescribeSchema is the one schema projection: every property at every
// depth — a nested object's properties and an array's items alike —
// takes the verb's knob of its own name on the surface, its
// description the knob's terse clause; a property the document does
// not knob is refused by name — the first in the walk's order, each
// node's names sorted and its properties walked before its items, so
// the refusal is one whatever the adapter's order — since an agent
// fills nested fields as it fills top-level ones and each earns its
// prose; a named property with no node still needs its knob and takes
// no description; a nil root describes nothing. The names visited, deduplicated and
// sorted, return for the face's coverage judgment — the one walk both
// the descriptions and the coverage enumeration derive from
// (REQ-guidance-render, REQ-guidance-coverage).
func (d *Document) DescribeSchema(surface, verb string, root SchemaNode) ([]string, error) {
	visited := map[string]bool{}
	if err := d.describe(surface, verb, root, visited); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(visited))
	for name := range visited {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (d *Document) describe(surface, verb string, node SchemaNode, visited map[string]bool) error {
	if node == nil {
		return nil
	}
	names := append([]string(nil), node.Properties()...)
	sort.Strings(names)
	for _, name := range names {
		k, err := d.Knob(surface, verb, name)
		if err != nil {
			return err
		}
		visited[name] = true
		prop, ok := node.Property(name)
		if !ok {
			continue
		}
		prop.Describe(k.Clause())
		if err := d.describe(surface, verb, prop, visited); err != nil {
			return err
		}
	}
	if items, ok := node.Items(); ok {
		return d.describe(surface, verb, items, visited)
	}
	return nil
}
