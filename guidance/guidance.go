// Package guidance parses and renders the fleet's tool-resident
// guidance documents (docs/specs/guidance.md): one structured
// markdown file per tool, embedded at build time and projected onto
// every surface at initialization, so a verb's served prose has
// exactly one home. The package is deliberately projection-only —
// rendering synthesizes no prose, and the per-surface coverage
// judgment is the hook a consuming repo's drift binding enforces.
// The per-surface name index is built at parse time and collisions
// refuse there, so a shadowed section is unrepresentable.
package guidance

import (
	"fmt"
	"sort"
	"strings"
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
	var b strings.Builder
	b.WriteString(v.Does)
	b.WriteString("\n\nknobs:")
	listed := false
	for _, k := range v.Knobs {
		if spelling, exists := on(k.Surfaces, k.Name, surface); exists {
			fmt.Fprintf(&b, "\n  %s — %s", spelling, k.Text)
			listed = true
		}
	}
	if !listed {
		b.WriteString(" none")
	}
	b.WriteString("\n\nwhen: ")
	b.WriteString(v.When)
	b.WriteString("\n\nexample:\n")
	b.WriteString(v.Example)
	return b.String(), nil
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
	var b strings.Builder
	b.WriteString(v.Does)
	b.WriteString("\n\nwhen: ")
	b.WriteString(v.When)
	b.WriteString("\n\nexample:\n")
	b.WriteString(v.Example)
	return b.String(), nil
}

// Orientation is the decision map's body, verbatim
// (REQ-guidance-render).
func (d *Document) Orientation() string {
	return d.DecisionMap
}

// Coverage judges the document against one surface's registered
// verbs — surface spellings mapped to served parameter or flag
// names — and reports every divergence in both directions, in a
// deterministic order: registered verbs sorted, knob defects in
// registered-then-document order, unregistered sections last in
// document order (REQ-guidance-coverage). An unknown surface is the
// caller's error, distinct from the defect list; an empty defect
// list is the drift binding's pass condition.
func (d *Document) Coverage(surface string, registered map[string][]string) ([]string, error) {
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
		for _, k := range v.Knobs {
			if spelling, exists := on(k.Surfaces, k.Name, surface); exists {
				documented[spelling] = true
			}
		}
		registeredSet := map[string]bool{}
		params := append([]string(nil), registered[verb]...)
		sort.Strings(params)
		for _, p := range params {
			if registeredSet[p] {
				continue
			}
			registeredSet[p] = true
			if !documented[p] {
				defects = append(defects, fmt.Sprintf("verb %q: registered knob %q undocumented", verb, p))
			}
		}
		for _, k := range v.Knobs {
			spelling, exists := on(k.Surfaces, k.Name, surface)
			if exists && !registeredSet[spelling] {
				defects = append(defects, fmt.Sprintf("verb %q: documented knob %q not registered", verb, spelling))
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
