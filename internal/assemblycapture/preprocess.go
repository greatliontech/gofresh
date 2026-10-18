package assemblycapture

import (
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/scanner"
	"unicode"
)

type asmToken struct {
	kind                     rune
	text, file               string
	line, column, end, depth int
}
type macro struct {
	args []string
	body []asmToken
}
type preprocessor struct {
	inputs     *inputSet
	inv        Invocation
	top        string
	macros     map[string]macro
	conditions []bool
	lookups    []Lookup
	lines      []Line
	line       []asmToken
}

func tokenize(text, file string, m *meter) ([]asmToken, error) {
	var s scanner.Scanner
	s.Init(strings.NewReader(text))
	s.Whitespace = 1<<'\t' | 1<<'\r' | 1<<' '
	s.Mode = scanner.ScanChars | scanner.ScanFloats | scanner.ScanIdents | scanner.ScanInts | scanner.ScanStrings | scanner.ScanComments
	s.IsIdentRune = func(r rune, i int) bool {
		return unicode.IsLetter(r) || r == '_' || r == '·' || r == '∕' || i > 0 && unicode.IsDigit(r)
	}
	var scanErr error
	s.Error = func(_ *scanner.Scanner, message string) {
		scanErr = fmt.Errorf("assembly capture: %s: %s", file, message)
	}
	var out []asmToken
	for {
		kind := s.Scan()
		if scanErr != nil {
			return nil, scanErr
		}
		if kind == scanner.EOF {
			break
		}
		if err := m.charge("tokens", 1); err != nil {
			return nil, err
		}
		if kind == scanner.Comment {
			continue
		}
		t := asmToken{kind: kind, text: s.TokenText(), file: file, line: s.Position.Line, column: s.Position.Column, end: s.Pos().Column}
		if (kind == '<' && s.Peek() == '<') || (kind == '>' && s.Peek() == '>') || ((kind == '-' || kind == '@') && s.Peek() == '>') {
			t.text += string(s.Next())
			t.end = s.Pos().Column
			// A combined operator must never be confused with a single '<'
			// in a function-like macro's argument grammar.
			t.kind = -100
		}
		out = append(out, t)
	}
	return out, nil
}

func preprocess(inputs *inputSet, inv Invocation, source string) (Provider, []Lookup, error) {
	p := &preprocessor{inputs: inputs, inv: inv, top: filepath.Dir(source), macros: map[string]macro{}}
	for _, definition := range inv.Defines {
		name, value, has := strings.Cut(definition, "=")
		if !has {
			value = "1"
		}
		n, err := tokenize(name, "<command-line>", inputs.m)
		if err != nil {
			return Provider{}, nil, err
		}
		if len(n) != 1 || n[0].kind != scanner.Ident {
			return Provider{}, nil, fmt.Errorf("assembly capture: malformed -D name %q", name)
		}
		body, err := tokenize(value, "<command-line>", inputs.m)
		if err != nil {
			return Provider{}, nil, err
		}
		if err := safeMacro(body); err != nil {
			return Provider{}, nil, err
		}
		// The assembler uses last -D value, unlike #define redefinition.
		p.macros[name] = macro{body: body}
	}
	if err := p.file(source, 0); err != nil {
		return Provider{}, nil, err
	}
	if len(p.conditions) != 0 {
		return Provider{}, nil, fmt.Errorf("assembly capture: unclosed assembly conditional")
	}
	if err := p.flush(); err != nil {
		return Provider{}, nil, err
	}
	return Provider{Source: source, Lines: p.lines, Invocation: cloneInvocation(inv)}, p.lookups, nil
}

func (p *preprocessor) enabled() bool {
	return len(p.conditions) == 0 || p.conditions[len(p.conditions)-1]
}

func (p *preprocessor) flush() error {
	if len(p.line) == 0 {
		return nil
	}
	line := Line{File: p.line[0].file, Line: p.line[0].line}
	for _, t := range p.line {
		if err := p.inputs.m.charge("bytes", len(t.text)+1); err != nil {
			return err
		}
		line.Tokens = append(line.Tokens, t.text)
	}
	line.Text = strings.Join(line.Tokens, " ")
	p.lines = append(p.lines, line)
	p.line = nil
	return nil
}

func (p *preprocessor) file(path string, depth int) error {
	if depth >= p.inputs.m.limits.Depth {
		return fmt.Errorf("assembly capture: include depth bound exhausted")
	}
	o, err := p.inputs.read(path)
	if err != nil {
		return err
	}
	if o.absent {
		return fmt.Errorf("assembly capture: source is absent: %s", path)
	}
	tokens, err := tokenize(string(o.data), path, p.inputs.m)
	if err != nil {
		return err
	}
	return p.process(tokens, depth)
}

func safeMacro(body []asmToken) error {
	for _, t := range body {
		if t.kind == '#' {
			return fmt.Errorf("assembly capture: macro-generated directives or token pasting are unsupported")
		}
	}
	return nil
}

func (p *preprocessor) process(tokens []asmToken, depth int) error {
	bol := len(p.line) == 0
	for i := 0; i < len(tokens); {
		if err := p.inputs.m.ctx.Err(); err != nil {
			return err
		}
		t := tokens[i]
		if t.kind == '#' {
			if !bol || t.depth != 0 {
				return fmt.Errorf("assembly capture: misplaced or generated directive at %s:%d", t.file, t.line)
			}
			end := i + 1
			for end < len(tokens) {
				if tokens[end].kind == '\n' {
					break
				}
				if tokens[end].kind == '\\' && end+1 < len(tokens) && (tokens[end+1].kind == '\\' || tokens[end+1].kind == '\n') {
					end += 2
					continue
				}
				end++
			}
			if end == len(tokens) {
				return fmt.Errorf("assembly capture: directive missing terminating newline")
			}
			if err := p.directive(tokens[i+1:end], depth); err != nil {
				return err
			}
			i = end + 1
			bol = true
			continue
		}
		if t.kind == scanner.Ident {
			if def, ok := p.macros[t.text]; ok {
				if t.depth >= p.inputs.m.limits.Depth {
					return fmt.Errorf("assembly capture: macro expansion bound exhausted")
				}
				end := i + 1
				var actual [][]asmToken
				if def.args != nil {
					if end >= len(tokens) || tokens[end].kind != '(' {
						return fmt.Errorf("assembly capture: bare function-like macro is outside the preprocessing grammar")
					}
					end++
					start, nesting := end, 0
					for ; end < len(tokens); end++ {
						k := tokens[end].kind
						if k == '\n' {
							return fmt.Errorf("assembly capture: newline in macro arguments")
						}
						if nesting == 0 && (k == ',' || k == ')') {
							actual = append(actual, tokens[start:end])
							start = end + 1
							if k == ')' {
								break
							}
						} else if k == '(' {
							nesting++
						} else if k == ')' {
							nesting--
						}
					}
					if end == len(tokens) {
						return fmt.Errorf("assembly capture: unterminated macro arguments")
					}
					end++
					if len(def.args) == 0 && len(actual) == 1 && len(actual[0]) == 0 {
						actual = nil
					}
					if len(actual) != len(def.args) {
						return fmt.Errorf("assembly capture: macro argument count mismatch")
					}
				}
				var expansion []asmToken
				for _, replacement := range def.body {
					arg := -1
					if replacement.kind == scanner.Ident {
						arg = slices.Index(def.args, replacement.text)
					}
					// In the Go assembler interface, an empty actual has a nil
					// token list and does not replace its formal. It may then
					// expand as an ordinary macro name in the surrounding input.
					if arg >= 0 && len(actual[arg]) != 0 {
						expansion = append(expansion, actual[arg]...)
					} else {
						expansion = append(expansion, replacement)
					}
				}
				if err := p.inputs.m.charge("tokens", len(expansion)+1); err != nil {
					return err
				}
				for j := range expansion {
					expansion[j].file, expansion[j].line, expansion[j].depth = t.file, t.line, t.depth+1
				}
				// Keep the remaining input beside the expansion: a replacement
				// naming another function macro may consume the original '(...)'.
				next := make([]asmToken, 0, len(expansion)+len(tokens)-end)
				next = append(next, expansion...)
				next = append(next, tokens[end:]...)
				tokens, i = next, 0
				continue
			}
		}
		if t.kind == '\n' {
			if p.enabled() {
				if err := p.flush(); err != nil {
					return err
				}
			}
			bol = true
		} else {
			if p.enabled() {
				p.line = append(p.line, t)
			}
			bol = false
		}
		i++
	}
	return nil
}

func (p *preprocessor) directive(ts []asmToken, depth int) error {
	if len(ts) == 0 || ts[0].kind != scanner.Ident {
		return fmt.Errorf("assembly capture: malformed preprocessor directive")
	}
	name, args := ts[0].text, ts[1:]
	identifier := func() (string, error) {
		if len(args) != 1 || args[0].kind != scanner.Ident {
			return "", fmt.Errorf("assembly capture: malformed #%s", name)
		}
		return args[0].text, nil
	}
	switch name {
	case "ifdef", "ifndef":
		id, err := identifier()
		if err != nil {
			return err
		}
		_, defined := p.macros[id]
		if name == "ifndef" {
			defined = !defined
		}
		p.conditions = append(p.conditions, p.enabled() && defined)
		if len(p.conditions) > p.inputs.m.limits.Depth {
			return fmt.Errorf("assembly capture: conditional depth bound exhausted")
		}
	case "else":
		if len(args) != 0 || len(p.conditions) == 0 {
			return fmt.Errorf("assembly capture: malformed or unmatched #else")
		}
		n := len(p.conditions)
		if n == 1 || p.conditions[n-2] {
			p.conditions[n-1] = !p.conditions[n-1]
		}
	case "endif":
		if len(args) != 0 || len(p.conditions) == 0 {
			return fmt.Errorf("assembly capture: malformed or unmatched #endif")
		}
		p.conditions = p.conditions[:len(p.conditions)-1]
	case "define", "undef", "include", "line":
		if !p.enabled() && name != "line" {
			return nil
		}
		switch name {
		case "define":
			if len(args) == 0 || args[0].kind != scanner.Ident {
				return fmt.Errorf("assembly capture: malformed #define")
			}
			id := args[0].text
			if _, exists := p.macros[id]; exists {
				return fmt.Errorf("assembly capture: macro %s redefined", id)
			}
			def := macro{}
			at := 1
			if at < len(args) && args[at].kind == '(' && args[at].line == args[0].line && args[at].column == args[0].end {
				def.args = []string{}
				at++
				for at < len(args) && args[at].kind != ')' {
					if args[at].kind != scanner.Ident || slices.Contains(def.args, args[at].text) {
						return fmt.Errorf("assembly capture: malformed macro parameters")
					}
					def.args = append(def.args, args[at].text)
					at++
					if at < len(args) && args[at].kind == ',' {
						at++
						continue
					}
					if at >= len(args) || args[at].kind != ')' {
						return fmt.Errorf("assembly capture: malformed macro parameter separator")
					}
				}
				if at >= len(args) {
					return fmt.Errorf("assembly capture: unterminated macro parameters")
				}
				at++
			}
			for ; at < len(args); at++ {
				t := args[at]
				if t.kind == '\\' {
					at++
					if at >= len(args) || args[at].kind != '\n' && args[at].kind != '\\' {
						return fmt.Errorf("assembly capture: unsupported macro escape")
					}
					t = args[at]
				}
				def.body = append(def.body, t)
			}
			if err := safeMacro(def.body); err != nil {
				return err
			}
			p.macros[id] = def
		case "undef":
			id, err := identifier()
			if err != nil {
				return err
			}
			if _, ok := p.macros[id]; !ok {
				return fmt.Errorf("assembly capture: undefined #undef %s", id)
			}
			delete(p.macros, id)
		case "include":
			if len(args) != 1 || args[0].kind != scanner.String {
				return fmt.Errorf("assembly capture: unsupported include operand")
			}
			path, err := strconv.Unquote(args[0].text)
			if err != nil || path == "" {
				return fmt.Errorf("assembly capture: malformed include path")
			}
			lookup := Lookup{Name: path}
			candidates := []string{absolute(p.inv.CWD, path)}
			if !filepath.IsAbs(path) {
				for _, dir := range append([]string{p.top}, p.inv.IncludeDirs...) {
					candidates = append(candidates, absolute(p.inv.CWD, filepath.Join(dir, path)))
				}
			}
			for _, candidate := range candidates {
				o, err := p.inputs.read(candidate)
				if err != nil {
					return err
				}
				if o.absent {
					lookup.Failed = append(lookup.Failed, candidate)
					continue
				}
				lookup.Selected = candidate
				break
			}
			if lookup.Selected == "" {
				return fmt.Errorf("assembly capture: unresolved include %q", path)
			}
			p.lookups = append(p.lookups, lookup)
			return p.file(lookup.Selected, depth+1)
		case "line":
			if len(args) != 2 || args[0].kind != scanner.Int || args[1].kind != scanner.String {
				return fmt.Errorf("assembly capture: malformed #line")
			}
			if _, err := strconv.Atoi(args[0].text); err != nil {
				return err
			}
			if _, err := strconv.Unquote(args[1].text); err != nil {
				return err
			}
			// #line affects debug locations. Physical origin remains the one
			// in this packet; no directive can replace its source ownership.
		}
	default:
		return fmt.Errorf("assembly capture: unsupported preprocessor directive #%s", name)
	}
	return nil
}
