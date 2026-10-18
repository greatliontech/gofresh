package closure

import (
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/greatliontech/gofresh/internal/assemblycapture"
)

type assemblyReferenceSymbol struct{ name, abi, local string }

type assemblyReferenceStatement struct {
	file string
	line int
	op   string
	args [][]string
}

type assemblyReferenceDefinition struct {
	symbol            assemblyReferenceSymbol
	flags             uint64
	locals, arguments int64
	body              []assemblyReferenceStatement
}

// Package-prefix escaping and assembly's middle-dot/division-slash spellings
// are naming operations of the Go object interface, not semantic approvals.
func assemblyReferencePackagePrefix(path string) string {
	last := strings.LastIndexByte(path, '/')
	var b strings.Builder
	for i := 0; i < len(path); i++ {
		c := path[i]
		if c <= ' ' || c == '.' && i > last || c == '%' || c == '"' || c >= 0x7f {
			fmt.Fprintf(&b, "%%%02x", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func assemblyReferenceIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if !unicode.IsLetter(r) && r != '_' && r != '.' && r != '·' && r != '∕' && !(i > 0 && unicode.IsDigit(r)) {
			return false
		}
	}
	return true
}

func assemblyReferenceSymbolOf(tokens []string, pkg, file string) (assemblyReferenceSymbol, error) {
	var out assemblyReferenceSymbol
	if len(tokens) < 4 || !assemblyReferenceIdentifier(tokens[0]) || !slices.Equal(tokens[len(tokens)-3:], []string{"(", "SB", ")"}) {
		return out, assemblyReferenceError("unsupported definition symbol spelling")
	}
	name := strings.ReplaceAll(strings.ReplaceAll(tokens[0], "·", "."), "∕", "/")
	if strings.HasPrefix(name, ".") {
		name = assemblyReferencePackagePrefix(pkg) + name
	}
	out = assemblyReferenceSymbol{name: name, abi: "ABI0"}
	attrs := tokens[1 : len(tokens)-3]
	switch {
	case len(attrs) == 0:
	case slices.Equal(attrs, []string{"<", ">"}):
		out.local = file
	case slices.Equal(attrs, []string{"<", "ABI0", ">"}):
	case slices.Equal(attrs, []string{"<", "ABIInternal", ">"}):
		out.abi = "ABIInternal"
	default:
		return out, assemblyReferenceError("unsupported symbol ABI or offset")
	}
	return out, nil
}

// The inventory grammar admits ordinary instructions which cannot define an
// object symbol. Their bodies are not thereby interpreted. Unknown directives,
// data definitions and raw instruction pseudo-operations conservatively refuse
// the complete binding, including when they precede or follow the desired TEXT.
func assemblyReferenceOrdinary(op string) bool {
	switch op {
	case "MOVQ", "MOVL", "MOVB", "CMPQ", "CMPL", "CMPB", "TESTQ", "TESTL", "TESTB",
		"LOCK", "CMPXCHGQ", "CMPXCHGL", "XADDQ", "XADDL", "ADDQ", "ADDL",
		"XCHGQ", "XCHGL", "XCHGB", "ANDQ", "ANDL", "ANDB", "ORQ", "ORL", "ORB",
		"XORQ", "XORL", "XORB", "RET", "JMP", "JNZ", "JZ", "JEQ", "JNE", "CALL",
		"SETEQ", "SETNE", "SETCS", "SETCC", "SETHI", "SETLS", "SETLT", "SETLE", "SETGT", "SETGE", "NOP":
		return true
	}
	return false
}

func assemblyReferenceOperands(tokens []string) ([][]string, error) {
	if len(tokens) == 0 {
		return nil, nil
	}
	var out [][]string
	start, depth := 0, 0
	for i, token := range tokens {
		switch token {
		case "(":
			depth++
		case ")":
			depth--
			if depth < 0 {
				return nil, assemblyReferenceError("unbalanced assembly operand")
			}
		case ":", "=", "#", "\n", "\r", ";":
			return nil, assemblyReferenceError("unexpanded or definition-capable operand syntax")
		case ",":
			if depth == 0 {
				if start == i {
					return nil, assemblyReferenceError("empty assembly operand")
				}
				out = append(out, slices.Clone(tokens[start:i]))
				start = i + 1
			}
		}
	}
	if depth != 0 || start == len(tokens) {
		return nil, assemblyReferenceError("incomplete assembly operand")
	}
	out = append(out, slices.Clone(tokens[start:]))
	return out, nil
}

func assemblyReferenceFlags(tokens []string) (uint64, error) {
	var value uint64
	for i, token := range tokens {
		if i%2 == 1 {
			if token != "|" {
				return 0, assemblyReferenceError("unsupported TEXT flag expression")
			}
			continue
		}
		n, err := strconv.ParseUint(token, 0, 32)
		if err != nil {
			return 0, assemblyReferenceError("TEXT flags are not expanded integer operands")
		}
		value |= n
	}
	if len(tokens)%2 != 1 || value & ^uint64(4|512) != 0 {
		return 0, assemblyReferenceError("unsupported or weak TEXT flags")
	}
	return value, nil
}

func assemblyReferenceText(statement assemblyReferenceStatement, pkg, provider string) (assemblyReferenceDefinition, error) {
	var out assemblyReferenceDefinition
	args := statement.args
	if len(args) != 2 && len(args) != 3 {
		return out, assemblyReferenceError("TEXT requires its full symbol, flags and frame operands")
	}
	var err error
	out.symbol, err = assemblyReferenceSymbolOf(args[0], pkg, provider)
	if err != nil {
		return out, err
	}
	if len(args) == 3 {
		out.flags, err = assemblyReferenceFlags(args[1])
		if err != nil {
			return out, err
		}
	}
	frame := args[len(args)-1]
	if len(frame) != 4 || frame[0] != "$" || frame[2] != "-" {
		return out, assemblyReferenceError("TEXT lacks exact nonnegative frame/argument sizes")
	}
	out.locals, err = strconv.ParseInt(frame[1], 0, 32)
	if err == nil {
		out.arguments, err = strconv.ParseInt(frame[3], 0, 32)
	}
	if err != nil || out.locals < 0 || out.arguments < 0 || out.symbol.abi == "ABIInternal" && out.flags&4 == 0 {
		return out, assemblyReferenceError("invalid TEXT ABI/frame declaration")
	}
	return out, nil
}

func assemblyReferenceInvocation(m *assemblyReferenceMeter, provider assemblycapture.Provider, pkg string) error {
	v := provider.Invocation
	if v.Tool == "" || v.CWD == "" || v.Package != pkg || provider.Source == "" {
		return assemblyReferenceError("incomplete final assembler invocation")
	}
	args := v.ExpandedArgs
	if len(args) == 0 {
		return assemblyReferenceError("missing effective assembler options")
	}
	packageSeen, outputSeen := false, false
	var sources, includes, defines []string
	for i := 0; i < len(args); i++ {
		if err := m.chargeBytes(len(args[i])); err != nil {
			return err
		}
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			if !filepath.IsAbs(arg) {
				arg = filepath.Join(v.CWD, arg)
			}
			sources = append(sources, filepath.Clean(arg))
			continue
		}
		if arg == "-std" {
			continue
		}
		flag, value, joined := strings.Cut(arg, "=")
		switch flag {
		case "-p", "-I", "-D", "-trimpath", "-o":
		default:
			return assemblyReferenceError("unsupported assembler transformation option: " + flag)
		}
		if !joined {
			i++
			if i >= len(args) {
				return assemblyReferenceError("incomplete assembler option")
			}
			value = args[i]
		}
		if err := m.chargeBytes(len(value)); err != nil {
			return err
		}
		switch flag {
		case "-p":
			if packageSeen || value != pkg {
				return assemblyReferenceError("assembler package qualification differs")
			}
			packageSeen = true
		case "-o":
			if outputSeen || value == "" {
				return assemblyReferenceError("ambiguous assembler output")
			}
			outputSeen = true
		case "-I":
			includes = append(includes, value)
		case "-D":
			defines = append(defines, value)
		}
	}
	if !packageSeen || !outputSeen || !slices.Contains(sources, filepath.Clean(provider.Source)) || !slices.Equal(includes, v.IncludeDirs) || !slices.Equal(defines, v.Defines) {
		return assemblyReferenceError("effective assembler membership/options disagree")
	}
	return nil
}

func assemblyReferenceDefinitions(m *assemblyReferenceMeter, providers []assemblycapture.Provider, pkg string) ([]assemblyReferenceDefinition, error) {
	if len(providers) == 0 || len(providers) > m.limits.instructions {
		return nil, assemblyReferenceError("missing or oversized provider inventory")
	}
	var out []assemblyReferenceDefinition
	seen := map[assemblyReferenceSymbol]bool{}
	files := map[string]bool{}
	count := 0
	for _, provider := range providers {
		if err := assemblyReferenceInvocation(m, provider, pkg); err != nil {
			return nil, err
		}
		if files[provider.Source] {
			return nil, assemblyReferenceError("duplicate selected provider")
		}
		files[provider.Source] = true
		current := -1
		labels := map[string]bool{}
		for _, line := range provider.Lines {
			if err := m.chargeBytes(len(line.Text) + len(line.File)); err != nil {
				return nil, err
			}
			if len(line.Tokens) > m.limits.nodes || line.File == "" || line.Line <= 0 {
				return nil, assemblyReferenceError("invalid expanded line provenance or token bound")
			}
			for _, token := range line.Tokens {
				if err := m.chargeBytes(len(token)); err != nil {
					return nil, err
				}
			}
			// A semicolon is an actual assembler statement boundary, including
			// when introduced by expansion. No joined text is reparsed as a name.
			start := 0
			for end := 0; end <= len(line.Tokens); end++ {
				if end < len(line.Tokens) && line.Tokens[end] != ";" {
					continue
				}
				tokens := line.Tokens[start:end]
				start = end + 1
				if len(tokens) == 0 {
					continue
				}
				count++
				if count > m.limits.instructions {
					return nil, assemblyReferenceError("complete provider instruction budget exhausted")
				}
				if len(tokens) >= 2 && tokens[1] == ":" {
					if current < 0 || !assemblyReferenceIdentifier(tokens[0]) || labels[tokens[0]] {
						return nil, assemblyReferenceError("invalid or repeated function-local label")
					}
					labels[tokens[0]] = true
					out[current].body = append(out[current].body, assemblyReferenceStatement{file: line.File, line: line.Line, op: ":"})
					tokens = tokens[2:]
					if len(tokens) == 0 {
						continue
					}
				}
				operands, err := assemblyReferenceOperands(tokens[1:])
				if err != nil {
					return nil, err
				}
				statement := assemblyReferenceStatement{line.File, line.Line, tokens[0], operands}
				if statement.op == "TEXT" {
					definition, err := assemblyReferenceText(statement, pkg, provider.Source)
					if err != nil {
						return nil, err
					}
					if seen[definition.symbol] {
						return nil, assemblyReferenceError("duplicate selected symbol/ABI definition")
					}
					seen[definition.symbol] = true
					out = append(out, definition)
					current, labels = len(out)-1, map[string]bool{}
				} else {
					if current < 0 || !assemblyReferenceOrdinary(statement.op) {
						return nil, assemblyReferenceError("unsupported definition boundary or assembly pseudo-operation: " + statement.op)
					}
					arity := 2
					switch statement.op {
					case "LOCK", "NOP":
						arity = 0
					case "RET":
						// RET symbol is a real tail-jump spelling. Inventory it;
						// the selected-body interpreter refuses its continuation.
						arity = len(statement.args)
						if arity > 1 {
							return nil, assemblyReferenceError("invalid return operand count")
						}
					case "JMP", "JNZ", "JZ", "JEQ", "JNE", "CALL", "SETEQ", "SETNE", "SETCS", "SETCC", "SETHI", "SETLS", "SETLT", "SETLE", "SETGT", "SETGE":
						arity = 1
					}
					if len(statement.args) != arity {
						return nil, assemblyReferenceError("invalid ordinary instruction operand count")
					}
					out[current].body = append(out[current].body, statement)
				}
			}
		}
	}
	return out, m.Err()
}
