package assemblycapture

import (
	"fmt"
	"path/filepath"
	"strings"
)

// responseWords models the tool's GCC-compatible response grammar. Malformed
// quotes are refused even on toolchains which tolerate an unterminated word.
func responseWords(data []byte) ([]string, error) {
	var result []string
	var word strings.Builder
	quote := byte(0)
	started := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if c == 0 {
			return nil, fmt.Errorf("assembly capture: NUL in response file")
		}
		// objabi consumes an unquoted escape at EOF without emitting it.
		// In particular, @nested.rsp\ selects nested.rsp, not nested.rsp\.
		if quote == 0 && c == '\\' && i+1 == len(data) {
			continue
		}
		if quote == '\'' {
			if c == quote {
				quote = 0
			} else {
				word.WriteByte(c)
			}
			continue
		}
		if c == '\\' && i+1 < len(data) {
			n := data[i+1]
			if n == '\n' {
				i++
				continue
			}
			if n == '\r' && i+2 < len(data) && data[i+2] == '\n' {
				i += 2
				continue
			}
			if quote == 0 || n == '\\' || n == '"' || n == '$' || n == '`' {
				word.WriteByte(n)
				started = true
				i++
				continue
			}
		}
		if quote == '"' {
			if c == '"' {
				quote = 0
			} else {
				word.WriteByte(c)
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			started = true
		case ' ', '\t', '\r', '\n':
			if started || word.Len() > 0 {
				result = append(result, word.String())
				word.Reset()
				started = false
			}
		default:
			word.WriteByte(c)
			started = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("assembly capture: unterminated response-file quote")
	}
	if started || word.Len() > 0 {
		result = append(result, word.String())
	}
	return result, nil
}

func expandArgs(inputs *inputSet, cwd string, args []string, depth int) ([]string, error) {
	if depth >= inputs.m.limits.Depth {
		return nil, fmt.Errorf("assembly capture: response-file depth bound exhausted")
	}
	var out []string
	for _, arg := range args {
		if err := inputs.m.charge("tokens", 1); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(arg, "@") {
			if err := inputs.m.charge("bytes", len(arg)); err != nil {
				return nil, err
			}
			out = append(out, arg)
			continue
		}
		if len(arg) == 1 {
			return nil, fmt.Errorf("assembly capture: empty response-file operand")
		}
		file, err := inputs.read(absolute(cwd, arg[1:]))
		if err != nil {
			return nil, err
		}
		if file.absent {
			return nil, fmt.Errorf("assembly capture: missing response file %s", arg[1:])
		}
		words, err := responseWords(file.data)
		if err != nil {
			return nil, err
		}
		expanded, err := expandArgs(inputs, cwd, words, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, expanded...)
	}
	return out, nil
}

type parsedTool struct {
	flags    map[string][]string
	operands []string
}

// The grammar distinguishes flags from operands, rather than finding filenames
// by suffix. Unknown tool options refuse capture instead of hiding an input in
// an unmodelled option's value.
func parseTool(args []string, tool string) (parsedTool, error) {
	p := parsedTool{flags: map[string][]string{}}
	stringsFlags := map[string]bool{}
	boolFlags := map[string]bool{}
	if tool == "asm" {
		for _, s := range []string{"D", "I", "o", "p", "trimpath", "spectre", "d"} {
			stringsFlags[s] = true
		}
		for _, s := range []string{"debug", "shared", "dynlink", "linkshared", "e", "gensymabis", "std", "v", "S", "V"} {
			boolFlags[s] = true
		}
	} else if tool == "compile" {
		for _, s := range []string{"o", "p", "trimpath", "lang", "installsuffix", "buildid", "goversion", "coveragecfg", "pgoprofile", "symabis", "c", "d", "D", "I", "importcfg", "embedcfg", "asmhdr", "bench", "blockprofile", "cpuprofile", "memprofile", "memprofilerate", "mutexprofile", "linkobj", "spectre", "json", "debugdwarf", "gendwarfinl", "lowerL"} {
			stringsFlags[s] = true
		}
		for _, s := range []string{"std", "complete", "dwarf", "nolocalimports", "pack", "race", "msan", "asan", "shared", "dynlink", "linkshared", "N", "l", "B", "C", "E", "K", "L", "S", "V", "W", "e", "h", "m", "r", "s", "t", "w", "wb", "smallframes", "clobberdead", "clobberdeadreg", "dwarflocationlists", "dwarfbasentries", "dwarfwb", "live", "v", "no-optimize"} {
			boolFlags[s] = true
		}
	} else if tool == "preprofile" {
		stringsFlags["i"] = true
		stringsFlags["o"] = true
	} else {
		return p, fmt.Errorf("assembly capture: unsupported tool parser %s", tool)
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			p.operands = append(p.operands, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			p.operands = append(p.operands, args[i:]...)
			break
		}
		name, value, equal := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if stringsFlags[name] {
			if !equal {
				i++
				if i == len(args) {
					return p, fmt.Errorf("assembly capture: missing -%s operand", name)
				}
				value = args[i]
			}
		} else if boolFlags[name] {
			if !equal {
				value = "true"
			}
		} else {
			return p, fmt.Errorf("assembly capture: unmodelled %s option -%s", tool, name)
		}
		p.flags[name] = append(p.flags[name], value)
	}
	return p, nil
}

func (p parsedTool) last(key string) string {
	s := p.flags[key]
	if len(s) == 0 {
		return ""
	}
	return s[len(s)-1]
}

func parseInvocation(inputs *inputSet, inv Invocation) (Invocation, parsedTool, error) {
	args, err := expandArgs(inputs, inv.CWD, inv.Args, 0)
	if err != nil {
		return inv, parsedTool{}, err
	}
	p, err := parseTool(args, filepath.Base(inv.Tool))
	if err != nil {
		return inv, p, err
	}
	inv.ExpandedArgs = args
	inv.Package = p.last("p")
	inv.IncludeDirs = append([]string(nil), p.flags["I"]...)
	inv.Defines = append([]string(nil), p.flags["D"]...)
	inv.Output = absolute(inv.CWD, p.last("o"))
	for _, name := range p.operands {
		inv.Sources = append(inv.Sources, absolute(inv.CWD, name))
	}
	return inv, p, nil
}
