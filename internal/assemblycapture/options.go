package assemblycapture

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/greatliontech/gofresh/internal/buildflags"
)

func flagValues(flags []string, key string) ([]string, error) {
	var values []string
	for i := 0; i < len(flags); i++ {
		name, value, eq := strings.Cut(strings.TrimLeft(flags[i], "-"), "=")
		if name != key {
			continue
		}
		if !eq {
			i++
			if i >= len(flags) {
				return nil, fmt.Errorf("assembly capture: missing -%s value", key)
			}
			value = flags[i]
		}
		values = append(values, value)
	}
	return values, nil
}

func packagePattern(pattern string, p Package, dir string) (bool, error) {
	switch pattern {
	case "all":
		return true, nil
	case "std":
		return p.Standard && !strings.HasPrefix(p.Path, "cmd/"), nil
	case "cmd":
		return p.Standard && strings.HasPrefix(p.Path, "cmd/"), nil
	}
	value := p.Path
	if strings.HasPrefix(pattern, ".") || filepath.IsAbs(pattern) {
		pattern = filepath.Clean(absolute(dir, pattern))
		value = p.Dir
	}
	// Go's ... does not match a vendor path element. Vendor packages remain
	// matchable by their explicit import path.
	if strings.Contains(pattern, "...") && (strings.HasPrefix(value, "vendor/") || strings.Contains(value, "/vendor/")) {
		return false, nil
	}
	expression := regexp.QuoteMeta(pattern)
	expression = strings.ReplaceAll(expression, `\.\.\.`, ".*")
	if strings.HasSuffix(pattern, "/...") {
		expression = strings.TrimSuffix(expression, "/.*") + "(/.*)?"
	}
	r, err := regexp.Compile("^" + expression + "$")
	if err != nil {
		return false, err
	}
	return r.MatchString(value), nil
}

// The last matching per-package rule wins. Values of unrelated rules are not
// combined, and the unqualified form applies only to the requested roots.
func (s *Selection) packageFlags(p Package, key string) ([]string, error) {
	values, err := flagValues(s.Flags(), key)
	if err != nil {
		return nil, err
	}
	var selected []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		match := p.Root
		if value != "" && !strings.HasPrefix(value, "-") {
			pattern, rest, ok := strings.Cut(value, "=")
			if !ok || pattern == "" {
				return nil, fmt.Errorf("assembly capture: malformed per-package flag")
			}
			match, err = packagePattern(strings.TrimSpace(pattern), p, s.request.Dir)
			if err != nil {
				return nil, err
			}
			value = rest
		}
		if match {
			selected, err = buildflags.Fields(value)
			if err != nil {
				return nil, err
			}
		}
	}
	return selected, nil
}

func (s *Selection) checkExplicitOptions(p Package, inv Invocation, parsed parsedTool, inputs *inputSet) error {
	key := "gcflags"
	if filepath.Base(inv.Tool) == "asm" {
		key = "asmflags"
	}
	expected, err := s.packageFlags(p, key)
	if err != nil {
		return err
	}
	// The effective explicit flags appear as one ordered argument fragment in
	// the driver invocation. Expanding response inputs checks that fragment's
	// actual tool meaning, with the same working-directory resolution.
	if len(expected) > 0 {
		found := false
		for i := 0; i+len(expected) <= len(inv.Args); i++ {
			if slices.Equal(inv.Args[i:i+len(expected)], expected) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("assembly capture: effective per-package %s disagree with owner: %s", key, p.ID)
		}
	}
	expanded, err := expandArgs(inputs, inv.CWD, expected, 0)
	if err != nil {
		return err
	}
	options, err := parseTool(expanded, filepath.Base(inv.Tool))
	if err != nil {
		return err
	}
	if len(options.operands) != 0 {
		return fmt.Errorf("assembly capture: per-package options introduce source operands")
	}
	// These options select compiler behavior, and have no driver-injected
	// default except the explicit instrumentation request. Unknown compiler
	// debug options remain recorded rather than silently normalized away.
	if key == "gcflags" {
		for _, name := range []string{"N", "l", "race", "msan", "asan"} {
			want := options.last(name)
			if want == "" && (name == "race" || name == "msan" || name == "asan") {
				for _, flag := range s.Flags() {
					if flag == "-"+name || flag == "-"+name+"=true" {
						want = "true"
					}
					if flag == "-"+name+"=false" {
						want = ""
					}
				}
			}
			got := parsed.last(name)
			if got == "false" || got == "0" {
				got = ""
			}
			if want == "false" || want == "0" {
				want = ""
			}
			if got != want {
				return fmt.Errorf("assembly capture: effective compiler -%s differs from owner: %s", name, p.ID)
			}
		}
	}
	return nil
}

func (s *Selection) collectFlagInputs(add func(string) ([]byte, error)) error {
	var visit func(string, []string, int) error
	visit = func(cwd string, args []string, depth int) error {
		if depth > 100 {
			return fmt.Errorf("assembly capture: option input recursion bound exhausted")
		}
		for i := 0; i < len(args); i++ {
			arg := args[i]
			if strings.HasPrefix(arg, "@") {
				data, err := add(absolute(cwd, arg[1:]))
				if err != nil {
					return err
				}
				if data == nil {
					continue
				}
				words, err := responseWords(data)
				if err != nil {
					return err
				}
				if err = visit(cwd, words, depth+1); err != nil {
					return err
				}
				continue
			}
			name, value, eq := strings.Cut(strings.TrimLeft(arg, "-"), "=")
			switch name {
			case "importcfg", "embedcfg", "symabis", "pgoprofile", "coveragecfg":
				if !eq {
					i++
					if i >= len(args) {
						return fmt.Errorf("assembly capture: missing configuration operand")
					}
					value = args[i]
				}
				if _, err := add(absolute(cwd, value)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, p := range s.packages {
		for _, key := range []string{"asmflags", "gcflags"} {
			flags, err := s.packageFlags(p, key)
			if err != nil {
				return err
			}
			cwd := s.request.Dir
			if key == "asmflags" {
				cwd = p.Dir
			}
			if err = visit(cwd, flags, 0); err != nil {
				return err
			}
		}
	}
	return nil
}
