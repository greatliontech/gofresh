package gotool

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// ValidateBuildFlags refuses flags whose selected source gofresh cannot
// represent, reading the effective GOFLAGS from the pass's reader — its one
// snapshot, never a probe of its own. Explicit flags and effective GOFLAGS are
// checked together so analysis never silently falls back to disk source for an
// overlay-backed build.
func ValidateBuildFlags(ctx context.Context, reader *EnvReader, explicit []string) error {
	for _, flag := range explicit {
		if isOverlayFlag(flag) {
			return unsupportedOverlay(flag)
		}
	}
	goFlags, err := reader.Value(ctx, "GOFLAGS")
	if err != nil {
		return fmt.Errorf("build flags: resolve GOFLAGS: %w", err)
	}
	parsedGoFlags, err := QuotedFields(goFlags)
	if err != nil {
		return fmt.Errorf("build flags: parse GOFLAGS: %w", err)
	}
	for _, flag := range parsedGoFlags {
		if isOverlayFlag(flag) {
			return unsupportedOverlay(flag)
		}
	}
	return nil
}

// EffectiveBuildVCS resolves the effective -buildvcs setting ("auto", "true",
// or "false") across GOFLAGS and explicit build flags following cmd/go's
// SetFromGOFLAGS and buildvcsFlag rules (default "auto", -buildvcs= resolves
// to "auto", IsBoolFlag() == true so bare -buildvcs does not consume the
// following argument, GOFLAGS requires standalone -flag or -flag=value tokens,
// and explicit flag parsing stops at "--" or the first non-flag token while
// failing closed on unrecognized bare flags without "=value").
func EffectiveBuildVCS(goflagsEnv string, explicit []string) (string, error) {
	parsedGoFlags, err := QuotedFields(goflagsEnv)
	if err != nil {
		return "", fmt.Errorf("build flags: parse GOFLAGS: %w", err)
	}
	mode := "auto"
	if mode, err = scanGoFlagsBuildVCS(parsedGoFlags, mode); err != nil {
		return "", err
	}
	return scanExplicitBuildVCS(explicit, mode)
}

func scanGoFlagsBuildVCS(args []string, mode string) (string, error) {
	for _, arg := range args {
		name, val, hasEq, ok := parseFlagToken(arg)
		if !ok {
			return "", fmt.Errorf("build flags: invalid GOFLAGS token %q", arg)
		}
		if name == "buildvcs" {
			if !hasEq {
				mode = "true"
				continue
			}
			parsed, err := parseBuildVCSValue(arg, val)
			if err != nil {
				return "", err
			}
			mode = parsed
			continue
		}
		if !hasEq && separateArgBuildFlags[name] {
			return "", fmt.Errorf("build flags: flag %s in GOFLAGS needs an argument", arg)
		}
	}
	return mode, nil
}

func scanExplicitBuildVCS(args []string, mode string) (string, error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if len(arg) < 2 || arg[0] != '-' {
			break
		}
		if arg == "--" {
			break
		}
		name, val, hasEq, ok := parseFlagToken(arg)
		if !ok {
			return "", fmt.Errorf("build flags: bad flag syntax: %s", arg)
		}
		if name == "buildvcs" {
			if !hasEq {
				mode = "true"
				continue
			}
			parsed, err := parseBuildVCSValue(arg, val)
			if err != nil {
				return "", err
			}
			mode = parsed
			continue
		}
		if hasEq || knownBoolBuildFlags[name] {
			continue
		}
		if separateArgBuildFlags[name] {
			if i+1 >= len(args) {
				return "", fmt.Errorf("build flags: flag needs an argument: %s", arg)
			}
			i++
			continue
		}
		return "", fmt.Errorf("build flags: unrecognized bare flag %s without =value", arg)
	}
	return mode, nil
}

func parseFlagToken(arg string) (name, val string, hasEq, ok bool) {
	if !strings.HasPrefix(arg, "-") || arg == "-" || arg == "--" ||
		strings.HasPrefix(arg, "---") || strings.HasPrefix(arg, "-=") || strings.HasPrefix(arg, "--=") {
		return "", "", false, false
	}
	rest := arg[1:]
	if rest[0] == '-' {
		rest = rest[1:]
	}
	if rest == "" {
		return "", "", false, false
	}
	if eq := strings.IndexByte(rest, '='); eq >= 0 {
		return rest[:eq], rest[eq+1:], true, true
	}
	return rest, "", false, true
}

func parseBuildVCSValue(flag, val string) (string, error) {
	if val == "" || val == "auto" {
		return "auto", nil
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return "", fmt.Errorf("build flags: invalid value %q for %s: neither \"auto\" nor a valid bool", val, flag)
	}
	return strconv.FormatBool(b), nil
}

var knownBoolBuildFlags = map[string]bool{
	"a": true, "artifacts": true, "asan": true, "benchmem": true, "c": true,
	"compiled": true, "cover": true, "deps": true, "e": true, "export": true,
	"failfast": true, "find": true, "fullpath": true, "i": true, "json": true,
	"linkshared": true, "m": true, "modcacherw": true, "msan": true, "n": true,
	"race": true, "retracted": true, "short": true, "test": true, "trimpath": true,
	"u": true, "v": true, "versions": true, "work": true, "x": true,
}

var separateArgBuildFlags = map[string]bool{
	"C": true, "asmflags": true, "bench": true, "benchtime": true,
	"blockprofile": true, "blockprofilerate": true, "buildmode": true,
	"compiler": true, "count": true, "covermode": true, "coverpkg": true,
	"coverprofile": true, "cpu": true, "cpuprofile": true,
	"debug-actiongraph": true, "debug-runtime-trace": true, "debug-trace": true,
	"exec": true, "f": true, "fuzz": true, "fuzzminimizetime": true,
	"fuzztime": true, "gccgoflags": true, "gcflags": true, "installsuffix": true,
	"ldflags": true, "list": true, "memprofile": true, "memprofilerate": true,
	"mod": true, "modfile": true, "mutexprofile": true,
	"mutexprofilefraction": true, "o": true, "outputdir": true, "overlay": true,
	"p": true, "parallel": true, "pgo": true, "pkgdir": true, "reuse": true,
	"run": true, "shuffle": true, "skip": true, "tags": true, "timeout": true,
	"toolexec": true, "trace": true, "vet": true,
}

func isOverlayFlag(flag string) bool {
	name := strings.TrimLeft(flag, "-")
	return name == "overlay" || strings.HasPrefix(name, "overlay=")
}

func unsupportedOverlay(flag string) error {
	return fmt.Errorf("build flags: %s is unsupported because freshness analysis hashes disk source", flag)
}
