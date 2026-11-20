// Package buildflags validates and resolves the Go flags that select source for
// freshness analysis.
package buildflags

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/internal/gotool"
)

// Validate refuses flags whose selected source gofresh cannot represent,
// the effective GOFLAGS read from the pass's reader — its one snapshot,
// never a probe of its own. Explicit flags and effective GOFLAGS are
// checked together so analysis never silently falls back to disk source
// for an overlay-backed build.
func Validate(ctx context.Context, reader *gotool.EnvReader, explicit []string) error {
	for _, flag := range explicit {
		if isOverlayFlag(flag) {
			return unsupportedOverlay(flag)
		}
	}
	goFlags, err := reader.Value(ctx, "GOFLAGS")
	if err != nil {
		return fmt.Errorf("build flags: resolve GOFLAGS: %w", err)
	}
	parsedGoFlags, err := Fields(goFlags)
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
// buildvcsFlag rules (default "auto", IsBoolFlag() == true so bare -buildvcs
// does not consume the following argument, and explicit flags override GOFLAGS
// in left-to-right order up to "--").
func EffectiveBuildVCS(goflagsEnv string, explicit []string) (string, error) {
	parsedGoFlags, err := Fields(goflagsEnv)
	if err != nil {
		return "", fmt.Errorf("build flags: parse GOFLAGS: %w", err)
	}
	mode := "auto"
	if mode, err = scanBuildVCSSlice(parsedGoFlags, mode, false); err != nil {
		return "", err
	}
	return scanBuildVCSSlice(explicit, mode, true)
}

func scanBuildVCSSlice(args []string, mode string, consumeValueArgs bool) (string, error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if strings.HasPrefix(arg, "---") {
			trimmed := strings.TrimLeft(arg, "-")
			if trimmed == "buildvcs" || strings.HasPrefix(trimmed, "buildvcs=") {
				return "", fmt.Errorf("build flags: bad flag syntax: %s", arg)
			}
			continue
		}
		if arg == "-buildvcs" || arg == "--buildvcs" {
			mode = "true"
			continue
		}
		if val, ok := cutBuildVCSValue(arg); ok {
			parsed, err := parseBuildVCSValue(arg, val)
			if err != nil {
				return "", err
			}
			mode = parsed
			continue
		}
		if consumeValueArgs && isSeparateArgBuildFlag(arg) {
			i++
		}
	}
	return mode, nil
}

func cutBuildVCSValue(arg string) (string, bool) {
	if v, ok := strings.CutPrefix(arg, "-buildvcs="); ok {
		return v, true
	}
	if v, ok := strings.CutPrefix(arg, "--buildvcs="); ok {
		return v, true
	}
	return "", false
}

func parseBuildVCSValue(flag, val string) (string, error) {
	if val == "auto" {
		return "auto", nil
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return "", fmt.Errorf("build flags: invalid value %q for %s: neither \"auto\" nor a valid bool", val, flag)
	}
	return strconv.FormatBool(b), nil
}

var separateArgBuildFlags = map[string]bool{
	"C": true, "asmflags": true, "buildmode": true, "compiler": true,
	"covermode": true, "coverpkg": true, "coverprofile": true,
	"gccgoflags": true, "gcflags": true, "installsuffix": true,
	"ldflags": true, "mod": true, "modfile": true, "o": true,
	"overlay": true, "p": true, "pgo": true, "pkgdir": true,
	"tags": true, "toolexec": true,
}

func isSeparateArgBuildFlag(arg string) bool {
	if strings.HasPrefix(arg, "--") {
		return separateArgBuildFlags[arg[2:]]
	}
	if strings.HasPrefix(arg, "-") {
		return separateArgBuildFlags[arg[1:]]
	}
	return false
}

func isOverlayFlag(flag string) bool {
	name := strings.TrimLeft(flag, "-")
	return name == "overlay" || strings.HasPrefix(name, "overlay=")
}

func unsupportedOverlay(flag string) error {
	return fmt.Errorf("build flags: %s is unsupported because freshness analysis hashes disk source", flag)
}
