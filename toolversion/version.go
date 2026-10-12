// Package toolversion reports the running executable's embedded build identity.
// Its standard-library-only module is versioned independently of the analysis
// module so an identity query never requires a freshness-engine migration.
package toolversion

import (
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"
	"unicode"
)

const gofreshPath = "github.com/greatliontech/gofresh"

// Identity returns one field-report line fragment: the module version and the
// available revision, modified state, compiler and linked Gofresh identity.
// It reads no project, environment, file or subprocess. Callers prepend their
// tool name and may append separately labelled capability information.
func Identity() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		info = nil
	}
	return identity(info)
}

func identity(info *debug.BuildInfo) string {
	version, revision, modified, compiler, dependency := "unknown", "unknown", "unknown", "unknown", "unknown"
	if info != nil {
		version = moduleVersion(info.Main.Version)
		compiler = known(info.GoVersion)
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				revision = known(setting.Value)
			case "vcs.modified":
				if setting.Value == "true" || setting.Value == "false" {
					modified = setting.Value
				}
			}
		}
		dependency = "not-linked"
		for _, dep := range info.Deps {
			if dep.Path != gofreshPath {
				continue
			}
			dependency = moduleVersion(dep.Version)
			if replacement := dep.Replace; replacement != nil {
				if replacement.Version == "" || replacement.Version == "(devel)" {
					dependency += "=>local:" + replacement.Path
				} else {
					dependency += "=>" + replacement.Path + "@" + replacement.Version
				}
			}
			break
		}
	}
	return fmt.Sprintf("%s (revision=%s, modified=%s, go=%s, gofresh=%s)",
		word(version), word(revision), modified, word(compiler), word(dependency))
}

func known(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

func moduleVersion(value string) string {
	if value == "(devel)" {
		return "devel"
	}
	return known(value)
}

// Quote values carrying the line's framing or whitespace, including a local
// replacement path. A metadata value never introduces a second output line.
func word(value string) string {
	if strings.ContainsAny(value, "\"(),") || strings.ContainsFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) {
		return strconv.Quote(value)
	}
	return value
}
