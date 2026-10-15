package guard

import (
	"fmt"
	"strings"
	"testing"
	"testing/quick"
)

func TestRuntimeConfigSeparatesEmbeddedEnvironmentEntries(t *testing.T) {
	// Moving a key-shaped suffix between these values preserves the old
	// delimiter-only encoding but changes the runtime's effective GOGC.
	first := []string{"GOGC=200\nGODEBUG=x", "GODEBUG=y"}
	second := []string{"GOGC=200", "GODEBUG=x\nGODEBUG=y"}
	if runtimeConfig(first) == runtimeConfig(second) {
		t.Fatal("distinct runtime configurations share a guard")
	}
	for _, env := range [][]string{nil, first, second} {
		var legacy strings.Builder
		for _, key := range runtimeConfigEnvKeys {
			value := ""
			for _, entry := range env {
				if strings.HasPrefix(entry, key+"=") {
					value = strings.TrimPrefix(entry, key+"=")
				}
			}
			fmt.Fprintf(&legacy, "%s=%s\n", key, value)
		}
		if runtimeConfig(env) == digest(legacy.String()) {
			t.Fatal("historical delimiter-only guard retained reuse eligibility")
		}
	}
}

func TestRuntimeConfigValueBoundaries(t *testing.T) {
	// Quantify the delimiter-shifting collision family rather than checking
	// just one pair. Environment values exclude NUL, but may contain newlines.
	property := func(a, b, c string) bool {
		if strings.ContainsRune(a+b+c, 0) {
			return true
		}
		first := []string{"GOGC=" + a + "\nGODEBUG=" + b, "GODEBUG=" + c}
		second := []string{"GOGC=" + a, "GODEBUG=" + b + "\nGODEBUG=" + c}
		return runtimeConfig(first) != runtimeConfig(second)
	}
	if err := quick.Check(property, nil); err != nil {
		t.Fatal(err)
	}
}
