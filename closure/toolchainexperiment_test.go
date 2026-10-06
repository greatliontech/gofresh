package closure

import (
	"maps"
	"strings"
	"testing"
)

func TestAuditedExperimentRejectsUnlistedSourceChanges(t *testing.T) {
	for _, suffix := range []string{"", " race", " plan9/amd64", " cgo0"} {
		t.Run(suffix, func(t *testing.T) {
			packages := rowChain(auditedToolchainSources, "go1.27.1-X:nodwarf5"+suffix)
			if len(packages) == 0 {
				t.Fatal("audited source chain is missing")
			}
			// Labels do not grant admission: these exact bytes remain known
			// even when an otherwise identical compiler has another label.
			if d := toolchainSourceDegradation("rebuilt-toolchain", sourceDigests{Packages: packages}, nil); !d.audited() {
				t.Fatalf("audited content rejected under a different label: %s", d.notice())
			}
			for _, key := range []string{"internal/goexperiment", "runtime"} {
				changed := maps.Clone(packages)
				changed[key] = "unlisted-source-change"
				d := toolchainSourceDegradation("go1.27.1-X:nodwarf5", sourceDigests{Packages: changed}, nil)
				if d.audited() || !strings.Contains(d.notice(), key) {
					t.Fatalf("changed %s admitted or not named: %s", key, d.notice())
				}
			}
		})
	}
}
