package runtimeinput

import (
	"strings"
	"testing"
)

// Two malformed declarations refuse at ingest naming the first: the
// options apply in order and the earliest fault is the refusal.
//
//gofresh:pure
func TestIngestRefusesTheFirstMalformedDeclaration(t *testing.T) {
	_, err := FromTestLog(nil, "/tmp/m", "/tmp/m", nil, withToolchainRoot("relative/go"), WithStaticInputRoot("/abs/corpus"))
	if err == nil || !strings.Contains(err.Error(), "clean absolute path") || strings.Contains(err.Error(), "module-relative") {
		t.Fatalf("ingest refused %v; want the first declaration's fault alone", err)
	}
}
