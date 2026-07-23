package closure

import (
	"encoding/json"
	"testing"
)

// A dynamic-state fact entry serves only under its exact scope and bucket —
// the key IS the freshness (REQ-closure-dynamic-state-memo).
func TestDynamicStateFactStoreMissesOnScopeAndBucketChange(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	facts := map[string]json.RawMessage{"example.com/dep": json.RawMessage(`{"mutates":["example.com/dep.Hook"]}`)}
	StoreDynamicStateFacts("scope-a", "modpath@v1|cone", facts)

	if got := LoadDynamicStateFacts("scope-a", "modpath@v1|cone"); got == nil || string(got["example.com/dep"]) != string(facts["example.com/dep"]) {
		t.Fatalf("exact key did not serve: %v", got)
	}
	if got := LoadDynamicStateFacts("scope-b", "modpath@v1|cone"); got != nil {
		t.Fatalf("moved scope served stale facts: %v", got)
	}
	if got := LoadDynamicStateFacts("scope-a", "modpath@v2|cone"); got != nil {
		t.Fatalf("moved bucket served stale facts: %v", got)
	}
	if got := LoadDynamicStateFacts("", "modpath@v1|cone"); got != nil {
		t.Fatalf("empty scope must disable the memo, served: %v", got)
	}
}
