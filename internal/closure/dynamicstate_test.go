package closure

import (
	"encoding/json"
	"testing"

	"github.com/greatliontech/gofresh/internal/cachefile"
)

// A dynamic-state fact entry serves only under its exact scope and bucket —
// the key IS the freshness (REQ-closure-dynamic-state-memo).
func TestDynamicStateFactStoreMissesOnScopeAndBucketChange(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	facts := map[string]json.RawMessage{"example.com/dep": json.RawMessage(`{"mutates":["example.com/dep.Hook"]}`)}
	cachefile.Merge("dynamicstate", "scope-a", "modpath@v1|cone", facts)

	var got map[string]json.RawMessage
	if !cachefile.Load("dynamicstate", "scope-a", "modpath@v1|cone", &got) || string(got["example.com/dep"]) != string(facts["example.com/dep"]) {
		t.Fatalf("exact key did not serve: %v", got)
	}
	got = nil
	if cachefile.Load("dynamicstate", "scope-b", "modpath@v1|cone", &got) {
		t.Fatalf("moved scope served stale facts: %v", got)
	}
	got = nil
	if cachefile.Load("dynamicstate", "scope-a", "modpath@v2|cone", &got) {
		t.Fatalf("moved bucket served stale facts: %v", got)
	}
	got = nil
	if cachefile.Load("dynamicstate", "", "modpath@v1|cone", &got) {
		t.Fatalf("empty scope must disable the memo, served: %v", got)
	}
}
