package gofresh

import (
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestUnscopedFactsNeverUseTheProcessCache(t *testing.T) {
	if testing.Short() {
		t.Skip("loads pinned facts under complete and absent scopes")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writePinnedDepModule(t)
	processFactCache = sync.Map{}
	t.Cleanup(func() { processFactCache = sync.Map{} })
	old := viewTestHooks.dynamicStateMissLoad
	loads := 0
	viewTestHooks.dynamicStateMissLoad = func([]string) { loads++ }
	t.Cleanup(func() { viewTestHooks.dynamicStateMissLoad = old })
	const pkg = "example.com/pinned"
	clean := runScan(t, "complete", dir, pkg)
	if loads != 1 {
		t.Fatalf("cold loads=%d", loads)
	}
	if warm := runScan(t, "complete", dir, pkg); loads != 1 || !reflect.DeepEqual(warm, clean) {
		t.Fatal("complete scope did not serve")
	}
	var key string
	var poison dynamicStateFact
	processFactCache.Range(func(k, v any) bool {
		if strings.HasSuffix(k.(string), "\x00golang.org/x/sync/errgroup") {
			key = k.(string)[strings.IndexByte(k.(string), 0):]
			poison = v.(dynamicStateFact)
			poison.Declares = append(poison.Declares, "golang.org/x/sync/errgroup.Ghost")
			poison.Mutates = append(poison.Mutates, "golang.org/x/sync/errgroup.Ghost")
		}
		return true
	})
	if key == "" {
		t.Fatal("no pinned fact control")
	}
	processFactCache = sync.Map{}
	processFactCache.Store(key, poison)
	for i := 0; i < 2; i++ {
		got := runScan(t, "", dir, pkg)
		if loads != 2+i || !reflect.DeepEqual(got, clean) {
			t.Errorf("unscoped scan served cached facts: loads=%d result=%+v", loads, got)
		}
		stored, ok := processFactCache.Load(key)
		if !ok || !reflect.DeepEqual(stored, poison) {
			t.Error("unscoped scan wrote process facts")
		}
	}
}
