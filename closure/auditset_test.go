package closure

import (
	"testing"

	"github.com/greatliontech/gofresh/internal/auditset"
)

// The closure tiers' symbol predicates read the audited sets by name
// exactly as the purity tier reads them by receiver and method: one
// table each, so the two spellings cannot drift apart
// (REQ-closure-shared-dynamic-state's source-audit discipline).
func TestAuditedSymbolPredicatesReadTheSharedTables(t *testing.T) {
	for _, name := range []string{"Mutex", "RWMutex", "Lock", "Unlock", "RLock", "RUnlock", "TryLock", "TryRLock", "Once", "Do"} {
		if !auditedSyncSymbol(true, "sync", name) || !auditset.SyncName(name) {
			t.Errorf("sync name %s not admitted", name)
		}
	}
	for _, name := range []string{"Pool", "Get", "Put"} {
		if !auditedPoolSymbol(true, "sync", name) || !auditset.PoolName(name) {
			t.Errorf("pool name %s not admitted", name)
		}
	}
	for _, name := range []string{"Type", "TypeOf", "DeepEqual"} {
		if !auditedRuntimeTypeSymbol(true, "reflect", name) || !auditset.ReflectSymbol(name) {
			t.Errorf("reflect symbol %s not admitted", name)
		}
	}
	for _, name := range []string{"Map", "Load", "Store", "LoadOrStore"} {
		if !auditedMemoSymbol(true, "sync", name) || !auditset.MemoName(name) {
			t.Errorf("memo name %s not admitted", name)
		}
	}
	for _, stray := range []string{"OnceFunc", "OnceValue", "WaitGroup", "Range", "Delete", "Swap", "New", "ValueOf", "Copy"} {
		if auditedSyncSymbol(true, "sync", stray) || auditedPoolSymbol(true, "sync", stray) || auditedMemoSymbol(true, "sync", stray) || auditedRuntimeTypeSymbol(true, "reflect", stray) {
			t.Errorf("%s admitted outside the tables", stray)
		}
	}
	if auditedSyncSymbol(false, "sync", "Lock") || auditedPoolSymbol(false, "sync", "Get") || auditedRuntimeTypeSymbol(false, "reflect", "TypeOf") {
		t.Fatal("an unaudited toolchain admitted an audited symbol")
	}
	if auditset.SyncName("Pool") || auditset.PoolName("Mutex") {
		t.Fatal("the sync and pool tables overlap")
	}
}
