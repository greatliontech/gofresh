package closure

import (
	"testing"

	"github.com/greatliontech/gofresh/internal/auditset"
)

// The closure tiers' symbol predicates read the audited sets by name
// exactly as the purity tier reads them by receiver and method: one
// table each, so the two spellings cannot drift apart
// (REQ-closure-shared-dynamic-state-audited-discharges).
func TestAuditedSymbolPredicatesReadTheSharedTables(t *testing.T) {
	for _, name := range []string{"Mutex", "RWMutex", "Lock", "Unlock", "RLock", "RUnlock", "TryLock", "TryRLock", "Once", "Do", "Cond", "NewCond", "Locker", "Wait", "Signal", "Broadcast"} {
		if !auditedStandardSymbol(true, "sync", name) || !auditset.SyncName(name) {
			t.Errorf("sync name %s not admitted", name)
		}
	}
	for _, name := range []string{"Pool", "Get", "Put"} {
		if !auditedStandardSymbol(true, "sync", name) || !auditset.PoolName(name) {
			t.Errorf("pool name %s not admitted", name)
		}
	}
	for _, name := range []string{"After", "Unix", "UnixMilli", "UnixMicro", "UTC", "AddDate"} {
		if !auditset.TimeMethod("Time", name) || auditedStandardSymbol(true, "time", name) {
			t.Errorf("time method %s: want receiver-qualified admission with the bare name excluded", name)
		}
	}
	for _, name := range []string{"Int", "Intn", "Int63", "Int63n", "Float64", "Perm", "Shuffle", "Read", "Seed"} {
		if !auditset.RandMethod("Rand", name) || auditedStandardSymbol(true, "math/rand", name) {
			t.Errorf("math/rand method %s: want receiver-qualified admission with the bare name excluded", name)
		}
	}
	for _, name := range []string{"New", "NewSource", "Rand", "Source", "Source64"} {
		if !auditedStandardSymbol(true, "math/rand", name) {
			t.Errorf("math/rand symbol %s not admitted", name)
		}
	}
	if auditset.TimeMethod("Time", "Local") || auditset.TimeMethod("Time", "Location") {
		t.Error("(Time).Local or (Time).Location admitted — the ambient zone install and the pointer into package time's own state")
	}
	// fmt sits in classBPackages (the effect classifier's gate) and in
	// the symbol tables (the pure remainder); the two sets are disjoint,
	// the classifier consulted first at every site, so an overlap would
	// be a silent false refusal.
	for _, name := range []string{"Scan", "Scanf", "Scanln", "Fscan", "Fscanf", "Fscanln", "Sscan", "Sscanf", "Sscanln", "Print", "Printf", "Println", "Fprint", "Fprintf", "Fprintln"} {
		if auditset.Symbol("fmt", name) {
			t.Errorf("fmt.%s is a classified effect and an audited symbol", name)
		}
	}
	for _, name := range []string{"Type", "TypeOf", "DeepEqual", "Elem", "Kind", "NumField", "Struct", "Get"} {
		if !classBPureStandard(true, "reflect", name) || !auditset.Symbol("reflect", name) {
			t.Errorf("reflect symbol %s not admitted through the class-B ladder", name)
		}
	}
	for _, name := range []string{"Map", "Load", "Store", "LoadOrStore"} {
		if !auditedStandardSymbol(true, "sync", name) || !auditset.MemoName(name) {
			t.Errorf("memo name %s not admitted", name)
		}
	}
	for _, stray := range []string{"OnceFunc", "OnceValue", "WaitGroup", "Range", "Delete", "Swap", "New", "ValueOf", "Copy"} {
		if auditedStandardSymbol(true, "sync", stray) || classBPureStandard(true, "reflect", stray) {
			t.Errorf("%s admitted outside the tables", stray)
		}
	}
	if auditedStandardSymbol(false, "sync", "Lock") || auditedStandardSymbol(false, "sync", "Get") || classBPureStandard(false, "reflect", "TypeOf") {
		t.Fatal("an unaudited toolchain admitted an audited symbol")
	}
	if auditset.SyncName("Pool") || auditset.PoolName("Mutex") {
		t.Fatal("the sync and pool tables overlap")
	}
}
