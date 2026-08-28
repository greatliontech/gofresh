package gofresh

import (
	"go/token"
	"go/types"
	"testing"
)

// TestUnauditedToolchainDropsPurityAdmissions pins the purity tier's
// half of the exact-version keying: on an unlisted release the audited
// synchronization, pooling, and immutable-type admissions all keep
// their fail-closed classifications
// (REQ-closure-observability-analysis's exact-version keying clause).
func TestUnauditedToolchainDropsPurityAdmissions(t *testing.T) {
	syncPkg := types.NewPackage("sync", "sync")
	method := func(recvType string, name string) *types.Func {
		named := types.NewNamed(types.NewTypeName(token.NoPos, syncPkg, recvType, nil), types.NewStruct(nil, nil), nil)
		recv := types.NewVar(token.NoPos, syncPkg, "m", types.NewPointer(named))
		sig := types.NewSignatureType(recv, nil, nil, nil, nil, false)
		return types.NewFunc(token.NoPos, syncPkg, name, sig)
	}
	lock := method("Mutex", "Lock")
	get := method("Pool", "Get")
	reflectPkg := types.NewPackage("reflect", "reflect")
	reflType := types.NewNamed(types.NewTypeName(token.NoPos, reflectPkg, "Type", nil), types.NewInterfaceType(nil, nil), nil)
	// The vacuity guard: under an audited verdict the fakes admit, so
	// the refusals below witness the verdict parameter, not a
	// malformed fake. The verdict is the two-axis
	// AuditedToolchainSelection value the scan entries compute once —
	// an unlisted release or unaudited selection reaches every
	// admission as false.
	if !auditedSynchronization(true, lock) || !auditedPooling(true, get) || !auditedImmutableType(true, reflType) {
		t.Fatal("fakes not admitted under an audited verdict; the refusal arms below would be vacuous")
	}
	if auditedSynchronization(false, lock) {
		t.Error("auditedSynchronization admits sync.Mutex.Lock on an unaudited toolchain")
	}
	if auditedPooling(false, get) {
		t.Error("auditedPooling admits sync.Pool.Get on an unaudited toolchain")
	}
	if auditedImmutableType(false, reflType) {
		t.Error("auditedImmutableType admits reflect.Type on an unaudited toolchain")
	}
}
