package gofresh

import (
	"go/token"
	"go/types"
	"runtime"
	"testing"
	_ "unsafe" // for go:linkname
)

// The purity tier's audited admissions answer from the same
// exact-version key as the closure tier's; this poke reaches the one
// list through its package (the fork's test-linkname idiom).
//
//go:linkname closureAuditedToolchainReleases github.com/greatliontech/gofresh/closure.auditedToolchainReleases
var closureAuditedToolchainReleases map[string]bool

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
	if !auditedSynchronization(lock) || !auditedPooling(get) || !auditedImmutableType(reflType) {
		t.Fatal("fakes not admitted on the audited toolchain; the poke below would be vacuous")
	}
	v := runtime.Version()
	if !closureAuditedToolchainReleases[v] {
		t.Fatalf("running toolchain %q unlisted; the closure-tier canary owns this failure", v)
	}
	closureAuditedToolchainReleases[v] = false
	defer func() { closureAuditedToolchainReleases[v] = true }()
	if auditedSynchronization(lock) {
		t.Error("auditedSynchronization admits sync.Mutex.Lock on an unaudited toolchain")
	}
	if auditedPooling(get) {
		t.Error("auditedPooling admits sync.Pool.Get on an unaudited toolchain")
	}
	if auditedImmutableType(reflType) {
		t.Error("auditedImmutableType admits reflect.Type on an unaudited toolchain")
	}
}
