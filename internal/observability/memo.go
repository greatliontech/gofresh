package observability

import (
	"github.com/greatliontech/gofresh/internal/cachefile"
	"github.com/greatliontech/gofresh/internal/closure"
)

const (
	observabilityDirName = "observability"
	rootedDirName        = "rooted"
	binaryRootedDirName  = "binaryrooted"
)

func loadMemo(scope, closureKey string) map[string]Observability {
	var proofs map[string]Observability
	if !cachefile.Load(observabilityDirName, scope, closureKey, &proofs) {
		closure.EmitMemoLoadTrace(observabilityDirName, closureKey, false, 0)
		return nil
	}
	closure.EmitMemoLoadTrace(observabilityDirName, closureKey, true, len(proofs))
	return proofs
}

func storeMemo(scope, closureKey string, proofs map[string]Observability) {
	cachefile.Merge(observabilityDirName, scope, closureKey, proofs)
	closure.EmitMemoStoreTrace(observabilityDirName, closureKey, len(proofs))
}

func (p *Prover) groupMemo(pkgPath string) (closureHash string, proofs map[string]Observability) {
	if p == nil || p.Hasher == nil {
		return "", nil
	}
	scope := p.Hasher.Scope().Proofs()
	if scope == "" {
		return "", nil
	}
	key, err := p.Hasher.PackageScanKey(pkgPath)
	if err != nil {
		return "", nil
	}
	return key, loadMemo(scope, key)
}

func loadRootedMemo(scope, closureKey string) map[string]RootedFunctions {
	var inventories map[string]RootedFunctions
	if !cachefile.Load(rootedDirName, scope, closureKey, &inventories) {
		closure.EmitMemoLoadTrace(rootedDirName, closureKey, false, 0)
		return nil
	}
	for k, inv := range inventories {
		if inv.Complete && inv.Fns == nil {
			inv.Fns = map[string]bool{}
			inventories[k] = inv
		}
	}
	closure.EmitMemoLoadTrace(rootedDirName, closureKey, true, len(inventories))
	return inventories
}

func storeRootedMemo(scope, closureKey string, inventories map[string]RootedFunctions) {
	cachefile.Merge(rootedDirName, scope, closureKey, inventories)
	closure.EmitMemoStoreTrace(rootedDirName, closureKey, len(inventories))
}

func (p *Prover) rootedGroupMemo(pkgPath string) (closureHash string, inventories map[string]RootedFunctions) {
	if p == nil || p.Hasher == nil {
		return "", nil
	}
	scope := p.Hasher.Scope().Rooted()
	if scope == "" {
		return "", nil
	}
	key, err := p.Hasher.PackageScanKey(pkgPath)
	if err != nil {
		return "", nil
	}
	return key, loadRootedMemo(scope, key)
}

func loadBinaryRootedMemo(scope, closureKey string) (RootedFunctions, bool) {
	var inventory RootedFunctions
	if !cachefile.Load(binaryRootedDirName, scope, closureKey, &inventory) {
		closure.EmitMemoLoadTrace(binaryRootedDirName, closureKey, false, 0)
		return RootedFunctions{}, false
	}
	if inventory.Complete && inventory.Fns == nil {
		inventory.Fns = map[string]bool{}
	}
	closure.EmitMemoLoadTrace(binaryRootedDirName, closureKey, true, len(inventory.Fns))
	return inventory, true
}

func storeBinaryRootedMemo(scope, closureKey string, inventory RootedFunctions) {
	cachefile.Store(binaryRootedDirName, scope, closureKey, inventory)
	closure.EmitMemoStoreTrace(binaryRootedDirName, closureKey, len(inventory.Fns))
}

func (p *Prover) binaryRootedMemo(pkgPath string) (closureHash string, inventory RootedFunctions, ok bool) {
	if p == nil || p.Hasher == nil {
		return "", RootedFunctions{}, false
	}
	scope := p.Hasher.Scope().Rooted()
	if scope == "" {
		return "", RootedFunctions{}, false
	}
	key, err := p.Hasher.PackageScanKey(pkgPath)
	if err != nil {
		return "", RootedFunctions{}, false
	}
	inv, ok := loadBinaryRootedMemo(scope, key)
	return key, inv, ok
}
