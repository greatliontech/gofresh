package closure

import (
	"go/constant"
	"go/token"
	"go/types"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// This is the complete selected source entry-to-operand prefix. The selected
// bodyless operation remains unexecuted; its narrow assembly relation, later
// float views and source loop require their own checked continuations.
func TestStoragePrefixSelectedRuntimeSource(t *testing.T) {
	if testing.Short() {
		t.Skip("loads selected compiler source for the complete entry-to-operand prefix")
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/localprefix\n\ngo 1.27\n"})
	source, _, _ := loadSourceCommandFixture(t, dir, "cmd/compile")
	var root, target *ssa.Function
	for _, pkg := range source.prog.Pkgs {
		switch pkg.PkgPath {
		case "runtime":
			root = source.prog.Prog.Package(pkg.Types).Func("check")
		case "internal/runtime/atomic":
			target = source.prog.Prog.Package(pkg.Types).Func("Cas")
		}
	}
	if root == nil || target == nil {
		t.Fatal("selected source candidates are absent")
	}
	var call *ssa.Call
	for _, block := range root.Blocks {
		for _, instruction := range block.Instrs {
			candidate, ok := instruction.(*ssa.Call)
			if ok && candidate.Call.StaticCallee() == target && (call == nil || candidate.Pos() < call.Pos()) {
				call = candidate
			}
		}
	}
	if call == nil {
		t.Fatal("selected narrow operand boundary is absent")
	}
	// Bind the complete selected runtime inventory under the same explicit bound
	// used by compiler-source fixtures; retain the ordinary region-proof limits.
	limits := defaultRegistrationLimits()
	limits.source.work, limits.source.bytes = 16<<20, 512<<20
	prefix, err := checkSourceOperandPrefix(t.Context(), source, root, call, limits)
	if err != nil {
		t.Fatal(err)
	}
	packet := prefix.region.packet
	if packet.input.root != root || packet.input.entry != (regionPoint{block: root.Blocks[0]}) || packet.input.owner != source.prog.Prog || prefix.call != call || len(packet.observations) != 1 || len(prefix.operands) != 3 || len(packet.input.initial.values) != 0 || len(packet.input.initial.memory) != 0 {
		t.Fatal("source prefix discarded entry coverage or introduced a specialized initial heap")
	}
	pointer := prefix.operands[0]
	allocation, ok := pointer.location.object.site.(*ssa.Alloc)
	if !ok || pointer.kind != regionPointer || pointer.location.object.kind != regionAllocation || allocation.Parent() != root || pointer.location.object.context != root || len(pointer.location.path) != 0 || !types.Identical(pointer.typ, types.NewPointer(types.Typ[types.Uint32])) {
		t.Fatal("first operand lacks its actual local uint32 allocation identity")
	}
	for index, want := range []uint64{1, 2} {
		value := prefix.operands[index+1]
		if value.kind != regionConstant || value.scalar == nil {
			t.Fatalf("operand %d lacks a checked constant", index+1)
		}
		actual, exact := constant.Uint64Val(value.scalar)
		if value.kind != regionConstant || !types.Identical(value.typ, types.Typ[types.Uint32]) || !exact || actual != want {
			t.Fatalf("operand %d is not the checked source value %d", index+1, want)
		}
	}
	current := readRegionLocation(packet.observations[0].state, pointer.location, types.Typ[types.Uint32])
	if current.kind != regionConstant || current.scalar == nil || !constant.Compare(current.scalar, token.EQL, constant.MakeUint64(1)) {
		t.Fatal("local allocation did not retain the actual initializing store")
	}
	t.Logf("complete selected entry %s to unexecuted %s; local allocation %s", root, target, allocation)
}
