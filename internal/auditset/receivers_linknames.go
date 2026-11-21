package auditset

import (
	"go/types"
	"maps"
	"slices"
	"strings"
)

// syncMethods is the audited synchronization set: sync's mutex
// receivers and the lock-shaped methods on them, and Once's Do — a
// done flag under a mutex running the caller's own function exactly
// once, program code judged where it is written; the Once's state
// cannot change dispatch. Grows only by source audit
// (REQ-closure-shared-dynamic-state-audited-discharges).
var syncMethods = map[string][]string{
	"Cond":    {"Broadcast", "Signal", "Wait"},
	"Mutex":   {"Lock", "Unlock", "TryLock"},
	"RWMutex": {"Lock", "Unlock", "RLock", "RUnlock", "TryLock", "TryRLock"},
	"Once":    {"Do"},
}

var syncSymbols = map[string]bool{
	"Locker":  true,
	"NewCond": true,
}

// memoMethods is the audited memo set: sync.Map with its Load, Store,
// and LoadOrStore operations — process-memory reads and writes fed by
// the analyzed program alone, admitted at the effect classification
// tiers; the shared-dynamic-state discharge is the data memo's content
// judgment, never this set's. Grows only by source audit
// (REQ-closure-shared-dynamic-state-memo).
var memoMethods = map[string][]string{
	"Map": {"Load", "Store", "LoadOrStore"},
}

// poolMethods is the audited pooling set: sync.Pool and its Get and
// Put operations (REQ-closure-shared-dynamic-state-pool).
var poolMethods = map[string][]string{
	"Pool": {"Get", "Put"},
}

// reflectMethods is the audited receiver-qualified surface of package
// reflect: (Type).Key — the map descriptor's key-type read, a panic on
// any other kind — whose bare name (*MapIter).Key shares with a read of live map
// iteration state, so the name admits only where the walk sees the
// canonical descriptor's own receiver (the unexported rtype).
// Consulted by the walk tiers alone (REQ-closure-observability-reflect-exclusion).
var reflectMethods = map[string][]string{
	"rtype": {"Key"},
}

// reflectImmutableTypes is the audited set of reflect types whose
// values are immutable once produced AND whose interface is sealed by
// unexported methods, so every referent is the runtime's canonical
// descriptor: the effect tiers' immutability ruling and the
// object-closed store rule read one table, and a member must meet
// both bars.
var reflectImmutableTypes = map[string]bool{"Type": true}

// constantImmutableTypes is the audited set of go/constant types whose
// values are immutable once produced AND whose interface is sealed by
// unexported methods (implementsValue).
var constantImmutableTypes = map[string]bool{"Value": true}

// The name unions the closure tiers' symbol predicates read, computed
// once from the tables.
var (
	syncNames = namesWithSymbols(syncMethods, syncSymbols)
	poolNames = names(poolMethods)
	memoNames = names(memoMethods)
)

// receiverTables maps each standard package with receiver-qualified method
// admissions to its method tables. ReceiverPackages and Identity both derive
// from this map so adding a receiver table updates both automatically.
var receiverTables = map[string][]map[string][]string{
	"go/ast":        {goASTMethods},
	"math/rand":     {randMethods},
	"reflect":       {reflectMethods},
	"runtime/debug": {runtimeDebugMethods},
	"sync":          {syncMethods, poolMethods, memoMethods},
	"sync/atomic":   {atomicMethods},
	"time":          {timeMethods},
}

// ReceiverPackages lists the packages whose receiver tables this set
// carries — sync's synchronization, pool and memo methods, reflect's
// view surface, time's receiver-qualified names — sorted; the
// toolchain-source audit's key walks it beside the symbol tables.
func ReceiverPackages() []string {
	keys := make([]string, 0, len(receiverTables))
	for k := range receiverTables {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// timeMethods is the audited receiver-qualified surface of package
// time: the pure methods of Time whose bare names timeSymbols must
// exclude for the ambient declaration sharing each — After (a
// comparison), Unix, UnixMilli, and UnixMicro (epoch arithmetic), UTC
// (installs the unexported UTC location, never the exported
// variable), and AddDate (re-enters Date through the receiver's
// location). An admitted method reads neither the clock, the local
// zone, nor a variable program code can reach, and hands out no
// pointer into package time's own state: Local is absent (it installs
// the ambient Local zone), and Location is absent (for a location-less
// Time it returns the exported UTC variable's value, the address of
// the package's own utcLoc, through which program code could write
// with no tier seeing the store). AddDate's own Location call is
// standard-internal and reads the exported variable, which holds the
// runtime's constant in every admitted program: only program code
// spelling time.UTC can assign it, and that spelling refuses at the
// fold in every compiled Go and cgo file of the closure. Gated on
// structural toolchain-source verification and consulted by the walk
// tiers alone — the fold sees no method call
// (REQ-closure-observability-audited-set).
var timeMethods = map[string][]string{
	"Time": {"After", "Unix", "UnixMilli", "UnixMicro", "UTC", "AddDate"},
}

// randMethods is the audited receiver-qualified surface of package
// math/rand: the integer and IEEE-754 float sampling methods on *Rand
// and *rngSource whose implementations in math/rand/{rand,rng}.go use
// pure integer arithmetic and float division over the receiver's own
// state, never touching globalRand or package math's transcendental
// operations (ExpFloat64 and NormFloat64 are excluded). Consulted by
// the walk tiers alone (REQ-closure-observability-entropy).
var randMethods = map[string][]string{
	"Rand": {
		"Float32", "Float64",
		"Int", "Int31", "Int31n", "Int63", "Int63n", "Intn",
		"Perm", "Read", "Seed", "Shuffle",
		"Uint32", "Uint64",
	},
	"rngSource": {
		"Int63", "Seed", "Uint64",
	},
}

// atomicMethods is the audited receiver-qualified method surface of package
// sync/atomic on scalar atomic types.
var atomicMethods = map[string][]string{
	"Bool":    {"CompareAndSwap", "Load", "Store", "Swap"},
	"Int32":   {"Add", "And", "CompareAndSwap", "Load", "Or", "Store", "Swap"},
	"Int64":   {"Add", "And", "CompareAndSwap", "Load", "Or", "Store", "Swap"},
	"Uint32":  {"Add", "And", "CompareAndSwap", "Load", "Or", "Store", "Swap"},
	"Uint64":  {"Add", "And", "CompareAndSwap", "Load", "Or", "Store", "Swap"},
	"Uintptr": {"Add", "And", "CompareAndSwap", "Load", "Or", "Store", "Swap"},
}

// PackageMethodAndReceiverNames returns the sorted union of receiver and
// method names registered in receiverTables for pkgPath.
func PackageMethodAndReceiverNames(pkgPath string) []string {
	tables := receiverTables[pkgPath]
	if len(tables) == 0 {
		return nil
	}
	var out []string
	for _, table := range tables {
		for recv, methods := range table {
			out = append(out, recv)
			out = append(out, methods...)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// SyncMethod reports whether a sync receiver's method is in the
// audited synchronization set.
func SyncMethod(receiver, method string) bool { return slices.Contains(syncMethods[receiver], method) }

// PoolMethod reports whether a sync receiver's method is in the
// audited pooling set.
func PoolMethod(receiver, method string) bool { return slices.Contains(poolMethods[receiver], method) }

// TimeMethod reports whether a time receiver's method is in the
// audited receiver-qualified set.
func TimeMethod(receiver, method string) bool { return slices.Contains(timeMethods[receiver], method) }

// ReflectMethod reports whether a reflect receiver's method is in the
// audited receiver-qualified set.
func ReflectMethod(receiver, method string) bool {
	return slices.Contains(reflectMethods[receiver], method)
}

// RandMethod reports whether a math/rand receiver's method is in the
// audited receiver-qualified set.
func RandMethod(receiver, method string) bool {
	return slices.Contains(randMethods[receiver], method)
}

// AtomicMethod reports whether a sync/atomic receiver's method is in the
// audited receiver-qualified scalar atomic set.
func AtomicMethod(receiver, method string) bool {
	return slices.Contains(atomicMethods[receiver], method)
}

// ReceiverMethod is the one receiver-unwrap ladder every
// receiver-qualified standard admission shares: a method declared in
// the named standard package on a named receiver (pointer or value)
// whose receiver and name the listed set carries. The purity tier's
// sync admissions and the walk tiers' time admissions read it alike;
// a nil or receiver-less function is never listed.
func ReceiverMethod(fn *types.Func, pkgPath string, listed func(receiver, method string) bool) bool {
	if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != pkgPath {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	t := types.Unalias(sig.Recv().Type())
	if pointer, ok := t.(*types.Pointer); ok {
		t = types.Unalias(pointer.Elem())
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj() == nil {
		return false
	}
	return listed(named.Obj().Name(), fn.Name())
}

// SyncName reports whether a sync symbol name — receiver, method, constructor,
// or interface — belongs to the audited synchronization set.
func SyncName(name string) bool { return slices.Contains(syncNames, name) }

// PoolName reports whether a sync symbol name — receiver or method —
// belongs to the audited pooling set.
func PoolName(name string) bool { return slices.Contains(poolNames, name) }

// MemoMethod reports whether a sync receiver method is in the audited
// memo set — sync.Map's Load, Store, and LoadOrStore.
func MemoMethod(receiver, method string) bool { return slices.Contains(memoMethods[receiver], method) }

// MemoName reports whether a sync symbol name — receiver or method —
// belongs to the audited memo set.
func MemoName(name string) bool { return slices.Contains(memoNames, name) }

// SyncSurfaceName reports whether a sync symbol name — receiver or method —
// belongs to any of the audited sync sets (synchronization, pooling, or memo).
func SyncSurfaceName(name string) bool {
	return SyncName(name) || PoolName(name) || MemoName(name)
}

// SyncTopLevelSymbols returns the sorted package-scope type, interface, and
// constructor names in package sync across the audited synchronization,
// pooling, and memo sets.
func SyncTopLevelSymbols() []string {
	var out []string
	for _, table := range []map[string][]string{syncMethods, poolMethods, memoMethods} {
		for recv := range table {
			out = append(out, recv)
		}
	}
	for sym := range syncSymbols {
		out = append(out, sym)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// ReflectImmutable reports whether a reflect type is in the audited
// immutable-type set.
func ReflectImmutable(name string) bool { return reflectImmutableTypes[name] }

// ConstantImmutable reports whether a go/constant type is in the audited
// immutable-type set.
func ConstantImmutable(name string) bool { return constantImmutableTypes[name] }

// auditedLinknameTargets is the audited linkname-target set: standard
// symbols whose pull-style linkname is a read-only trampoline, each
// audited at the source of its version-pinned importer
// (golang.org/x/sys/unix on linux) — runtime.getAuxv (a read-only
// accessor of the runtime's startup-captured auxiliary vector),
// runtime.vgetrandom (the kernel entropy read the Getrandom surface
// already classifies), and syscall.prlimit (a standard syscall the
// calling surface's own syscall classifications already carry). The
// trampoline adds no effect its file's remaining classifications do
// not price, so an audited-only linkname file drops exactly the
// OPAQUE-linkage effect and keeps every other effect it carries —
// REQ-closure-blindspot's "resolved" disposition applied at the
// tier-1 floor, per target and by source audit only.
var auditedLinknameTargets = map[string]bool{
	"runtime.getAuxv":    true,
	"runtime.vgetrandom": true,
	"syscall.prlimit":    true,
}

// AuditedLinknameTarget reports whether target is in the audited
// pull-style linkname-target set.
func AuditedLinknameTarget(target string) bool { return auditedLinknameTargets[target] }

// AuditedLinknameTargets returns the sorted audited linkname targets.
func AuditedLinknameTargets() []string { return slices.Sorted(maps.Keys(auditedLinknameTargets)) }

// auditedReadOnlyVarLinknameTargets maps runtime startup-constant scalar
// variables to their exact underlying Go BasicKind so two-argument pull-form
// //go:linkname bindings cannot widen layout or reinterpret scalars as string
// or pointer headers, and are admitted at Tier-2 observability only when the
// local variable (and every peer bound to the same target in the program) has
// no initializer, no stores, no address escapes, and no non-SSA native hazards
// in its declaring package.
var auditedReadOnlyVarLinknameTargets = map[string]types.BasicKind{
	"internal/cpu.HWCap": types.Uint,
}

// AuditedReadOnlyVarLinknameTarget reports whether target is an audited
// startup-constant scalar linkname target and returns its required BasicKind.
func AuditedReadOnlyVarLinknameTarget(target string) (types.BasicKind, bool) {
	k, ok := auditedReadOnlyVarLinknameTargets[target]
	return k, ok
}

// AuditedReadOnlyVarLinknameTargets returns a copy of the audited
// startup-constant scalar linkname targets and their required BasicKinds.
func AuditedReadOnlyVarLinknameTargets() map[string]types.BasicKind {
	return maps.Clone(auditedReadOnlyVarLinknameTargets)
}

// classBPackages is the set of effect-bearing packages with declarative Class-B
// operation entries, shared between the effect classifier, the maximal tier's
// dot-import backstop, and toolchain pure-delegate verification
// (REQ-closure-observability-audited-set).
var classBPackages = map[string]bool{
	"crypto/rand":           true,
	"fmt":                   true,
	"golang.org/x/sys/unix": true,
	"html/template":         true,
	"net":                   true,
	"net/http":              true,
	"os":                    true,
	"plugin":                true,
	"syscall":               true,
	"testing":               true,
	"text/template":         true,
}

// ClassBPackage reports whether pkgPath has declarative Class-B external-effect
// operation entries.
func ClassBPackage(pkgPath string) bool { return classBPackages[pkgPath] }

// ClassBPackages returns the sorted package paths in the Class-B package set.
func ClassBPackages() []string { return slices.Sorted(maps.Keys(classBPackages)) }

// NetworkPackage is the one spelling of the net tree's network-I/O
// classification: net and every package beneath it except net/url —
// value computation with no socket, admitted by symbol
// (REQ-closure-observability-audited-set).
func NetworkPackage(pkgPath string) bool {
	return pkgPath == "net" || (strings.HasPrefix(pkgPath, "net/") && pkgPath != "net/url")
}

// AlwaysExternalPackage reports whether pkgPath is an always-external package
// (plugin, syscall, golang.org/x/sys/..., or a network-I/O package).
func AlwaysExternalPackage(pkgPath string) bool {
	return pkgPath == "plugin" || pkgPath == "syscall" ||
		strings.HasPrefix(pkgPath, "golang.org/x/sys/") || NetworkPackage(pkgPath)
}

// names is the union of a method set's receiver and method names.
func names(set map[string][]string) []string {
	return namesWithSymbols(set, nil)
}

// namesWithSymbols is the union of a method set's receiver and method names
// with any bare symbol names in symbols.
func namesWithSymbols(set map[string][]string, symbols map[string]bool) []string {
	var out []string
	for receiver, methods := range set {
		out = append(out, receiver)
		out = append(out, methods...)
	}
	for symbol := range symbols {
		out = append(out, symbol)
	}
	slices.Sort(out)
	return slices.Compact(out)
}
