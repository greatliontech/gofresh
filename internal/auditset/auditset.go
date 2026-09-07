// Package auditset holds the one shape every source-audited admission
// answers from — a listing consulted by a lookup that refuses whatever
// it does not name — and the audited sets whose contents two tiers
// read: the closure tiers by symbol name, the purity tier by receiver
// and method. One table per set, so the two tiers cannot drift apart
// one arm at a time, and one listing shape per version domain, so
// "listed or refused" is written once (the audit-key consolidation).
// The sets are package-private and read through predicates: an
// audited set grows only by source audit — by editing this file —
// never by a write at runtime.
package auditset

import (
	"slices"
	"strings"
)

// VersionListing is a source audit's record: each key (a toolchain
// release, a module variable, a harness package) names the versions
// whose source the audit walked. Nothing outside the listing is ever
// admitted — a version later or earlier than the listed ones refuses
// fail-closed until its source is audited.
type VersionListing map[string][]string

// Listed reports whether the key's listing names the version.
func (l VersionListing) Listed(key, version string) bool {
	return slices.Contains(l[key], version)
}

// syncMethods is the audited synchronization set: sync's mutex
// receivers and the lock-shaped methods on them. Grows only by source
// audit (REQ-closure-shared-dynamic-state).
var syncMethods = map[string][]string{
	"Mutex":   {"Lock", "Unlock", "TryLock"},
	"RWMutex": {"Lock", "Unlock", "RLock", "RUnlock", "TryLock", "TryRLock"},
}

// poolMethods is the audited pooling set: sync.Pool and its Get and
// Put operations (REQ-closure-shared-dynamic-state).
var poolMethods = map[string][]string{
	"Pool": {"Get", "Put"},
}

// reflectSymbols is the audited reflect surface the closure tiers
// admit by symbol: the type-identity operations that read no dynamic
// state (REQ-closure-shared-dynamic-state).
var reflectSymbols = []string{"Type", "TypeOf", "DeepEqual"}

// reflectImmutableTypes is the audited set of reflect types whose
// values are immutable once produced.
var reflectImmutableTypes = []string{"Type"}

// The name unions the closure tiers' symbol predicates read, computed
// once from the tables.
var (
	syncNames = names(syncMethods)
	poolNames = names(poolMethods)
)

// SyncMethod reports whether a sync receiver's method is in the
// audited synchronization set.
func SyncMethod(receiver, method string) bool { return slices.Contains(syncMethods[receiver], method) }

// PoolMethod reports whether a sync receiver's method is in the
// audited pooling set.
func PoolMethod(receiver, method string) bool { return slices.Contains(poolMethods[receiver], method) }

// SyncName reports whether a sync symbol name — receiver or method —
// belongs to the audited synchronization set.
func SyncName(name string) bool { return slices.Contains(syncNames, name) }

// PoolName reports whether a sync symbol name — receiver or method —
// belongs to the audited pooling set.
func PoolName(name string) bool { return slices.Contains(poolNames, name) }

// ReflectSymbol reports whether a reflect symbol is in the audited
// type-identity surface.
func ReflectSymbol(name string) bool { return slices.Contains(reflectSymbols, name) }

// ReflectImmutable reports whether a reflect type is in the audited
// immutable-type set.
func ReflectImmutable(name string) bool { return slices.Contains(reflectImmutableTypes, name) }

// names is the union of a method set's receiver and method names.
func names(set map[string][]string) []string {
	var out []string
	for receiver, methods := range set {
		out = append(out, receiver)
		out = append(out, methods...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// BoundedToken reports whether text begins with marker as a whole token
// — marker followed by end of text or by one of the bound bytes — and
// returns the remainder after the marker. A directive or generator name
// matched this way can never be shadowed by a longer name sharing its
// prefix; each caller names the bounds its grammar allows (space or
// tab for a directive, space, tab, or a period for a generator header).
func BoundedToken(text, marker, bounds string) (rest string, ok bool) {
	if !strings.HasPrefix(text, marker) {
		return "", false
	}
	rest = text[len(marker):]
	if rest == "" || strings.IndexByte(bounds, rest[0]) >= 0 {
		return rest, true
	}
	return "", false
}
