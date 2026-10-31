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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/types"
	"slices"
	"sort"
	"strings"
)

// Identity binds the immutable admission inventories. Algorithm changes still
// carry the consuming derivation's version; changing table data keys itself.
func Identity() string {
	methods := func(table map[string][]string) map[string][]string {
		result := make(map[string][]string, len(table))
		for receiver, names := range table {
			ordered := slices.Clone(names)
			slices.Sort(ordered)
			result[receiver] = slices.Compact(ordered)
		}
		return result
	}
	data, _ := json.Marshal([]any{purePackages, symbolTables, methods(syncMethods), syncSymbols,
		methods(poolMethods), methods(memoMethods), methods(timeMethods), methods(reflectMethods), methods(randMethods), methods(atomicMethods),
		methods(standardSentinelGlobals), reflectImmutableTypes, constantImmutableTypes})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

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

// reflectSymbols is the audited surface of package reflect, matched by
// bare name at every tier like its peers: the runtime-type set (Type,
// TypeOf — bit-deterministic over the operand's static type — and the
// structural comparator DeepEqual, which calls no method and compares
// function values by nil-ness alone); the descriptor-view surface of
// Type, every member a read of the runtime's canonical descriptor or
// a pure judgment over two of them, panicking on a wrong kind and
// invoking nothing (FieldByNameFunc's callback is resolved by the
// enumeration at reflect's own match site — a function constant is
// scanned as an operand besides — so its body is classified either
// way); the Kind and ChanDir constants and the
// StructField and StructTag shapes with Get and Lookup, execution-free
// references or string parsing; and the Elem accessors — (Type).Elem
// the descriptor read, (Value).Elem the operand-pinned dereference.
// The bare-name match admits every same-named declaration, so each is
// audited: the Value members sharing a listed name (Kind, String,
// Len, NumField, Field, FieldByIndex, FieldByName, FieldByNameFunc,
// NumMethod, Comparable, the Overflow queries, Bool, Int, Uint, Type,
// Elem) read the type or the memory their operand pins
// — an addressable result's write channel is the Set family, refused
// — and every Value is reached only behind a producer's own refusal;
// Kind's and ChanDir's String format their constant; the unexported
// interfaceType and structType forms are the descriptor reads the
// exported ones delegate to. Key is absent: (*MapIter).Key shares the
// name and reads live iteration state, so (Type).Key admits through
// the receiver-qualified table reflectMethods instead. Chained
// selectors off an admitted result are separate callees with their
// own classifications at the walk tiers (a field's Tag.Get is judged
// as StructTag's Get), and the fold never sees them either way;
// reflect dispatch still defeats static reachability everywhere
// else. Refused by name: Method and MethodByName (they build callable
// Values — the reflective-dispatch channel, with the Call family and
// MakeFunc), the producers (ValueOf, New, Zero, Indirect, the Make
// and Of constructors), the address results (Pointer, UnsafePointer —
// and so those two Kind constants and the deprecated Ptr), and the
// hand-out (Interface, Slice). An admitted member hands out no pointer
// into the package's own state: descriptors are sealed and never
// written after construction. The admission is gated on the structural
// toolchain-source verification (REQ-closure-observability-reflect-exclusion).
var reflectSymbols = map[string]bool{
	// the runtime-type set
	"Type": true, "TypeOf": true, "DeepEqual": true, "Elem": true,
	// the descriptor-view surface of Type
	"Kind": true, "Name": true, "String": true, "PkgPath": true, "Size": true, "Align": true, "FieldAlign": true, "Bits": true,
	"NumField": true, "Field": true, "FieldByIndex": true, "FieldByName": true, "FieldByNameFunc": true, "NumMethod": true,
	"Len": true, "NumIn": true, "NumOut": true, "In": true, "Out": true, "IsVariadic": true, "ChanDir": true,
	"Comparable": true, "Implements": true, "AssignableTo": true, "ConvertibleTo": true, "CanSeq": true, "CanSeq2": true,
	"OverflowInt": true, "OverflowUint": true, "OverflowFloat": true, "OverflowComplex": true,
	// the shapes and their string parsing
	"StructField": true, "StructTag": true, "Get": true, "Lookup": true,
	// the Kind constants whose same-named Value members read pinned memory
	"Invalid": true, "Bool": true, "Int": true, "Int8": true, "Int16": true, "Int32": true, "Int64": true,
	"Uint": true, "Uint8": true, "Uint16": true, "Uint32": true, "Uint64": true, "Uintptr": true,
	"Float32": true, "Float64": true, "Complex64": true, "Complex128": true,
	"Array": true, "Chan": true, "Func": true, "Map": true, "Struct": true,
	// the ChanDir constants
	"RecvDir": true, "SendDir": true, "BothDir": true,
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

// fmtSymbols is the audited surface of package fmt: the Sprint and
// Append families and Errorf — value-to-value formatting whose
// arguments' methods stay visible to reachability — and the Stringer
// name; the Print family is classified output and the Scan family
// input, so only the pure remainder is here
// (REQ-closure-observability-audited-set).
var fmtSymbols = map[string]bool{
	"Sprint": true, "Sprintf": true, "Sprintln": true, "Errorf": true,
	"Append": true, "Appendf": true, "Appendln": true, "FormatString": true, "Stringer": true,
}

// The name unions the closure tiers' symbol predicates read, computed
// once from the tables.
var (
	syncNames = namesWithSymbols(syncMethods, syncSymbols)
	poolNames = names(poolMethods)
	memoNames = names(memoMethods)
)

// purePackages is the audited-pure standard package set: packages that
// are bit-deterministic pure computation for every consumer of the
// audit — every ambient effect enters via a flagged constructor or
// global of an effect-bearing package, no testlog-invisible input
// channel, no machine-variant results. The exclusion rationale per
// family lives with the closure tier's consumer (isSourceOnlyStandardPackage).
// Grows only by source audit, each admission with its own record in
// the commit that lists it (REQ-closure-observability-audited-set).
var purePackages = map[string]bool{
	"bufio": true, "bytes": true, "cmp": true,
	"container/heap": true, "container/list": true, "container/ring": true,
	"crypto/hmac": true, "crypto/md5": true, "crypto/sha1": true, "crypto/sha256": true, "crypto/sha512": true, "crypto/subtle": true,
	"encoding": true, "encoding/asn1": true, "encoding/base32": true, "encoding/base64": true, "encoding/binary": true, "encoding/csv": true,
	"encoding/hex": true, "encoding/json": true, "encoding/pem": true, "encoding/xml": true,
	"errors": true, "hash": true, "hash/adler32": true, "hash/crc32": true, "hash/crc64": true, "hash/fnv": true,
	"io": true, "io/fs": true, "iter": true, "maps": true, "math/big": true, "math/bits": true,
	"path": true, "regexp": true, "regexp/syntax": true,
	"slices": true, "sort": true, "strconv": true, "strings": true, "text/scanner": true,
	"unicode": true, "unicode/utf16": true, "unicode/utf8": true,
}

// PurePackage reports whether a standard package is in the audited-pure
// set.
func PurePackage(pkgPath string) bool { return purePackages[pkgPath] }

// PurePackages lists the audited-pure standard package set, sorted —
// the toolchain-source audit's key walks it.
func PurePackages() []string {
	keys := make([]string, 0, len(purePackages))
	for k := range purePackages {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// ReceiverPackages lists the packages whose receiver tables this set
// carries — sync's synchronization, pool and memo methods, reflect's
// view surface, time's receiver-qualified names — sorted; the
// toolchain-source audit's key walks it beside the symbol tables.
func ReceiverPackages() []string {
	return []string{"math/rand", "reflect", "sync", "sync/atomic", "time"}
}

// timeSymbols is the audited surface of package time, matched by bare
// name at every tier: fixed-argument construction and value
// computation over Time, Duration, Month, and Weekday that reads
// neither the clock, nor the local zone, nor the exported time.UTC
// variable. A name shared by a pure declaration and an ambient one is
// excluded here whole — After (the timer channel), Local and UTC (the
// exported variables), Unix, UnixMilli, and UnixMicro (the functions
// install the LOCAL zone on the value they construct — every later
// decomposition of it reads $TZ and the zone database), Location (the
// type name), and AddDate — those of the method forms the receiver
// distinguishes and the audit admits living in timeMethods for the
// tiers that know the callee. Now, Since, Until, Sleep, Tick,
// AfterFunc, NewTimer, NewTicker, Parse, ParseInLocation,
// LoadLocation, and LoadLocationFromTZData never enter. Grows only by source audit
// (REQ-closure-observability-audited-set).
var timeSymbols = map[string]bool{
	// construction and the type/constant names
	"Date": true, "FixedZone": true, "ParseDuration": true,
	"Time": true, "Duration": true, "Month": true, "Weekday": true,
	"January": true, "February": true, "March": true, "April": true, "May": true, "June": true,
	"July": true, "August": true, "September": true, "October": true, "November": true, "December": true,
	"Sunday": true, "Monday": true, "Tuesday": true, "Wednesday": true, "Thursday": true, "Friday": true, "Saturday": true,
	"Nanosecond": true, "Microsecond": true, "Millisecond": true, "Second": true, "Minute": true, "Hour": true,
	// the layout constants: execution-free string references
	"Layout": true, "ANSIC": true, "UnixDate": true, "RubyDate": true, "RFC822": true, "RFC822Z": true,
	"RFC850": true, "RFC1123": true, "RFC1123Z": true, "RFC3339": true, "RFC3339Nano": true, "Kitchen": true,
	"Stamp": true, "StampMilli": true, "StampMicro": true, "StampNano": true, "DateTime": true, "DateOnly": true, "TimeOnly": true,
	// Time value computation
	"Add": true, "Sub": true, "Before": true, "Equal": true, "Compare": true, "IsZero": true,
	"Format": true, "AppendFormat": true, "String": true, "Truncate": true, "Round": true, "In": true,
	"Zone": true, "ZoneBounds": true, "Year": true, "Day": true, "YearDay": true, "ISOWeek": true, "Clock": true,
	"UnixNano": true,
	// Duration value computation
	"Hours": true, "Minutes": true, "Seconds": true, "Milliseconds": true, "Microseconds": true, "Nanoseconds": true, "Abs": true,
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

// randSymbols is the audited bare-name surface of package math/rand:
// the explicit-seed source constructor NewSource, the local PRNG
// constructor New, and the Rand, Source, and Source64 type names.
// Top-level sampling functions (Int, Intn, Float64, Perm, Shuffle,
// Read, Seed, etc.) share their names with (*Rand) methods and read
// the process-wide unseeded global generator, so they are excluded from
// the bare-name table and admitted only on a *Rand or *rngSource
// receiver through randMethods. ExpFloat64, NormFloat64, and Zipf call
// package math's transcendental functions and remain excluded
// (REQ-closure-observability-entropy).
var randSymbols = map[string]bool{
	"New": true, "NewSource": true,
	"Rand": true, "Source": true, "Source64": true,
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

// urlSymbols is the audited surface of package net/url, matched by
// bare name at every tier: escaping and unescaping, the Userinfo
// constructors, and the value methods of URL, Values, Userinfo, and
// the error types — string computation over their operands. Every
// operation that reaches the package's two GODEBUG settings
// (urlstrictcolons through parseHost, urlmaxqueryparams through
// parseQuery) never enters: Parse, ParseRequestURI, ParseQuery,
// JoinPath, (URL).Parse, (URL).Query, (URL).UnmarshalBinary — a
// setting is read through the runtime's debug registry, which no
// code-result guard pins and which one Setenv moves in-process — and
// a name shared with one of them (Parse, JoinPath) is excluded whole.
// The package's other reaches are net/netip's value parsing (its
// unique-interning registry is value-deterministic; its math use is
// a constant) and a push linkname of setPath (pure over its
// receiver). No exported variables; grows only by source audit
// (REQ-closure-observability-audited-set).
var urlSymbols = map[string]bool{
	"QueryEscape": true, "QueryUnescape": true, "PathEscape": true, "PathUnescape": true,
	"User": true, "UserPassword": true, "Username": true, "Password": true,
	"URL": true, "Values": true, "Userinfo": true, "Error": true, "EscapeError": true, "InvalidHostError": true,
	"String": true, "EscapedPath": true, "EscapedFragment": true, "Redacted": true, "IsAbs": true,
	"ResolveReference": true, "RequestURI": true, "Hostname": true, "Port": true,
	"MarshalBinary": true, "AppendBinary": true, "Clone": true,
	"Get": true, "Set": true, "Add": true, "Del": true, "Has": true, "Encode": true,
	"Unwrap": true, "Timeout": true, "Temporary": true,
}

// FlagRole classifies a symbol of standard package flag across the
// audited-pure surface, the registration-facts sink judgments, and
// the refused parsed-input / callback surface.
type FlagRole uint8

const (
	FlagRoleRefused FlagRole = iota
	FlagRoleAudited
	FlagRoleValueRegistration
	FlagRolePointerRegistration
)

// IsRegistration reports whether the role is one of the value- or
// pointer-shaped flag registration families.
func (r FlagRole) IsRegistration() bool {
	return r == FlagRoleValueRegistration || r == FlagRolePointerRegistration
}

// flagSurface is the one table classifying standard package flag:
//   - FlagRoleAudited: the default set's variable, the set constructor,
//     the error-handling constants, and the type names — each a selector
//     a registration's receiver or argument spells and none an input
//     channel by itself (REQ-closure-observability-flag-registration).
//   - FlagRoleValueRegistration / FlagRolePointerRegistration: the
//     value- and pointer-shaped registration families whose storage
//     flagRegistrationFacts traces program-wide.
//   - FlagRoleRefused: parsed-state readers/writers, exit/usage helpers,
//     and callback registration families (Parse, Parsed, Lookup, Set,
//     Args, NArg, Arg, NFlag, Visit, VisitAll, PrintDefaults, Output,
//     SetOutput, Init, Usage, Name, UnquoteUsage, ErrHelp, Var, TextVar,
//     Func, BoolFunc); any unlisted symbol also defaults to FlagRoleRefused.
var flagSurface = map[string]FlagRole{
	// Audited pure / type / constant surface
	"NewFlagSet": FlagRoleAudited, "CommandLine": FlagRoleAudited,
	"FlagSet": FlagRoleAudited, "Flag": FlagRoleAudited, "Value": FlagRoleAudited, "Getter": FlagRoleAudited, "ErrorHandling": FlagRoleAudited,
	"ContinueOnError": FlagRoleAudited, "ExitOnError": FlagRoleAudited, "PanicOnError": FlagRoleAudited,
	// Value-returning registration families
	"Bool": FlagRoleValueRegistration, "Int": FlagRoleValueRegistration, "Int64": FlagRoleValueRegistration,
	"Uint": FlagRoleValueRegistration, "Uint64": FlagRoleValueRegistration, "String": FlagRoleValueRegistration,
	"Float64": FlagRoleValueRegistration, "Duration": FlagRoleValueRegistration,
	// Pointer-taking registration families
	"BoolVar": FlagRolePointerRegistration, "IntVar": FlagRolePointerRegistration, "Int64Var": FlagRolePointerRegistration,
	"UintVar": FlagRolePointerRegistration, "Uint64Var": FlagRolePointerRegistration, "StringVar": FlagRolePointerRegistration,
	"Float64Var": FlagRolePointerRegistration, "DurationVar": FlagRolePointerRegistration,
	// Refused parsed-input, output, and callback families
	"Parse": FlagRoleRefused, "Parsed": FlagRoleRefused, "Lookup": FlagRoleRefused, "Set": FlagRoleRefused,
	"Args": FlagRoleRefused, "NArg": FlagRoleRefused, "Arg": FlagRoleRefused, "NFlag": FlagRoleRefused,
	"Visit": FlagRoleRefused, "VisitAll": FlagRoleRefused, "PrintDefaults": FlagRoleRefused,
	"Output": FlagRoleRefused, "SetOutput": FlagRoleRefused, "Init": FlagRoleRefused, "Usage": FlagRoleRefused,
	"Name": FlagRoleRefused, "UnquoteUsage": FlagRoleRefused, "ErrHelp": FlagRoleRefused,
	"Var": FlagRoleRefused, "TextVar": FlagRoleRefused, "Func": FlagRoleRefused, "BoolFunc": FlagRoleRefused,
}

// FlagSurface returns the classification of a symbol in package flag.
func FlagSurface(name string) FlagRole {
	return flagSurface[name]
}

// FlagNonAuditedNames lists the explicitly classified flag symbols
// outside FlagRoleAudited (registrations and refused operations), sorted.
func FlagNonAuditedNames() []string {
	var out []string
	for name, role := range flagSurface {
		if role != FlagRoleAudited {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

var flagSymbols = func() map[string]bool {
	out := make(map[string]bool)
	for name, role := range flagSurface {
		if role == FlagRoleAudited {
			out[name] = true
		}
	}
	return out
}()

// symbolTables is the one table of per-package audited surfaces the
// class-B ladder consults; a widening is a row here, never a new
// consulting site. The audited set has two shapes — a package
// admitted whole (purePackages) or by symbol (here) — and a package
// is in exactly one, so the two consulting predicates can never
// answer differently for one package (pinned by the package's test).
var symbolTables = map[string]map[string]bool{
	"context":        contextSymbols,
	"crypto/fips140": fips140Symbols,
	"fmt":            fmtSymbols,
	"math":           mathSymbols,
	"reflect":        reflectSymbols,
	"sync/atomic":    atomicSymbols,
	"time":           timeSymbols,
	"path/filepath":  filepathSymbols,
	"net/url":        urlSymbols,
	"flag":           flagSymbols,
	"math/rand":      randSymbols,
}

// atomicSymbols is the audited bare-name surface of package sync/atomic:
// the scalar atomic types (Bool, Int32, Int64, Uint32, Uint64, Uintptr)
// and the top-level scalar atomic operations. Pointer[T] and Value, and the
// top-level Pointer operations (LoadPointer, StorePointer, SwapPointer,
// CompareAndSwapPointer), are excluded from this table; scalar receiver
// methods (Load, Store, Add, Swap, CompareAndSwap, And, Or) live in
// atomicMethods so Value's methods of the same names remain excluded.
var atomicSymbols = map[string]bool{
	"Bool": true, "Int32": true, "Int64": true, "Uint32": true, "Uint64": true, "Uintptr": true,
	"AddInt32": true, "AddInt64": true, "AddUint32": true, "AddUint64": true, "AddUintptr": true,
	"AndInt32": true, "AndInt64": true, "AndUint32": true, "AndUint64": true, "AndUintptr": true,
	"CompareAndSwapInt32": true, "CompareAndSwapInt64": true, "CompareAndSwapUint32": true, "CompareAndSwapUint64": true, "CompareAndSwapUintptr": true,
	"LoadInt32": true, "LoadInt64": true, "LoadUint32": true, "LoadUint64": true, "LoadUintptr": true,
	"OrInt32": true, "OrInt64": true, "OrUint32": true, "OrUint64": true, "OrUintptr": true,
	"StoreInt32": true, "StoreInt64": true, "StoreUint32": true, "StoreUint64": true, "StoreUintptr": true,
	"SwapInt32": true, "SwapInt64": true, "SwapUint32": true, "SwapUint64": true, "SwapUintptr": true,
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

// mathSymbols is the audited compile-time constant surface of package math:
// architectural integer limit constants and IEEE-754 floating-point constants.
// All runtime floating-point and transcendental functions in package math
// remain excluded (REQ-closure-observability-audited-set).
var mathSymbols = map[string]bool{
	"E": true, "Pi": true, "Phi": true,
	"Sqrt2": true, "SqrtE": true, "SqrtPi": true, "SqrtPhi": true,
	"Ln2": true, "Log2E": true, "Ln10": true, "Log10E": true,
	"MaxFloat32": true, "SmallestNonzeroFloat32": true,
	"MaxFloat64": true, "SmallestNonzeroFloat64": true,
	"MaxInt": true, "MinInt": true,
	"MaxInt8": true, "MinInt8": true,
	"MaxInt16": true, "MinInt16": true,
	"MaxInt32": true, "MinInt32": true,
	"MaxInt64": true, "MinInt64": true,
	"MaxUint": true, "MaxUint8": true, "MaxUint16": true, "MaxUint32": true, "MaxUint64": true,
}

// fips140Symbols is the audited surface of package crypto/fips140:
// WithoutEnforcement, which sets a goroutine-local bypass flag around a
// caller-supplied callback whose own body is walked and classified at its
// call site, and Enforced, which reports the immutable startup-resolved
// FIPS enforcement bit (REQ-closure-observability-audited-set). Enabled,
// Version, and Enforce remain excluded.
var fips140Symbols = map[string]bool{
	"WithoutEnforcement": true,
	"Enforced":           true,
}

// contextSymbols is the audited surface of package context: the timerless
// cancellation and value constructors, the Context and CancelFunc types and
// read methods, and the Canceled / DeadlineExceeded sentinel errors.
// WithDeadline, WithDeadlineCause, WithTimeout, WithTimeoutCause, and AfterFunc
// are excluded because they read the clock, start runtime timers, or launch
// goroutines.
var contextSymbols = map[string]bool{
	"Context": true, "CancelFunc": true, "CancelCauseFunc": true,
	"Background": true, "TODO": true,
	"WithCancel": true, "WithCancelCause": true, "WithValue": true, "WithoutCancel": true,
	"Cause": true,
	"Deadline": true, "Done": true, "Err": true, "Value": true, "String": true,
	"Canceled": true, "DeadlineExceeded": true,
}

// standardSentinelGlobals lists exported standard-library globals whose
// SSA referrers are verified unmutated outside their declaring package's init.
var standardSentinelGlobals = map[string][]string{
	"context":         {"Canceled", "DeadlineExceeded"},
	"encoding/binary": {"BigEndian", "LittleEndian"},
	"io":              {"Discard", "EOF", "ErrClosedPipe", "ErrNoProgress", "ErrShortBuffer", "ErrShortWrite", "ErrUnexpectedEOF"},
	"io/fs":           {"ErrClosed", "ErrExist", "ErrInvalid", "ErrNotExist", "ErrPermission", "SkipAll", "SkipDir"},
}

// StandardSentinelGlobal reports whether pkgPath.name is in the audited
// standard sentinel global set.
func StandardSentinelGlobal(pkgPath, name string) bool {
	return slices.Contains(standardSentinelGlobals[pkgPath], name)
}

// Symbol reports whether a standard package's symbol name is in its
// audited surface; a package without a table admits nothing here.
func Symbol(pkgPath, name string) bool { return symbolTables[pkgPath][name] }

// SymbolPackages lists the packages admitted by symbol, sorted, so a
// consumer's own package classifications can be pinned disjoint from
// them.
func SymbolPackages() []string {
	out := make([]string, 0, len(symbolTables))
	for pkgPath := range symbolTables {
		out = append(out, pkgPath)
	}
	sort.Strings(out)
	return out
}

// filepathSymbols is the audited surface of package path/filepath,
// matched by bare name at every tier: the lexical operations —
// each a string computation over its operands and the build-selected
// GOOS's separators, delegated to internal/filepathlite, which
// reaches no ambient channel — the two separator constants, and the
// callback type name, and HasPrefix (deprecated, a bare
// strings.HasPrefix over its operands). The filesystem-reaching
// operations never enter: Abs (the working directory), EvalSymlinks,
// Glob, Walk, WalkDir. The
// exported error variables (ErrBadPattern, SkipDir, SkipAll) refuse as
// standard globals whatever this table says. No admitted name is
// shared with an ambient declaration; grows only by source audit
// (REQ-closure-observability-audited-set).
var filepathSymbols = map[string]bool{
	"Clean": true, "IsLocal": true, "Localize": true, "ToSlash": true, "FromSlash": true,
	"SplitList": true, "Split": true, "Join": true, "Ext": true, "IsAbs": true, "Rel": true,
	"Base": true, "Dir": true, "VolumeName": true, "Match": true, "HasPrefix": true,
	"Separator": true, "ListSeparator": true, "WalkFunc": true,
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

// ReflectImmutable reports whether a reflect type is in the audited
// immutable-type set.
func ReflectImmutable(name string) bool { return reflectImmutableTypes[name] }

// ConstantImmutable reports whether a go/constant type is in the audited
// immutable-type set.
func ConstantImmutable(name string) bool { return constantImmutableTypes[name] }

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
