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
	"go/types"
	"slices"
	"sort"
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
// receivers and the lock-shaped methods on them, and Once's Do — a
// done flag under a mutex running the caller's own function exactly
// once, program code judged where it is written; the Once's state
// cannot change dispatch. Grows only by source audit
// (REQ-closure-shared-dynamic-state).
var syncMethods = map[string][]string{
	"Mutex":   {"Lock", "Unlock", "TryLock"},
	"RWMutex": {"Lock", "Unlock", "RLock", "RUnlock", "TryLock", "TryRLock"},
	"Once":    {"Do"},
}

// memoMethods is the audited memo set: sync.Map with its Load, Store,
// and LoadOrStore operations — process-memory reads and writes fed by
// the analyzed program alone, admitted at the effect classification
// tiers; the shared-dynamic-state discharge is the data memo's content
// judgment, never this set's. Grows only by source audit
// (REQ-closure-shared-dynamic-state).
var memoMethods = map[string][]string{
	"Map": {"Load", "Store", "LoadOrStore"},
}

// poolMethods is the audited pooling set: sync.Pool and its Get and
// Put operations (REQ-closure-shared-dynamic-state).
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
// written after construction. Audited on go1.27.0-dst.14; reflect
// lies in no listed release's walked delta, so the one audit holds
// under every listed selection (REQ-closure-observability-analysis's
// audited-set boundary).
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
// Consulted by the walk tiers alone (REQ-closure-observability-analysis).
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

// fmtSymbols is the audited surface of package fmt: the Sprint and
// Append families and Errorf — value-to-value formatting whose
// arguments' methods stay visible to reachability — and the Stringer
// name; the Print family is classified output and the Scan family
// input, so only the pure remainder is here
// (REQ-closure-observability-analysis).
var fmtSymbols = map[string]bool{
	"Sprint": true, "Sprintf": true, "Sprintln": true, "Errorf": true,
	"Append": true, "Appendf": true, "Appendln": true, "FormatString": true, "Stringer": true,
}

// The name unions the closure tiers' symbol predicates read, computed
// once from the tables.
var (
	syncNames = names(syncMethods)
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
// the commit that lists it (REQ-closure-observability-analysis).
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
// (REQ-closure-observability-analysis).
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
// fold in every compiled Go and cgo file of the closure. Audited on
// go1.27.0-dst.14; time lies in no listed release's walked delta.
// Consulted by the walk tiers alone — the fold sees no method call
// (REQ-closure-observability-analysis).
var timeMethods = map[string][]string{
	"Time": {"After", "Unix", "UnixMilli", "UnixMicro", "UTC", "AddDate"},
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
// receiver). No exported variables. Audited on go1.27.0-dst.14;
// grows only by source audit (REQ-closure-observability-analysis).
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

// flagSymbols is the audited surface of package flag beside the
// registration families the closure walks admit by name: the default
// set's variable, the set constructor (an allocation binding its own
// usage method), the error-handling constants, and the type names —
// each a selector a registration's receiver or argument spells and
// none an input channel by itself. Parse, Parsed, Lookup, Set, Args,
// NArg, Arg, NFlag, Visit, VisitAll, PrintDefaults, Output, SetOutput,
// Init, Usage, Name, UnquoteUsage, ErrHelp, and the callback families
// never enter: they read or write parsed state, exit, or run arbitrary
// code at Parse. A subject-time read of CommandLine still refuses at
// the walk as a standard global; the registration-facts judgment
// covers every registration's storage program-wide, the method form's
// receiver included. CommandLine is the one exported mutable variable
// an audited row admits: a startup-flow replacement of the default set
// adds no channel, the storage judgment being per registration call
// and set-blind, and every channel the variable carries is a method
// refused by name. The admission is by bare name at every tier, so the
// ErrorHandling name also admits the (*FlagSet).ErrorHandling accessor
// — a field written only at construction and by Init, which refuses.
// Audited on go1.27.0-dst.14 (REQ-closure-observability-analysis).
var flagSymbols = map[string]bool{
	"NewFlagSet": true, "CommandLine": true,
	"FlagSet": true, "Flag": true, "Value": true, "Getter": true, "ErrorHandling": true,
	"ContinueOnError": true, "ExitOnError": true, "PanicOnError": true,
}

// symbolTables is the one table of per-package audited surfaces the
// class-B ladder consults; a widening is a row here, never a new
// consulting site. The audited set has two shapes — a package
// admitted whole (purePackages) or by symbol (here) — and a package
// is in exactly one, so the two consulting predicates can never
// answer differently for one package (pinned by the package's test).
var symbolTables = map[string]map[string]bool{
	"fmt":           fmtSymbols,
	"reflect":       reflectSymbols,
	"time":          timeSymbols,
	"path/filepath": filepathSymbols,
	"net/url":       urlSymbols,
	"flag":          flagSymbols,
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
// shared with an ambient declaration. Audited on go1.27.0-dst.14;
// grows only by source audit (REQ-closure-observability-analysis).
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

// SyncName reports whether a sync symbol name — receiver or method —
// belongs to the audited synchronization set.
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

// ReflectImmutable reports whether a reflect type is in the audited
// immutable-type set.
func ReflectImmutable(name string) bool { return reflectImmutableTypes[name] }

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
