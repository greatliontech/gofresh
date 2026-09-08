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
// excluded whole: After (the timer channel and (Time).After), Local
// and UTC (the exported variables and the methods), Unix, UnixMilli,
// and UnixMicro (the functions install the LOCAL zone on the value
// they construct — every later decomposition of it reads $TZ and the
// zone database — beside the pure (Time).Unix method), Location (the
// type name beside a method that returns the time.UTC variable for a
// location-less Time), and AddDate (it re-enters Date through that
// method). Now, Since, Until, Sleep, Tick, AfterFunc, NewTimer,
// NewTicker, Parse, ParseInLocation, LoadLocation, and
// LoadLocationFromTZData never enter. Grows only by source audit
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
