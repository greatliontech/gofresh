// Package auditset holds the audited standard-library symbol, receiver, and
// sentinel sets whose contents two tiers read: the closure tiers by symbol
// name, the purity tier by receiver and method. One table per set keeps the
// tiers aligned so they cannot drift apart one arm at a time. The sets are
// package-private and read through predicates: an audited set grows only by
// source audit — by editing this package — never by a write at runtime.
package auditset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
	"sort"
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
	receivers := make(map[string][]map[string][]string, len(receiverTables))
	for pkgPath, tables := range receiverTables {
		normalized := make([]map[string][]string, len(tables))
		for i, table := range tables {
			normalized[i] = methods(table)
		}
		receivers[pkgPath] = normalized
	}
	data, _ := json.Marshal([]any{
		purePackages, symbolTables, flagSurface, receivers, syncSymbols,
		methods(standardSentinelGlobals), reflectImmutableTypes, constantImmutableTypes,
		auditedLinknameTargets, auditedReadOnlyVarLinknameTargets, classBPackages,
		fmtWriterFuncs, fmtReaderFuncs,
		methods(inMemoryWriterTypes), methods(inMemoryReaderTypes),
		methods(valuePlaneFuncs), methods(readOnlySliceInspectFuncs),
		methods(readOnlySliceCopyFuncs), methods(inPlaceContainerMutateFuncs),
		methods(pureScalarOrValueFuncs), pureScalarOrValuePackages,
		pureHashPackages, goASTNodeInterfaces,
		methods(writerFirstExtraStdFuncs), goParserSourceFuncs,
		nonRetainingStdPackages, nonRetainingSyncReceivers,
		nonRetainingAtomicPrefixes, nonRetainingAtomicFuncs,
		retainingReflectExcludedPrefixes, retainingReflectExcludedFuncs,
		nonMutatingAtomicLoadFuncs, nonMutatingAtomicLoadReceivers,
		nonMutatingValuePackages, methods(nonMutatingExtraSliceFuncs),
		methods(nonMutatingValueReceiverTypes), methods(nonMutatingValueReceiverMethods),
	})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
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

// fmtSymbols is the audited surface of package fmt: the Sprint, Append,
// and Sscan families and Errorf — value-to-value formatting and string
// scanning whose arguments' methods stay visible to reachability — plus
// the formatting/scanning state interfaces; Print/Fprint are classified
// output and Scan/Fscan input, so only the pure remainder is here
// (REQ-closure-observability-audited-set).
var fmtSymbols = map[string]bool{
	"Sprint": true, "Sprintf": true, "Sprintln": true, "Errorf": true,
	"Append": true, "Appendf": true, "Appendln": true, "FormatString": true,
	"Sscan": true, "Sscanf": true, "Sscanln": true,
	"Formatter": true, "GoStringer": true, "ScanState": true, "Scanner": true, "State": true, "Stringer": true,
}

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
	"errors": true, "go/build/constraint": true,
	"hash": true, "hash/adler32": true, "hash/crc32": true, "hash/crc64": true, "hash/fnv": true,
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
	"flag":           flagSymbols,
	"fmt":            fmtSymbols,
	"go/ast":         goASTSymbols,
	"go/parser":      goParserSymbols,
	"go/scanner":     goScannerSymbols,
	"go/token":       goTokenSymbols,
	"math":           mathSymbols,
	"math/rand":      randSymbols,
	"net/url":        urlSymbols,
	"path/filepath":  filepathSymbols,
	"reflect":        reflectSymbols,
	"runtime":        runtimeSymbols,
	"runtime/debug":  runtimeDebugSymbols,
	"sync/atomic":    atomicSymbols,
	"text/tabwriter": tabwriterSymbols,
	"time":           timeSymbols,
}

// runtimeSymbols is the audited compile-time constant surface of package
// runtime: GOOS and GOARCH are compile-time string constants pinned by the
// build guard. All runtime functions and mutable state in package runtime
// remain excluded (REQ-closure-observability-audited-set).
var runtimeSymbols = map[string]bool{
	"GOARCH": true,
	"GOOS":   true,
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

// mathConstants is the compile-time constant surface of package math:
// architectural integer limit constants and IEEE-754 floating-point constants.
var mathConstants = map[string]bool{
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

// mathPureFuncs is the Tier-1 universally internal/cpu-free IEEE-754 exact
// function surface of package math across every (GOOS, GOARCH) selection,
// mechanically re-verified against the selected Go and assembly implementation
// in the toolchain audit. FMA is excluded because cmd/compile emits a runtime
// internal/cpu feature branch under amd64 GOAMD64<v3 and arm that changes the
// quiet-NaN sign bit of FMA(0, Inf, NaN) without moving code guards; CPU-free
// transcendental functions on the selected target admit at Tier 2 instead
// (REQ-closure-observability-audited-set, REQ-guard-runtime-relevance).
var mathPureFuncs = map[string]bool{
	"Abs": true, "Ceil": true, "Copysign": true, "Dim": true,
	"Float32bits": true, "Float32frombits": true,
	"Float64bits": true, "Float64frombits": true,
	"Floor": true, "Frexp": true, "Hypot": true, "Ilogb": true,
	"Inf": true, "IsInf": true, "IsNaN": true,
	"Ldexp": true, "Logb": true, "Max": true, "Min": true,
	"Mod": true, "Modf": true, "NaN": true,
	"Nextafter": true, "Nextafter32": true,
	"Pow10": true, "Remainder": true,
	"Round": true, "RoundToEven": true,
	"Signbit": true, "Sqrt": true, "Trunc": true,
}

// mathSymbols is the Tier-1 audited surface of package math: compile-time
// constants and universally internal/cpu-free IEEE-754 exact functions.
var mathSymbols = func() map[string]bool {
	out := make(map[string]bool, len(mathConstants)+len(mathPureFuncs))
	maps.Copy(out, mathConstants)
	maps.Copy(out, mathPureFuncs)
	return out
}()

// MathConstant reports whether name is an audited compile-time constant in
// package math.
func MathConstant(name string) bool { return mathConstants[name] }

// MathConstants returns the sorted audited compile-time constants in package
// math.
func MathConstants() []string { return slices.Sorted(maps.Keys(mathConstants)) }

// MathPureFunc reports whether name is a Tier-1 universally internal/cpu-free
// function in package math.
func MathPureFunc(name string) bool { return mathPureFuncs[name] }

// MathPureFuncs returns the sorted Tier-1 universally internal/cpu-free
// functions in package math.
func MathPureFuncs() []string { return slices.Sorted(maps.Keys(mathPureFuncs)) }

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
	"strconv":         {"ErrRange", "ErrSyntax"},
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

// PackageSymbols returns the sorted bare-name symbols admitted for pkgPath:
// the package's symbolTables entry, or for package sync the union of the
// audited synchronization, pooling, and memo symbol names.
func PackageSymbols(pkgPath string) []string {
	if pkgPath == "sync" {
		var out []string
		out = append(out, syncNames...)
		out = append(out, poolNames...)
		out = append(out, memoNames...)
		slices.Sort(out)
		return slices.Compact(out)
	}
	table := symbolTables[pkgPath]
	if len(table) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(table))
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
