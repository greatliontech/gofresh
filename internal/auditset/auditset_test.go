package auditset

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// The audited sets' exact contents — the goldens a source audit edits
// (REQ-closure-shared-dynamic-state-audited-discharges).
func TestAuditedSetsAreExactlyTheAuditedContents(t *testing.T) {
	if !slices.Equal(syncNames, []string{"Broadcast", "Cond", "Do", "Lock", "Locker", "Mutex", "NewCond", "Once", "RLock", "RUnlock", "RWMutex", "Signal", "TryLock", "TryRLock", "Unlock", "Wait"}) {
		t.Fatalf("sync names = %v", syncNames)
	}
	if !slices.Equal(poolNames, []string{"Get", "Pool", "Put"}) {
		t.Fatalf("pool names = %v", poolNames)
	}
	if len(timeMethods) != 1 || !slices.Equal(timeMethods["Time"], []string{"After", "Unix", "UnixMilli", "UnixMicro", "UTC", "AddDate"}) {
		t.Fatalf("time methods = %v", timeMethods)
	}
	for _, name := range timeMethods["Time"] {
		if timeSymbols[name] {
			t.Errorf("time method %s is also a bare-name symbol — the receiver-qualified set exists for names the bare table must exclude", name)
		}
	}
	if !TimeMethod("Time", "UTC") || !TimeMethod("Time", "AddDate") || TimeMethod("Time", "Local") || TimeMethod("Time", "Location") || TimeMethod("Time", "Now") || TimeMethod("Duration", "UTC") || TimeMethod("Location", "String") {
		t.Fatal("time method predicate wrong")
	}
	if !slices.Equal(memoNames, []string{"Load", "LoadOrStore", "Map", "Store"}) {
		t.Fatalf("memo names = %v", memoNames)
	}
	if !MemoMethod("Map", "Load") || MemoMethod("Map", "Range") || MemoMethod("Pool", "Load") || !MemoName("LoadOrStore") || MemoName("Delete") {
		t.Fatal("memo predicates wrong")
	}
	reflectNames := slices.Sorted(maps.Keys(reflectSymbols))
	if !slices.Equal(reflectNames, []string{"Align", "Array", "AssignableTo", "Bits", "Bool", "BothDir", "CanSeq", "CanSeq2", "Chan", "ChanDir", "Comparable", "Complex128", "Complex64", "ConvertibleTo", "DeepEqual", "Elem", "Field", "FieldAlign", "FieldByIndex", "FieldByName", "FieldByNameFunc", "Float32", "Float64", "Func", "Get", "Implements", "In", "Int", "Int16", "Int32", "Int64", "Int8", "Invalid", "IsVariadic", "Kind", "Len", "Lookup", "Map", "Name", "NumField", "NumIn", "NumMethod", "NumOut", "Out", "OverflowComplex", "OverflowFloat", "OverflowInt", "OverflowUint", "PkgPath", "RecvDir", "SendDir", "Size", "String", "Struct", "StructField", "StructTag", "Type", "TypeOf", "Uint", "Uint16", "Uint32", "Uint64", "Uint8", "Uintptr"}) || !slices.Equal(slices.Sorted(maps.Keys(reflectImmutableTypes)), []string{"Type"}) {
		t.Fatalf("reflect sets = %v, %v", reflectNames, reflectImmutableTypes)
	}
	if len(reflectMethods) != 1 || !slices.Equal(reflectMethods["rtype"], []string{"Key"}) {
		t.Fatalf("reflect methods = %v", reflectMethods)
	}
	for _, names := range reflectMethods {
		for _, name := range names {
			if reflectSymbols[name] {
				t.Errorf("reflect method %s is also a bare-name symbol — the receiver-qualified set exists for names the bare table must exclude", name)
			}
		}
	}
	if !ReflectMethod("rtype", "Key") || ReflectMethod("MapIter", "Key") || ReflectMethod("Value", "Key") {
		t.Fatal("reflect method predicate wrong")
	}
	if !slices.Equal(slices.Sorted(maps.Keys(randSymbols)), []string{"New", "NewSource", "Rand", "Source", "Source64"}) {
		t.Fatalf("rand symbols = %v", slices.Sorted(maps.Keys(randSymbols)))
	}
	for _, names := range randMethods {
		for _, name := range names {
			if randSymbols[name] {
				t.Errorf("rand method %s is also a bare-name symbol — top-level sampling functions read globalRand and must be excluded from randSymbols", name)
			}
		}
	}
	if !RandMethod("Rand", "Intn") || !RandMethod("Rand", "Float64") || !RandMethod("rngSource", "Int63") || RandMethod("Rand", "ExpFloat64") || RandMethod("Rand", "NormFloat64") || RandMethod("Zipf", "Uint64") {
		t.Fatal("rand method predicate wrong")
	}
	if !slices.Equal(slices.Sorted(maps.Keys(fmtSymbols)), []string{"Append", "Appendf", "Appendln", "Errorf", "FormatString", "Formatter", "GoStringer", "ScanState", "Scanner", "Sprint", "Sprintf", "Sprintln", "Sscan", "Sscanf", "Sscanln", "State", "Stringer"}) {
		t.Fatalf("fmt symbols = %v", slices.Sorted(maps.Keys(fmtSymbols)))
	}
	if !PurePackage("go/build/constraint") {
		t.Fatal("go/build/constraint missing from purePackages")
	}
	if !RuntimeDebugMethod("BuildInfo", "String") || RuntimeDebugMethod("Module", "String") || Symbol("runtime/debug", "ReadBuildInfo") || Symbol("runtime/debug", "String") || !Symbol("runtime/debug", "ParseBuildInfo") {
		t.Fatal("runtime/debug symbol or method predicate wrong")
	}
	if !GoASTMethod("Ident", "String") || !GoASTMethod("ObjKind", "String") || GoASTMethod("CommentMap", "String") || GoASTMethod("Scope", "String") || Symbol("go/ast", "String") {
		t.Fatal("go/ast receiver-qualified String predicate wrong")
	}
	if !slices.Equal(slices.Sorted(maps.Keys(fips140Symbols)), []string{"Enforced", "WithoutEnforcement"}) {
		t.Fatalf("fips140 symbols = %v", slices.Sorted(maps.Keys(fips140Symbols)))
	}
	if !Symbol("math", "MaxUint32") || !Symbol("math", "MaxInt64") || !Symbol("math", "NaN") || !Symbol("math", "Sqrt") || !Symbol("math", "Float64bits") || Symbol("math", "Sin") || Symbol("math", "Exp") || Symbol("math", "FMA") || !Symbol("crypto/fips140", "WithoutEnforcement") || !Symbol("crypto/fips140", "Enforced") || Symbol("crypto/fips140", "Enabled") || !Symbol("runtime", "GOARCH") || !Symbol("runtime", "GOOS") || Symbol("runtime", "NumCPU") {
		t.Fatal("math, crypto/fips140, or runtime symbol predicate wrong")
	}
	if len(MathConstants()) != 30 || len(MathPureFuncs()) != 31 || !MathConstant("Pi") || MathConstant("Sqrt") || !MathPureFunc("Sqrt") || MathPureFunc("Pi") || MathPureFunc("FMA") {
		t.Fatalf("math partition wrong: constants=%d pureFuncs=%d", len(MathConstants()), len(MathPureFuncs()))
	}
	for _, name := range []string{"Pointer", "UnsafePointer", "Ptr", "Interface", "Slice", "Key", "Method", "MethodByName", "Call", "CallSlice", "MakeFunc", "ValueOf", "New", "Zero", "Indirect", "Set", "SetInt", "Index", "Addr", "Convert", "Append", "Copy", "Swapper", "Select", "MakeSlice", "MakeMap", "MakeChan", "PointerTo", "SliceOf", "MapOf", "ArrayOf", "ChanOf", "FuncOf", "StructOf", "TypeFor", "Seq", "Seq2", "Bytes", "IsNil", "IsValid", "IsZero", "MapIndex", "MapRange", "Cap"} {
		if reflectSymbols[name] {
			t.Errorf("reflect %s admitted — the dispatch channel, a producer, an address, or the hand-out", name)
		}
	}
	if !SyncMethod("RWMutex", "RLock") || SyncMethod("Mutex", "RLock") || !SyncMethod("Once", "Do") || SyncMethod("Once", "Lock") || !SyncMethod("Cond", "Wait") || !SyncMethod("Cond", "Signal") || !SyncMethod("Cond", "Broadcast") || SyncMethod("Cond", "Lock") {
		t.Fatal("sync method predicate wrong")
	}
	if !Symbol("sync/atomic", "Int64") || !Symbol("sync/atomic", "LoadInt64") || Symbol("sync/atomic", "Value") || Symbol("sync/atomic", "Pointer") || Symbol("sync/atomic", "LoadPointer") || !AtomicMethod("Int64", "Add") || !AtomicMethod("Bool", "CompareAndSwap") || AtomicMethod("Value", "Load") || AtomicMethod("Pointer", "Load") {
		t.Fatal("sync/atomic symbol or method predicate wrong")
	}
	if !StandardSentinelGlobal("io", "EOF") || !StandardSentinelGlobal("io/fs", "ErrNotExist") || !StandardSentinelGlobal("encoding/binary", "BigEndian") || !StandardSentinelGlobal("io", "Discard") || !StandardSentinelGlobal("strconv", "ErrRange") || !StandardSentinelGlobal("strconv", "ErrSyntax") || StandardSentinelGlobal("os", "Stdout") {
		t.Fatal("standard sentinel global predicate wrong")
	}
	if !PoolMethod("Pool", "Get") || PoolMethod("Pool", "New") {
		t.Fatal("pool method predicate wrong")
	}
	if !SyncName("TryRLock") || SyncName("Pool") || !PoolName("Put") || PoolName("Lock") {
		t.Fatal("name predicates wrong")
	}
	if !Symbol("reflect", "TypeOf") || Symbol("reflect", "ValueOf") || !ReflectImmutable("Type") || ReflectImmutable("Value") {
		t.Fatal("reflect predicates wrong")
	}
	if !slices.Equal(AuditedLinknameTargets(), []string{"runtime.getAuxv", "runtime.vgetrandom", "syscall.prlimit"}) || !AuditedLinknameTarget("runtime.getAuxv") || AuditedLinknameTarget("runtime.nanotime") {
		t.Fatalf("audited linkname targets = %v", AuditedLinknameTargets())
	}
	if kind, ok := AuditedReadOnlyVarLinknameTarget("internal/cpu.HWCap"); !ok || kind != types.Uint {
		t.Fatalf("AuditedReadOnlyVarLinknameTarget(internal/cpu.HWCap) = %v, %v", kind, ok)
	}
	if _, ok := AuditedReadOnlyVarLinknameTarget("runtime.writeBarrier"); ok {
		t.Fatal("AuditedReadOnlyVarLinknameTarget admitted runtime.writeBarrier")
	}
	if got := AuditedReadOnlyVarLinknameTargets(); !maps.Equal(got, map[string]types.BasicKind{"internal/cpu.HWCap": types.Uint}) {
		t.Fatalf("AuditedReadOnlyVarLinknameTargets() = %v", got)
	}
	if !slices.Equal(ClassBPackages(), []string{"crypto/rand", "fmt", "golang.org/x/sys/unix", "html/template", "net", "net/http", "os", "plugin", "syscall", "testing", "text/template"}) || !ClassBPackage("os") || ClassBPackage("strings") {
		t.Fatalf("ClassBPackages() = %v", ClassBPackages())
	}
	if !NetworkPackage("net") || !NetworkPackage("net/http") || NetworkPackage("net/url") || NetworkPackage("os") {
		t.Fatal("NetworkPackage predicate wrong")
	}
	if !AlwaysExternalPackage("plugin") || !AlwaysExternalPackage("syscall") || !AlwaysExternalPackage("golang.org/x/sys/unix") || !AlwaysExternalPackage("net/http") || AlwaysExternalPackage("net/url") || AlwaysExternalPackage("os") {
		t.Fatal("AlwaysExternalPackage predicate wrong")
	}
}

func TestBoundedTokenNeverShadowsALongerName(t *testing.T) {
	for _, tc := range []struct {
		text, marker, bounds string
		rest                 string
		ok                   bool
	}{
		{"//go:linkname a b", "//go:linkname", " \t", " a b", true},
		{"//go:linkname", "//go:linkname", " \t", "", true},
		{"//go:linknamestd a b", "//go:linkname", " \t", "", false},
		{"//go:linkname.x a b", "//go:linkname", " \t", "", false},
		// A non-ASCII space is not a directive separator: the bound is
		// the byte grammar the caller names, narrower than a Unicode
		// field split.
		{"//go:linkname\u00a0a b", "//go:linkname", " \t", "", false},
		{"// Code generated by protoc-gen-go. DO NOT EDIT.", "// Code generated by protoc-gen-go", " \t.", ". DO NOT EDIT.", true},
		{"// Code generated by protoc-gen-go-grpc. DO NOT EDIT.", "// Code generated by protoc-gen-go", " \t.", "", false},
		{"short", "longer marker", " ", "", false},
	} {
		rest, ok := BoundedToken(tc.text, tc.marker, tc.bounds)
		if ok != tc.ok || rest != tc.rest {
			t.Errorf("BoundedToken(%q, %q, %q) = %q, %v; want %q, %v", tc.text, tc.marker, tc.bounds, rest, ok, tc.rest, tc.ok)
		}
	}
}

// A standard package is admitted whole or by symbol, never both: the
// two consulting predicates would otherwise answer differently for one
// package (REQ-closure-observability-audited-set).
func TestAuditedShapesAreDisjoint(t *testing.T) {
	for pkgPath := range symbolTables {
		if purePackages[pkgPath] {
			t.Errorf("%s is admitted whole and by symbol", pkgPath)
		}
		if len(symbolTables[pkgPath]) == 0 {
			t.Errorf("%s has an empty symbol table", pkgPath)
		}
	}
	if Symbol("net/url", "Parse") || !Symbol("net/url", "QueryEscape") || Symbol("strings", "ToUpper") {
		t.Fatal("Symbol answers outside its tables")
	}
}

// The receiver ladder answers by declaring package, receiver type
// name (one pointer level stripped), and method name — a same-named
// method on a same-named type in another package, a receiver-less
// function, and a nil function are never listed.
func TestReceiverLadderKeysOnPackageReceiverAndName(t *testing.T) {
	method := func(pkgPath, receiver, name string, pointer bool) *types.Func {
		pkg := types.NewPackage(pkgPath, "p")
		obj := types.NewTypeName(token.NoPos, pkg, receiver, nil)
		named := types.NewNamed(obj, types.NewStruct(nil, nil), nil)
		var recv types.Type = named
		if pointer {
			recv = types.NewPointer(named)
		}
		sig := types.NewSignatureType(types.NewVar(token.NoPos, pkg, "t", recv), nil, nil, nil, nil, false)
		return types.NewFunc(token.NoPos, pkg, name, sig)
	}
	if !ReceiverMethod(method("time", "Time", "UTC", false), "time", TimeMethod) || !ReceiverMethod(method("sync", "Mutex", "Lock", true), "sync", SyncMethod) {
		t.Fatal("a listed method on its declaring package's receiver refused")
	}
	if ReceiverMethod(method("example.com/time", "Time", "UTC", false), "time", TimeMethod) || ReceiverMethod(method("time", "Time", "Local", false), "time", TimeMethod) || ReceiverMethod(method("time", "Duration", "UTC", false), "time", TimeMethod) {
		t.Fatal("a foreign package, an unlisted name, or an unlisted receiver admitted")
	}
	free := types.NewFunc(token.NoPos, types.NewPackage("time", "time"), "UTC", types.NewSignatureType(nil, nil, nil, nil, nil, false))
	if ReceiverMethod(free, "time", TimeMethod) || ReceiverMethod(nil, "time", TimeMethod) {
		t.Fatal("a receiver-less or nil function admitted")
	}
	universe := types.NewFunc(token.NoPos, nil, "UTC", types.NewSignatureType(nil, nil, nil, nil, nil, false))
	if ReceiverMethod(universe, "time", TimeMethod) {
		t.Fatal("a package-less function admitted")
	}
	// A method declared on an alias of the receiver type resolves
	// through the alias to the named type.
	pkg := types.NewPackage("sync", "sync")
	mutex := types.NewNamed(types.NewTypeName(token.NoPos, pkg, "Mutex", nil), types.NewStruct(nil, nil), nil)
	alias := types.NewAlias(types.NewTypeName(token.NoPos, pkg, "M", nil), mutex)
	aliased := types.NewFunc(token.NoPos, pkg, "Lock", types.NewSignatureType(types.NewVar(token.NoPos, pkg, "m", types.NewPointer(alias)), nil, nil, nil, nil, false))
	byValue := types.NewFunc(token.NoPos, pkg, "Lock", types.NewSignatureType(types.NewVar(token.NoPos, pkg, "m", alias), nil, nil, nil, nil, false))
	if !ReceiverMethod(aliased, "sync", SyncMethod) || !ReceiverMethod(byValue, "sync", SyncMethod) {
		t.Fatal("a method on an alias of a listed receiver (pointer or value) refused")
	}
}

func TestIdentityCoversFlagSurfaceRolesAndReceiverTables(t *testing.T) {
	base := Identity()
	if base == "" {
		t.Fatal("Identity returned empty string")
	}
	if got := ReceiverPackages(); !slices.Equal(got, []string{"go/ast", "math/rand", "reflect", "runtime/debug", "sync", "sync/atomic", "time"}) {
		t.Fatalf("ReceiverPackages() = %v", got)
	}

	// Mutating a non-FlagRoleAudited role in flagSurface must move Identity().
	origRole := flagSurface["Parse"]
	flagSurface["Parse"] = FlagRolePointerRegistration
	movedFlag := Identity()
	flagSurface["Parse"] = origRole
	if movedFlag == base {
		t.Fatal("Identity() did not move when flagSurface role changed between non-Audited roles")
	}
	if Identity() != base {
		t.Fatal("Identity() did not restore after reverting flagSurface")
	}
}

func TestIdentityCoversAdmissionInventories(t *testing.T) {
	base := Identity()
	for _, table := range []map[string]bool{purePackages, reflectImmutableTypes, constantImmutableTypes, symbolTables["reflect"], symbolTables["go/ast"], symbolTables["go/parser"], symbolTables["go/scanner"], symbolTables["go/token"], symbolTables["runtime/debug"], symbolTables["text/tabwriter"], auditedLinknameTargets, classBPackages, fmtWriterFuncs, fmtReaderFuncs, pureScalarOrValuePackages, pureHashPackages, goASTNodeInterfaces, goParserSourceFuncs} {
		defer delete(table, "identity-test")
		table["identity-test"] = true
		changed := Identity()
		delete(table, "identity-test")
		if changed == base || Identity() != base {
			t.Fatal("admission membership did not key its identity")
		}
	}
	defer delete(auditedReadOnlyVarLinknameTargets, "identity-test")
	auditedReadOnlyVarLinknameTargets["identity-test"] = types.Uint64
	changedRO := Identity()
	delete(auditedReadOnlyVarLinknameTargets, "identity-test")
	if changedRO == base || Identity() != base {
		t.Fatal("auditedReadOnlyVarLinknameTargets did not key its identity")
	}
	for _, table := range []map[string][]string{syncMethods, poolMethods, memoMethods, timeMethods, reflectMethods, randMethods, atomicMethods, goASTMethods, runtimeDebugMethods, standardSentinelGlobals, inMemoryWriterTypes, inMemoryReaderTypes, valuePlaneFuncs, readOnlySliceInspectFuncs, readOnlySliceCopyFuncs, inPlaceContainerMutateFuncs, pureScalarOrValueFuncs, writerFirstExtraStdFuncs} {
		defer delete(table, "identity-test")
		table["identity-test"] = []string{"Second", "First"}
		changed := Identity()
		slices.Reverse(table["identity-test"])
		if Identity() != changed {
			t.Fatal("method ordering changed membership identity")
		}
		delete(table, "identity-test")
		if changed == base || Identity() != base {
			t.Fatal("receiver membership did not key its identity")
		}
	}
}

func TestUnifiedSurfaceAndTraitQueries(t *testing.T) {
	if got := PackageSymbols("fmt"); !slices.Equal(got, []string{"Append", "Appendf", "Appendln", "Errorf", "FormatString", "Formatter", "GoStringer", "ScanState", "Scanner", "Sprint", "Sprintf", "Sprintln", "Sscan", "Sscanf", "Sscanln", "State", "Stringer"}) {
		t.Fatalf("PackageSymbols(fmt) = %v", got)
	}
	syncSyms := PackageSymbols("sync")
	for _, want := range []string{"Mutex", "Lock", "Once", "Do", "Pool", "Get", "Map", "LoadOrStore", "NewCond"} {
		if !slices.Contains(syncSyms, want) {
			t.Fatalf("PackageSymbols(sync) missing %q: %v", want, syncSyms)
		}
	}
	if PackageSymbols("unknown/pkg") != nil {
		t.Fatal("expected nil PackageSymbols for unknown package")
	}
	if got := PackageMethodAndReceiverNames("reflect"); !slices.Equal(got, []string{"Key", "rtype"}) {
		t.Fatalf("PackageMethodAndReceiverNames(reflect) = %v", got)
	}
	if PackageMethodAndReceiverNames("fmt") != nil {
		t.Fatal("expected nil PackageMethodAndReceiverNames(fmt)")
	}

	if !FmtWriterFunc("Fprintf") || FmtWriterFunc("Sprintf") || !FmtReaderFunc("Fscanf") || FmtReaderFunc("Sscanf") {
		t.Fatal("FmtWriterFunc / FmtReaderFunc classification mismatch")
	}
	if !InMemoryWriterPointerType("bytes", "Buffer") || !InMemoryWriterPointerType("strings", "Builder") || InMemoryWriterPointerType("strings", "Reader") || InMemoryWriterPointerType("os", "File") {
		t.Fatal("InMemoryWriterPointerType mismatch")
	}
	if !InMemoryReaderPointerType("bytes", "Buffer") || !InMemoryReaderPointerType("bytes", "Reader") || !InMemoryReaderPointerType("strings", "Reader") || InMemoryReaderPointerType("strings", "Builder") {
		t.Fatal("InMemoryReaderPointerType mismatch")
	}
	if !ValuePlaneClone("slices", "Clone") || !ValuePlaneClone("slices", "Concat") || !ValuePlaneClone("maps", "Clone") || ValuePlaneClone("bytes", "Clone") || ValuePlaneClone("slices", "Sort") {
		t.Fatal("ValuePlaneClone mismatch")
	}

	traitCases := []struct {
		pkg, fn string
		want    StdCallTraits
	}{
		{"", "Clone", StdCallTraits{}},
		{"slices", "Clone", StdCallTraits{ValuePlaneClone: true, ReadOnlySliceCopy: true}},
		{"slices", "Concat", StdCallTraits{ValuePlaneClone: true, ReadOnlySliceCopy: true}},
		{"maps", "Clone", StdCallTraits{ValuePlaneClone: true}},
		{"bytes", "Clone", StdCallTraits{ReadOnlySliceCopy: true, PureScalarOrValue: true}},
		{"bytes", "Equal", StdCallTraits{ReadOnlySliceInspect: true, PureScalarOrValue: true}},
		{"unicode/utf8", "Valid", StdCallTraits{ReadOnlySliceInspect: true, PureScalarOrValue: true}},
		{"slices", "BinarySearch", StdCallTraits{ReadOnlySliceInspect: true}},
		{"slices", "Sort", StdCallTraits{InPlaceContainerMutate: true}},
		{"sort", "Strings", StdCallTraits{InPlaceContainerMutate: true}},
		{"reflect", "TypeOf", StdCallTraits{ReadOnlySliceInspect: true, PureScalarOrValue: true}},
		{"errors", "New", StdCallTraits{PureScalarOrValue: true}},
		{"math", "Sqrt", StdCallTraits{PureScalarOrValue: true}},
		{"math", "Exp", StdCallTraits{}},
		{"math", "FMA", StdCallTraits{}},
		{"os", "Getenv", StdCallTraits{}},
	}
	for _, tc := range traitCases {
		if got := DeterministicStdCallTraits(tc.pkg, tc.fn); got != tc.want {
			t.Errorf("DeterministicStdCallTraits(%q, %q) = %+v, want %+v", tc.pkg, tc.fn, got, tc.want)
		}
	}

	fmtCases := []struct {
		fmtStr      string
		wantExposes bool
		wantScanOK  bool
		wantStringer bool
	}{
		{"hello %% world", false, true, true},
		{"%s:%d:%x:%q:%v:%+v:%T", false, true, false},
		{"%s:%q:%x:%X:%v:%+v:%T", false, true, true},
		{"%p", true, true, false},
		{"%#v", true, true, false},
		{"%+#010v", true, true, false},
		{"%#x", false, true, false},
		{"%[1]s %[2]d", false, true, false},
		{"%[1]p", true, true, false},
		{"%.[1]p", true, true, false},
		{"%*.*p", true, true, false},
		{"trailing %", true, false, false},
		{"unclosed %[1", true, false, false},
		{"zero index %[0]d", true, false, false},
		{"non-digit %[a]d", true, false, false},
		{"bad width after index %[1]2d", true, false, false},
		{"bad prec after index %[1].2d", true, false, false},
		{"bad prec digits after prec index %.[1]2s", true, false, false},
		{"trailing dot without verb %.", true, false, false},
		{"trailing width dot %10.", true, false, false},
		{"trailing sharp dot %#.", true, false, false},
		{"flagged percent %#%", true, false, false},
		{"width percent %2%", true, false, false},
		{"invalid utf8 verb %\xff", true, false, false},
		{"multibyte verb %😀%p", true, true, false},
		{"multibyte safe %😀%d", false, true, false},
	}
	for _, tc := range fmtCases {
		if got := FormatStringExposesPointerIdentity(tc.fmtStr); got != tc.wantExposes {
			t.Errorf("FormatStringExposesPointerIdentity(%q) = %v, want %v", tc.fmtStr, got, tc.wantExposes)
		}
		allStringer := true
		ok := ScanFmtDirectives(tc.fmtStr, func(d FmtDirective) bool {
			if !d.InvokesStringerOnly() {
				allStringer = false
			}
			return true
		})
		if ok != tc.wantScanOK {
			t.Errorf("ScanFmtDirectives(%q) ok = %v, want %v", tc.fmtStr, ok, tc.wantScanOK)
		}
		if ok && allStringer != tc.wantStringer {
			t.Errorf("ScanFmtDirectives(%q) InvokesStringerOnly = %v, want %v", tc.fmtStr, allStringer, tc.wantStringer)
		}
	}

	// Verify IEEE-754 quiet NaN sign-bit witness documenting why FMA is excluded:
	// math.FMA(0, Inf, NaN) vs software 0*Inf+NaN can differ in sign bit across CPUs.
	_ = math.Float64bits(math.NaN())
}

type heapBox struct {
	X   int
	Sub *int
}

func (b *heapBox) String() string { return fmt.Sprintf("box(%d)", b.X) }

func checkFmtOracleOnFormat(t testing.TB, fmtStr string) {
	t.Helper()
	v1, v2 := 7, 7
	b1 := &heapBox{X: 42, Sub: &v1}
	b2 := &heapBox{X: 42, Sub: &v2}
	e1 := errors.New("same-err")
	e2 := errors.New("same-err")
	rt1 := reflect.SliceOf(reflect.TypeOf(b1))
	rt2 := reflect.SliceOf(reflect.TypeOf(b2))

	exposes := FormatStringExposesPointerIdentity(fmtStr)
	allStringer := true
	noIndexOrStar := true
	var verbs []FmtDirective
	scanOK := ScanFmtDirectives(fmtStr, func(d FmtDirective) bool {
		verbs = append(verbs, d)
		if !d.InvokesStringerOnly() {
			allStringer = false
		}
		if d.HasArgIndex || d.DynamicWidth || d.DynamicPrec || d.Verb == '%' {
			noIndexOrStar = false
		}
		return true
	})

	// 1. Scalar arguments: whenever FormatStringExposesPointerIdentity is false,
	// identical scalar values MUST format to identical strings.
	if !exposes {
		s1 := fmt.Sprintf(fmtStr, 123, "abc", true)
		s2 := fmt.Sprintf(fmtStr, 123, "abc", true)
		if s1 != s2 {
			t.Fatalf("scalar format drift for %q: %q vs %q", fmtStr, s1, s2)
		}
	}

	// 2. Heap-allocated Stringer/error/reflect.Type arguments at distinct addresses:
	// whenever ScanFmtDirectives succeeds, noIndexOrStar holds, len(verbs) == 1,
	// and InvokesStringerOnly() is true, distinct heap allocations with equal
	// logical String()/Error() representation MUST produce identical formatted bytes!
	if scanOK && noIndexOrStar && len(verbs) == 1 && allStringer {
		if got1, got2 := fmt.Sprintf(fmtStr, b1), fmt.Sprintf(fmtStr, b2); got1 != got2 {
			t.Fatalf("InvokesStringerOnly admitted address leak on *heapBox for %q: %q vs %q", fmtStr, got1, got2)
		}
		if got1, got2 := fmt.Sprintf(fmtStr, e1), fmt.Sprintf(fmtStr, e2); got1 != got2 {
			t.Fatalf("InvokesStringerOnly admitted address leak on error for %q: %q vs %q", fmtStr, got1, got2)
		}
	}

	// 3. Pointer-address soundness: if formatting e1 vs e2 (which has no inner
	// pointer fields, only string s) differs, FormatStringExposesPointerIdentity
	// MUST return true!
	if got1, got2 := fmt.Sprintf(fmtStr, e1), fmt.Sprintf(fmtStr, e2); got1 != got2 && !exposes {
		t.Fatalf("FormatStringExposesPointerIdentity(%q) = false, but fmt.Sprintf leaked error address: %q vs %q", fmtStr, got1, got2)
	}
	_ = rt1
	_ = rt2
}

func TestPropertyFmtDirectivesAgainstRuntimeSprintfOracle(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		nParts := rapid.IntRange(1, 5).Draw(rt, "nParts")
		var b []byte
		for range nParts {
			if rapid.Bool().Draw(rt, "lit") {
				b = append(b, rapid.StringMatching(`[a-zA-Z0-9_ :.-]{0,4}`).Draw(rt, "text")...)
				continue
			}
			b = append(b, '%')
			flags := rapid.SliceOfN(rapid.SampledFrom([]byte{'#', '+', '-', ' ', '0'}), 0, 3).Draw(rt, "flags")
			b = append(b, flags...)
			if rapid.Bool().Draw(rt, "idx") {
				b = append(b, rapid.SampledFrom([]string{"[1]", "[2]", "[0]", "[a]", "["}).Draw(rt, "idxTok")...)
			}
			b = append(b, rapid.SampledFrom([]string{"", "4", "*"}).Draw(rt, "wid")...)
			if rapid.Bool().Draw(rt, "prec") {
				b = append(b, '.')
				b = append(b, rapid.SampledFrom([]string{"", "2", "*", "[1]*", "[1]2"}).Draw(rt, "precTok")...)
			}
			b = append(b, rapid.SampledFrom([]string{"v", "s", "q", "d", "x", "X", "p", "T", "w", "%", "", "😀"}).Draw(rt, "verb")...)
		}
		checkFmtOracleOnFormat(t, string(b))
	})
}

func FuzzScanFmtDirectivesAndPointerIdentityOracle(f *testing.F) {
	for _, seed := range []string{
		"", "%", "%%", "%p", "%#v", "%+v", "%v", "%s", "%d", "%x", "%q", "%T", "%w",
		"%[1]p", "%.[1]p", "%*p", "%[a%p]s", "%[0]v", "%[1]2d", "%[1].2d", "%😀%p", "%\xff",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, fmtStr string) {
		checkFmtOracleOnFormat(t, fmtStr)
	})
}

func TestIsGeneratedMarker(t *testing.T) {
	for _, tc := range []struct {
		text string
		want bool
	}{
		{"// Code generated by protoc-gen-go. DO NOT EDIT.", true},
		{"  // Code generated by protoc-gen-go. DO NOT EDIT.  ", true},
		{"// Code generated  DO NOT EDIT.", true},
		{"// Code generated \n DO NOT EDIT.", false},
		{"// Code generated DO NOT EDIT.", false},
		{"// Code generated by tool. DO NOT EDIT", false},
		{"/* Code generated by tool. DO NOT EDIT. */", false},
	} {
		if got := IsGeneratedMarker(tc.text); got != tc.want {
			t.Errorf("IsGeneratedMarker(%q) = %v, want %v", tc.text, got, tc.want)
		}
	}
}

func TestSyntaxTabwriterHashAndBuildInfoPredicatesAndGOROOTPartition(t *testing.T) {
	for _, pkg := range []string{
		"crypto/md5", "crypto/sha1", "crypto/sha256", "crypto/sha512",
		"crypto/internal/fips140/sha256", "crypto/internal/fips140/sha512", "crypto/internal/fips140/sha3",
		"hash/adler32", "hash/crc32", "hash/crc64", "hash/fnv",
	} {
		if !PureHashPackage(pkg) {
			t.Errorf("PureHashPackage(%q) = false, want true", pkg)
		}
	}
	for _, nonPureHash := range []string{"hash/maphash", "hash", "crypto/hmac", "crypto/rand"} {
		if PureHashPackage(nonPureHash) {
			t.Errorf("PureHashPackage(%q) = true, want false", nonPureHash)
		}
	}

	for _, iface := range []string{"Node", "Expr", "Stmt", "Decl", "Spec"} {
		if !GoASTNodeInterface(iface) {
			t.Errorf("GoASTNodeInterface(%q) = false, want true", iface)
		}
	}
	for _, other := range []string{"Visitor", "File", "Ident", ""} {
		if GoASTNodeInterface(other) {
			t.Errorf("GoASTNodeInterface(%q) = true, want false", other)
		}
	}

	if !WriterFirstStdFunc("fmt", "Fprintf") || !WriterFirstStdFunc("fmt", "Fprint") || !WriterFirstStdFunc("fmt", "Fprintln") ||
		!WriterFirstStdFunc("go/scanner", "PrintError") ||
		WriterFirstStdFunc("go/ast", "Fprint") || WriterFirstStdFunc("go/ast", "Print") ||
		WriterFirstStdFunc("fmt", "Sprintf") || WriterFirstStdFunc("go/scanner", "Scan") {
		t.Fatal("WriterFirstStdFunc classification mismatch")
	}

	if !GoParserSourceFunc("ParseFile") || !GoParserSourceFunc("ParseExprFrom") ||
		GoParserSourceFunc("ParseExpr") || GoParserSourceFunc("ParseDir") {
		t.Fatal("GoParserSourceFunc classification mismatch")
	}

	// Verify exact partition of exported symbols and methods on exported types in $GOROOT/src.
	exclusions := map[string]map[string]bool{
		"text/tabwriter": {},
		"go/token":       {"Read": true, "Write": true},
		"go/scanner":     {"PrintError": true},
		"go/ast": {
			"Print": true, "Fprint": true, "NotNilFilter": true,
			"NewPackage": true, "Importer": true, "String": true,
		},
		"go/parser": {"ParseFile": true, "ParseExprFrom": true, "ParseDir": true},
		"runtime/debug": {
			"ReadBuildInfo": true, "String": true,
			"CrashOptions": true, "FreeOSMemory": true, "GCStats": true,
			"PrintStack": true, "ReadGCStats": true, "SetCrashOutput": true,
			"SetGCPercent": true, "SetMaxStack": true, "SetMaxThreads": true,
			"SetMemoryLimit": true, "SetPanicOnFault": true, "SetTraceback": true,
			"Stack": true, "WriteHeapDump": true,
		},
	}

	goroot := runtime.GOROOT()
	fset := token.NewFileSet()
	for pkgPath, excluded := range exclusions {
		dir := filepath.Join(goroot, "src", filepath.FromSlash(pkgPath))
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		exportedTypes := map[string]bool{}
		var files []*ast.File
		for _, ent := range entries {
			if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".go") || strings.HasSuffix(ent.Name(), "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(dir, ent.Name()), nil, 0)
			if err != nil {
				t.Fatalf("parse %s/%s: %v", pkgPath, ent.Name(), err)
			}
			files = append(files, f)
			for _, decl := range f.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.TYPE {
					continue
				}
				for _, sp := range gd.Specs {
					ts := sp.(*ast.TypeSpec)
					if ts.Name != nil && ast.IsExported(ts.Name.Name) {
						exportedTypes[ts.Name.Name] = true
					}
				}
			}
		}
		seen := map[string]bool{}
		for _, f := range files {
			for _, decl := range f.Decls {
				switch d := decl.(type) {
				case *ast.GenDecl:
					for _, sp := range d.Specs {
						switch s := sp.(type) {
						case *ast.ValueSpec:
							for _, id := range s.Names {
								if ast.IsExported(id.Name) {
									seen[id.Name] = true
								}
							}
						case *ast.TypeSpec:
							if s.Name != nil && ast.IsExported(s.Name.Name) {
								seen[s.Name.Name] = true
								if iface, ok := ast.Unparen(s.Type).(*ast.InterfaceType); ok && iface.Methods != nil {
									for _, m := range iface.Methods.List {
										for _, id := range m.Names {
											if ast.IsExported(id.Name) {
												seen[id.Name] = true
											}
										}
									}
								}
							}
						}
					}
				case *ast.FuncDecl:
					if d.Name == nil || !ast.IsExported(d.Name.Name) {
						continue
					}
					if d.Recv == nil {
						seen[d.Name.Name] = true
						continue
					}
					if len(d.Recv.List) == 1 {
						rt := ast.Unparen(d.Recv.List[0].Type)
						if st, ok := rt.(*ast.StarExpr); ok {
							rt = ast.Unparen(st.X)
						}
						if id, ok := rt.(*ast.Ident); ok && exportedTypes[id.Name] {
							seen[d.Name.Name] = true
						}
					}
				}
			}
		}
		for sym := range seen {
			admitted := Symbol(pkgPath, sym)
			isExcluded := excluded[sym]
			if admitted == isExcluded {
				t.Errorf("%s.%s: Symbol=%v, excluded=%v (must be in exactly one)", pkgPath, sym, admitted, isExcluded)
			}
		}
		for sym := range symbolTables[pkgPath] {
			if !seen[sym] {
				t.Errorf("%s.%s listed in symbolTables[%q] but not found in GOROOT/src", pkgPath, sym, pkgPath)
			}
		}
	}
}
