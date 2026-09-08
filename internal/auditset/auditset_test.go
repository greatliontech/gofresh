package auditset

import (
	"go/token"
	"go/types"
	"maps"
	"slices"
	"testing"
)

func TestVersionListingAdmitsOnlyListedVersions(t *testing.T) {
	l := VersionListing{"k": {"v1", "v2"}}
	if !l.Listed("k", "v1") || !l.Listed("k", "v2") {
		t.Fatal("listed versions refused")
	}
	if l.Listed("k", "v3") || l.Listed("other", "v1") || l.Listed("k", "") {
		t.Fatal("an unlisted version or key admitted")
	}
}

// The audited sets' exact contents — the goldens a source audit edits
// (REQ-closure-shared-dynamic-state).
func TestAuditedSetsAreExactlyTheAuditedContents(t *testing.T) {
	if !slices.Equal(syncNames, []string{"Do", "Lock", "Mutex", "Once", "RLock", "RUnlock", "RWMutex", "TryLock", "TryRLock", "Unlock"}) {
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
	if !slices.Equal(slices.Sorted(maps.Keys(fmtSymbols)), []string{"Append", "Appendf", "Appendln", "Errorf", "FormatString", "Sprint", "Sprintf", "Sprintln", "Stringer"}) {
		t.Fatalf("fmt symbols = %v", slices.Sorted(maps.Keys(fmtSymbols)))
	}
	for _, name := range []string{"Pointer", "UnsafePointer", "Ptr", "Interface", "Slice", "Key", "Method", "MethodByName", "Call", "CallSlice", "MakeFunc", "ValueOf", "New", "Zero", "Indirect", "Set", "SetInt", "Index", "Addr", "Convert", "Append", "Copy", "Swapper", "Select", "MakeSlice", "MakeMap", "MakeChan", "PointerTo", "SliceOf", "MapOf", "ArrayOf", "ChanOf", "FuncOf", "StructOf", "TypeFor", "Seq", "Seq2", "Bytes", "IsNil", "IsValid", "IsZero", "MapIndex", "MapRange", "Cap"} {
		if reflectSymbols[name] {
			t.Errorf("reflect %s admitted — the dispatch channel, a producer, an address, or the hand-out", name)
		}
	}
	if !SyncMethod("RWMutex", "RLock") || SyncMethod("Mutex", "RLock") || !SyncMethod("Once", "Do") || SyncMethod("Once", "Lock") {
		t.Fatal("sync method predicate wrong")
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
// package (REQ-closure-observability-analysis).
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
