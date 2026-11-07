package closure

import (
	"context"
	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/testenv"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The closure tiers' symbol predicates read the audited sets by name
// exactly as the purity tier reads them by receiver and method: one
// table each, so the two spellings cannot drift apart
// (REQ-closure-shared-dynamic-state-audited-discharges).
func TestAuditedSymbolPredicatesReadTheSharedTables(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"Mutex", "RWMutex", "Lock", "Unlock", "RLock", "RUnlock", "TryLock", "TryRLock", "Once", "Do", "Cond", "NewCond", "Locker", "Wait", "Signal", "Broadcast"} {
		if !auditedStandardSymbol(true, "sync", name) || !auditset.SyncName(name) {
			t.Errorf("sync name %s not admitted", name)
		}
	}
	for _, name := range []string{"Pool", "Get", "Put"} {
		if !auditedStandardSymbol(true, "sync", name) || !auditset.PoolName(name) {
			t.Errorf("pool name %s not admitted", name)
		}
	}
	for _, name := range []string{"After", "Unix", "UnixMilli", "UnixMicro", "UTC", "AddDate"} {
		if !auditset.TimeMethod("Time", name) || auditedStandardSymbol(true, "time", name) {
			t.Errorf("time method %s: want receiver-qualified admission with the bare name excluded", name)
		}
	}
	for _, name := range []string{"Int", "Intn", "Int63", "Int63n", "Float64", "Perm", "Shuffle", "Read", "Seed"} {
		if !auditset.RandMethod("Rand", name) || auditedStandardSymbol(true, "math/rand", name) {
			t.Errorf("math/rand method %s: want receiver-qualified admission with the bare name excluded", name)
		}
	}
	for _, name := range []string{"New", "NewSource", "Rand", "Source", "Source64"} {
		if !auditedStandardSymbol(true, "math/rand", name) {
			t.Errorf("math/rand symbol %s not admitted", name)
		}
	}
	if auditset.TimeMethod("Time", "Local") || auditset.TimeMethod("Time", "Location") {
		t.Error("(Time).Local or (Time).Location admitted — the ambient zone install and the pointer into package time's own state")
	}
	// fmt sits in classBPackages (the effect classifier's gate) and in
	// the symbol tables (the pure remainder); the two sets are disjoint,
	// the classifier consulted first at every site, so an overlap would
	// be a silent false refusal.
	for _, name := range []string{"Scan", "Scanf", "Scanln", "Fscan", "Fscanf", "Fscanln", "Sscan", "Sscanf", "Sscanln", "Print", "Printf", "Println", "Fprint", "Fprintf", "Fprintln"} {
		if auditset.Symbol("fmt", name) {
			t.Errorf("fmt.%s is a classified effect and an audited symbol", name)
		}
	}
	for _, name := range []string{"Type", "TypeOf", "DeepEqual", "Elem", "Kind", "NumField", "Struct", "Get"} {
		if !classBPureStandard(true, "reflect", name) || !auditset.Symbol("reflect", name) {
			t.Errorf("reflect symbol %s not admitted through the class-B ladder", name)
		}
	}
	for _, name := range []string{"Map", "Load", "Store", "LoadOrStore"} {
		if !auditedStandardSymbol(true, "sync", name) || !auditset.MemoName(name) {
			t.Errorf("memo name %s not admitted", name)
		}
	}
	for _, stray := range []string{"OnceFunc", "OnceValue", "WaitGroup", "Range", "Delete", "Swap", "New", "ValueOf", "Copy"} {
		if auditedStandardSymbol(true, "sync", stray) || classBPureStandard(true, "reflect", stray) {
			t.Errorf("%s admitted outside the tables", stray)
		}
	}
	if auditedStandardSymbol(false, "sync", "Lock") || auditedStandardSymbol(false, "sync", "Get") || classBPureStandard(false, "reflect", "TypeOf") {
		t.Fatal("an unaudited toolchain admitted an audited symbol")
	}
	if auditset.SyncName("Pool") || auditset.PoolName("Mutex") {
		t.Fatal("the sync and pool tables overlap")
	}
}

// The audited-pure widening: subjects reaching pure standard
// computation prove observable, while the two soundness exclusions -
// flag registration (covert Parse-time channel) and reflect (defeats
// reachability) - stay blocked
// (REQ-closure-observability-audited-set).
func TestAuditedPureWideningAndExclusions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, sub := range []string{"pure", "flagged", "mirrored"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, dir, "go.mod", "module example.com/audited\n\ngo 1.26\n")
	writeFile(t, dir, "pure/pure.go", `package pure

import (
	"bufio"
	"encoding/base32"
	"fmt"
	"strings"
)

func Formats(x float64) string {
	r := bufio.NewReader(strings.NewReader(fmt.Sprintf("%.2f", x)))
	line, _ := r.ReadString('\n')
	// A locally constructed Encoding: the package's exported Encoding
	// VARS (StdEncoding, HexEncoding) stay flagged as standard globals
	// exactly like base64's — the audited membership admits the
	// operations.
	return base32.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567").EncodeToString([]byte(line))
}
`)
	writeFile(t, dir, "pure/pure_test.go", `package pure

import "testing"

func TestFormats(t *testing.T) {
	if Formats(4) == "" {
		t.Fatal("formats")
	}
}
`)
	writeFile(t, dir, "mirrored/mirrored.go", `package mirrored

import "reflect"

func Reflected(v any) string { return reflect.TypeOf(v).Name() }
`)
	writeFile(t, dir, "mirrored/mirrored_test.go", `package mirrored

import "testing"

func TestReflected(t *testing.T) {
	_ = Reflected(1)
}
`)
	writeFile(t, dir, "flagged/flagged.go", `package flagged

import "flag"

var verbose = flag.Bool("audited-verbose", false, "covert channel")

var quiet bool

func init() { flag.BoolVar(&quiet, "audited-quiet", false, "covert channel") }

var cfg struct{ N int }

func init() { flag.IntVar(&cfg.N, "audited-n", 1, "covert channel") }

func Registered() bool { return *verbose }

func RegisteredVar() bool { return quiet }

func RegisteredField() int { return cfg.N }
`)
	writeFile(t, dir, "flagged/flagged_test.go", `package flagged

import "testing"

func TestRegistered(t *testing.T) {
	_ = Registered()
}
`)
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{
		{Package: "example.com/audited/pure", Symbol: "Formats"},
		{Package: "example.com/audited/mirrored", Symbol: "Reflected"},
		{Package: "example.com/audited/flagged", Symbol: "Registered"},
		{Package: "example.com/audited/flagged", Symbol: "RegisteredVar"},
		{Package: "example.com/audited/flagged", Symbol: "RegisteredField"},
	})
	if err != nil {
		t.Fatal(err)
	}
	formats := proofs[Subject{Package: "example.com/audited/pure", Symbol: "Formats"}]
	if !formats.Observable {
		t.Fatalf("pure fmt/bufio subject unobservable: %+v", formats)
	}
	registered := proofs[Subject{Package: "example.com/audited/flagged", Symbol: "Registered"}]
	if registered.Observable || !strings.Contains(registered.Reason, "flag") {
		t.Fatalf("flag-registration subject = %+v, want blocked on the covert channel", registered)
	}
	registeredVar := proofs[Subject{Package: "example.com/audited/flagged", Symbol: "RegisteredVar"}]
	if registeredVar.Observable || !strings.Contains(registeredVar.Reason, "flag") {
		t.Fatalf("Var-family registration subject = %+v, want blocked on the covert channel", registeredVar)
	}
	registeredField := proofs[Subject{Package: "example.com/audited/flagged", Symbol: "RegisteredField"}]
	if registeredField.Observable || !strings.Contains(registeredField.Reason, "flag") {
		t.Fatalf("field-registration subject = %+v, want blocked on the covert channel", registeredField)
	}
	reflected := proofs[Subject{Package: "example.com/audited/mirrored", Symbol: "Reflected"}]
	if reflected.Observable || (!strings.Contains(reflected.Reason, "reflect") && !strings.Contains(reflected.Reason, "reachability")) {
		t.Fatalf("reflect subject = %+v, want blocked on reachability", reflected)
	}
}

// The value-constructor and comparator admissions: math/big's
// constructors, time.Date, and reflect.DeepEqual are pure computation
// over their operands, while the ambient channels beside them - the
// clock read, the Location globals, reflective value dispatch - keep
// their classifications
// (REQ-closure-observability-audited-set).
func TestAuditedValueConstructorAndComparatorAdmissions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, sub := range []string{"values", "entropylocal", "entropyparam", "calendar", "stamp", "clock", "mirror", "span", "timer", "parsed", "unixzone", "elem", "elemname", "elemvalue", "shared", "localmethod", "poison", "poisoned", "boundmethod", "views", "lookup", "kindptr", "fieldfunc", "fieldeffect", "fieldconst"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, dir, "go.mod", "module example.com/audited\n\ngo 1.26\n")
	writeFile(t, dir, "values/values.go", `package values

import (
	"math/big"
	"math/rand"
	"reflect"
)

var answer = big.NewInt(42)

func Equal() bool {
	return reflect.DeepEqual(big.NewInt(42), answer)
}

func SeededRandLocal() string {
	r := rand.New(rand.NewSource(7))
	return new(big.Int).Rand(r, big.NewInt(int64(100+r.Intn(5)))).String()
}

func Ratio() *big.Rat {
	if reflect.DeepEqual(big.NewRat(1, 2), big.NewFloat(0.5)) {
		return big.NewRat(1, 1)
	}
	return big.NewRat(1, 2)
}

func Indirect() bool {
	mk := big.NewInt
	f, _ := big.NewFloat(2.5).Int(nil)
	return reflect.DeepEqual(mk(2), f)
}

// Arithmetic exercises the package beyond its constructors: the
// whole-package admission covers every operation.
func Arithmetic() string {
	n, _ := new(big.Int).SetString("123456789012345678901234567890", 10)
	n.Exp(n, big.NewInt(3), nil).Mul(n, big.NewInt(7))
	f := new(big.Float).SetPrec(200).SetInt(n)
	f.Sqrt(f)
	r := big.NewRat(22, 7)
	return n.String() + f.Text('g', 30) + r.FloatString(12)
}
`)
	writeFile(t, dir, "values/values_test.go", `package values

import "testing"

func TestValues(t *testing.T) {
	if !Equal() {
		t.Fatal("value comparison")
	}
	_ = Ratio()
}
`)
	// The entropy legs live in packages of their own: the package scan
	// is package-wide, so a math/rand construction anywhere in a package
	// refuses every subject of it — the caller-side refusal the
	// admission relies on — and each leg's reason must be its own.
	writeFile(t, dir, "entropylocal/entropylocal.go", `package entropylocal

import (
	"math/big"
	"math/rand"
)

// RandLocal draws entropy through math/rand's unseeded global generator:
// the ambient entry is refused at the caller, never inside the admitted
// seeded surface.
func RandLocal() string {
	return new(big.Int).Rand(rand.New(rand.NewSource(rand.Int63())), big.NewInt(100)).String()
}
`)
	writeFile(t, dir, "entropylocal/entropylocal_test.go", `package entropylocal

import "testing"

func TestRandLocal(t *testing.T) {
	_ = RandLocal()
}
`)
	writeFile(t, dir, "entropyparam/entropyparam.go", `package entropyparam

import (
	"math/big"
	"math/rand"
)

// RandParam draws through a caller-supplied source: the subject's own
// body reaches no ambient constructor; whoever constructs an unseeded
// source carries the refusal.
func RandParam(r *rand.Rand) string {
	return new(big.Int).Rand(r, big.NewInt(100)).String()
}
`)
	writeFile(t, dir, "entropyparam/entropyparam_test.go", `package entropyparam

import (
	"math/rand"
	"testing"
)

func TestRandParam(t *testing.T) {
	_ = RandParam(rand.New(rand.NewSource(rand.Int63())))
}
`)
	writeFile(t, dir, "calendar/calendar.go", `package calendar

import "time"

type monther interface {
	Month() time.Month
}

func Year() int {
	var t time.Time
	y, m, _ := t.Date()
	var via monther = t
	if m == time.January && m == via.Month() {
		return y
	}
	return y + 1
}
`)
	writeFile(t, dir, "calendar/calendar_test.go", `package calendar

import "testing"

func TestYear(t *testing.T) {
	_ = Year()
}
`)
	writeFile(t, dir, "stamp/stamp.go", `package stamp

import "time"

func Stamp() time.Time {
	return time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
}
`)
	writeFile(t, dir, "stamp/stamp_test.go", `package stamp

import "testing"

func TestStamp(t *testing.T) {
	_ = Stamp()
}
`)
	writeFile(t, dir, "span/span.go", `package span

import "time"

// A closed interface value dispatching a shared-name method reaches
// the enumerated-target arm, the static call the callee arm.
type shifter interface {
	UTC() time.Time
}

// Span computes with fixed arguments only: construction under a fixed
// zone, calendar and duration arithmetic, comparison, formatting, and
// a zone change to another fixed zone.
func Span() string {
	a := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.FixedZone("X", 3600))
	b := a.Add(400*24*time.Hour + 90*time.Minute).Round(time.Minute)
	d := b.Sub(a).Truncate(time.Second)
	if !a.Before(b) || a.Equal(b) || a.Compare(b) >= 0 || a.IsZero() {
		return "order"
	}
	name, offset := b.Zone()
	y, w := b.ISOWeek()
	// The pure methods behind the shared names, admitted by receiver in
	// subject flow.
	c := b.UTC().AddDate(0, 1, 0)
	var via shifter = c
	if !c.After(a) || c.Unix() < a.UnixMilli()/1000 || c.UnixMicro() < 0 || !via.UTC().Equal(c) {
		return "shared"
	}
	return d.String() + b.Format(time.RFC3339) + b.In(time.FixedZone("Y", 0)).Weekday().String() + name + string(rune('0'+offset%10)) + string(rune('0'+(y+w)%10)) + string(b.AppendFormat(nil, time.Kitchen)[0:1]) + d.Abs().String()
}
`)
	writeFile(t, dir, "span/span_test.go", `package span

import "testing"

func TestSpan(t *testing.T) {
	if Span() == "" {
		t.Fatal("span")
	}
}
`)
	writeFile(t, dir, "timer/timer.go", `package timer

import "time"

// Wait reaches the timer channel through the name a pure method
// shares: excluded whole.
func Wait() {
	<-time.After(time.Millisecond)
}
`)
	writeFile(t, dir, "timer/timer_test.go", `package timer

import "testing"

func TestWait(t *testing.T) {
	Wait()
}
`)
	writeFile(t, dir, "parsed/parsed.go", `package parsed

import "time"

// Parsed reaches Parse, which consults Local for zone abbreviations.
func Parsed() time.Time {
	t, _ := time.Parse(time.RFC1123, "Wed, 01 Jan 2020 00:00:00 UTC")
	return t
}
`)
	writeFile(t, dir, "parsed/parsed_test.go", `package parsed

import "testing"

func TestParsed(t *testing.T) {
	_ = Parsed()
}
`)
	writeFile(t, dir, "unixzone/unixzone.go", `package unixzone

import "time"

// Epoch constructs through time.Unix, which installs the LOCAL zone:
// the rendering reads $TZ and the zone database.
func Epoch() string {
	return time.Unix(0, 0).Format(time.RFC3339)
}
`)
	writeFile(t, dir, "unixzone/unixzone_test.go", `package unixzone

import "testing"

func TestEpoch(t *testing.T) {
	_ = Epoch()
}
`)
	writeFile(t, dir, "clock/clock.go", `package clock

import "time"

func Now() time.Time {
	return time.Now()
}
`)
	writeFile(t, dir, "clock/clock_test.go", `package clock

import "testing"

func TestNow(t *testing.T) {
	_ = Now()
}
`)
	writeFile(t, dir, "mirror/mirror.go", `package mirror

import "reflect"

func Mirror(v any) reflect.Value {
	return reflect.ValueOf(v)
}
`)
	writeFile(t, dir, "mirror/mirror_test.go", `package mirror

import "testing"

func TestMirror(t *testing.T) {
	_ = Mirror(1)
}
`)
	// The same methods in startup flow — the field's refusal site —
	// and the ambient method sharing the exclusion's name, which keeps
	// its class, in its own package (the startup walk is package-wide).
	writeFile(t, dir, "shared/shared.go", `package shared

import "time"

var base = time.Date(2020, time.January, 1, 0, 0, 0, 0, time.FixedZone("X", 3600))

var later = base.UTC().AddDate(1, 2, 3)

var facts = []int64{later.Unix(), later.UnixMilli(), later.UnixMicro()}

var ordered = later.After(base)

func Shared() int64 {
	if !ordered {
		return -1
	}
	return facts[0] + facts[1] + facts[2]
}
`)
	writeFile(t, dir, "shared/shared_test.go", `package shared

import "testing"

func TestShared(t *testing.T) {
	_ = Shared()
}
`)
	writeFile(t, dir, "localmethod/localmethod.go", `package localmethod

import "time"

var local = time.Date(2020, time.January, 1, 0, 0, 0, 0, time.FixedZone("X", 3600)).Local()

func Localized() int { return local.Year() }
`)
	writeFile(t, dir, "localmethod/localmethod_test.go", `package localmethod

import "testing"

func TestLocalized(t *testing.T) {
	_ = Localized()
}
`)
	// The soundness of the exported variable's read inside AddDate rests
	// on every spelling of time.UTC refusing wherever it sits: a
	// dependency's init assigning it poisons an otherwise clean subject.
	writeFile(t, dir, "poison/poison.go", `package poison

import "time"

func init() { time.UTC = time.FixedZone("Z", 0) }
`)
	writeFile(t, dir, "poisoned/poisoned.go", `package poisoned

import (
	"time"

	_ "example.com/audited/poison"
)

var later = time.Date(2020, time.January, 1, 0, 0, 0, 0, time.FixedZone("X", 3600)).UTC().AddDate(1, 0, 0)

func Poisoned() int { return later.Year() }
`)
	writeFile(t, dir, "poisoned/poisoned_test.go", `package poisoned

import "testing"

func TestPoisoned(t *testing.T) {
	_ = Poisoned()
}
`)
	// The method value form binds a wrapper declaring the method it
	// delegates to; the enumerated-target arm judges it as that method,
	// its own body never walked.
	writeFile(t, dir, "boundmethod/boundmethod.go", `package boundmethod

import "time"

var base = time.Date(2020, time.January, 1, 0, 0, 0, 0, time.FixedZone("X", 3600))

var normalize = base.UTC

var later = normalize()

func Bound() int { return later.Year() }
`)
	writeFile(t, dir, "boundmethod/boundmethod_test.go", `package boundmethod

import "testing"

func TestBound(t *testing.T) {
	_ = Bound()
}
`)
	// The descriptor-view surface in startup flow: kinds, fields, tags,
	// implements, sizes, names, the Kind constants.
	writeFile(t, dir, "views/views.go", `package views

import "reflect"

type Box struct {
	N int `+"`"+`json:"n"`+"`"+`
	s string
}

var boxType = reflect.TypeOf(Box{})

var errorType = reflect.TypeOf((*error)(nil)).Elem()

var facts = []bool{
	boxType.Kind() == reflect.Struct,
	boxType.NumField() == 2,
	boxType.Field(0).Name == "N",
	boxType.Field(0).Tag.Get("json") == "n",
	boxType.Field(0).Type.Kind() == reflect.Int,
	boxType.Field(1).PkgPath != "",
	boxType.Comparable(),
	!boxType.Implements(errorType),
	boxType.Size() > 0 && boxType.Align() > 0,
	boxType.String() == "views.Box" && boxType.Name() == "Box" && boxType.PkgPath() != "",
	boxType.NumMethod() == 0,
	reflect.TypeOf(make(chan int)).ChanDir() == reflect.BothDir,
	reflect.TypeOf(map[string]int{}).Key().Kind() == reflect.String,
}

func Views() int {
	n := 0
	for _, f := range facts {
		if f {
			n++
		}
	}
	return n
}
`)
	writeFile(t, dir, "views/views_test.go", `package views

import "testing"

func TestViews(t *testing.T) {
	_ = Views()
}
`)
	// The reflective-dispatch channel keeps its refusal by name.
	writeFile(t, dir, "lookup/lookup.go", `package lookup

import "reflect"

type Box struct{ N int }

var method, found = reflect.TypeOf(Box{}).MethodByName("String")

func Lookup() bool { return found && method.Index == 0 }
`)
	writeFile(t, dir, "lookup/lookup_test.go", `package lookup

import "testing"

func TestLookup(t *testing.T) {
	_ = Lookup()
}
`)
	// A Kind constant sharing its name with an address result refuses
	// at the fold like any unaudited name.
	writeFile(t, dir, "kindptr/kindptr.go", `package kindptr

import "reflect"

type Box struct{ N int }

var isPointer = reflect.TypeOf(&Box{}).Kind() == reflect.Pointer

func Pointerish() bool { return isPointer }
`)
	writeFile(t, dir, "kindptr/kindptr_test.go", `package kindptr

import "testing"

func TestPointerish(t *testing.T) {
	_ = Pointerish()
}
`)
	// FieldByNameFunc's callback is resolved by the enumeration at
	// reflect's own match site whether it arrives as a constant or a
	// loaded value (a constant is scanned as an operand besides), so a
	// pure callback admits and a refused method inside one refuses by
	// that method's name on either route.
	writeFile(t, dir, "fieldfunc/fieldfunc.go", `package fieldfunc

import "reflect"

type Box struct{ N int }

var direct, _ = reflect.TypeOf(Box{}).FieldByNameFunc(func(n string) bool { return n == "N" })

var pick = func(n string) bool { return len(n) == 1 }

var loaded, _ = reflect.TypeOf(Box{}).FieldByNameFunc(pick)

func Found() bool { return direct.Name == loaded.Name }
`)
	writeFile(t, dir, "fieldfunc/fieldfunc_test.go", `package fieldfunc

import "testing"

func TestFound(t *testing.T) {
	_ = Found()
}
`)
	writeFile(t, dir, "fieldeffect/fieldeffect.go", `package fieldeffect

import (
	"reflect"
	"time"
)

type Box struct{ N int }

var base = time.Date(2020, time.January, 1, 0, 0, 0, 0, time.FixedZone("X", 3600))

var pick = func(n string) bool { return base.Local().Year() > 0 && n == "N" }

var found, _ = reflect.TypeOf(Box{}).FieldByNameFunc(pick)

func Found() bool { return found.Name == "N" }
`)
	writeFile(t, dir, "fieldeffect/fieldeffect_test.go", `package fieldeffect

import "testing"

func TestFound(t *testing.T) {
	_ = Found()
}
`)
	writeFile(t, dir, "fieldconst/fieldconst.go", `package fieldconst

import (
	"reflect"
	"time"
)

type Box struct{ N int }

var base = time.Date(2020, time.January, 1, 0, 0, 0, 0, time.FixedZone("X", 3600))

var found, _ = reflect.TypeOf(Box{}).FieldByNameFunc(func(n string) bool { return base.Local().Year() > 0 && n == "N" })

func Found() bool { return found.Name == "N" }
`)
	writeFile(t, dir, "fieldconst/fieldconst_test.go", `package fieldconst

import "testing"

func TestFound(t *testing.T) {
	_ = Found()
}
`)
	writeFile(t, dir, "elem/elem.go", `package elem

import "reflect"

type Box struct{ N int }

// The descriptor read in startup flow, its result a runtime-canonical
// reflect.Type the subject compares.
var boxType = reflect.TypeOf(&Box{}).Elem()

func Kind() bool { return boxType == reflect.TypeOf(Box{}) }
`)
	writeFile(t, dir, "elem/elem_test.go", `package elem

import "testing"

func TestElem(t *testing.T) {
	_ = Kind()
}
`)
	// A view method reached through an Elem result in startup flow —
	// its own package, the startup walk being package-wide.
	writeFile(t, dir, "elemname/elemname.go", `package elemname

import "reflect"

type Box struct{ N int }

var boxName = reflect.TypeOf(&Box{}).Elem().Name()

func Named() string { return boxName }
`)
	writeFile(t, dir, "elemname/elemname_test.go", `package elemname

import "testing"

func TestNamed(t *testing.T) {
	_ = Named()
}
`)
	// The Value form is reached only through a producer, whose refusal
	// stands — the reachability tier refuses the unsafe pointer the
	// producer carries before any symbol is judged; in its own package
	// so the refusal reaches no sibling row.
	writeFile(t, dir, "elemvalue/elemvalue.go", `package elemvalue

import "reflect"

type Box struct{ N int }

func Deref() bool {
	b := Box{N: 3}
	return reflect.ValueOf(&b).Elem().CanSet()
}
`)
	writeFile(t, dir, "elemvalue/elemvalue_test.go", `package elemvalue

import "testing"

func TestDeref(t *testing.T) {
	_ = Deref()
}
`)
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{
		{Package: "example.com/audited/values", Symbol: "Equal"},
		{Package: "example.com/audited/values", Symbol: "SeededRandLocal"},
		{Package: "example.com/audited/values", Symbol: "Ratio"},
		{Package: "example.com/audited/values", Symbol: "Indirect"},
		{Package: "example.com/audited/values", Symbol: "Arithmetic"},
		{Package: "example.com/audited/entropylocal", Symbol: "RandLocal"},
		{Package: "example.com/audited/entropyparam", Symbol: "TestRandParam"},
		{Package: "example.com/audited/entropyparam", Symbol: "RandParam"},
		{Package: "example.com/audited/calendar", Symbol: "Year"},
		{Package: "example.com/audited/stamp", Symbol: "Stamp"},
		{Package: "example.com/audited/clock", Symbol: "Now"},
		{Package: "example.com/audited/span", Symbol: "Span"},
		{Package: "example.com/audited/timer", Symbol: "Wait"},
		{Package: "example.com/audited/parsed", Symbol: "Parsed"},
		{Package: "example.com/audited/unixzone", Symbol: "Epoch"},
		{Package: "example.com/audited/mirror", Symbol: "Mirror"},
		{Package: "example.com/audited/elem", Symbol: "Kind"},
		{Package: "example.com/audited/shared", Symbol: "Shared"},
		{Package: "example.com/audited/localmethod", Symbol: "Localized"},
		{Package: "example.com/audited/poisoned", Symbol: "Poisoned"},
		{Package: "example.com/audited/boundmethod", Symbol: "Bound"},
		{Package: "example.com/audited/elemname", Symbol: "Named"},
		{Package: "example.com/audited/views", Symbol: "Views"},
		{Package: "example.com/audited/lookup", Symbol: "Lookup"},
		{Package: "example.com/audited/kindptr", Symbol: "Pointerish"},
		{Package: "example.com/audited/fieldfunc", Symbol: "Found"},
		{Package: "example.com/audited/fieldeffect", Symbol: "Found"},
		{Package: "example.com/audited/fieldconst", Symbol: "Found"},
		{Package: "example.com/audited/elemvalue", Symbol: "Deref"},
	})
	if err != nil {
		t.Fatal(err)
	}
	equal := proofs[Subject{Package: "example.com/audited/values", Symbol: "Equal"}]
	if !equal.Observable {
		t.Fatalf("Equal = %+v, want the constructor/comparator subject observable", equal)
	}
	seededRand := proofs[Subject{Package: "example.com/audited/values", Symbol: "SeededRandLocal"}]
	if !seededRand.Observable {
		t.Fatalf("SeededRandLocal = %+v, want a deterministic constant-seeded local *rand.Rand observable", seededRand)
	}
	ratio := proofs[Subject{Package: "example.com/audited/values", Symbol: "Ratio"}]
	if !ratio.Observable {
		t.Fatalf("Ratio = %+v, want the constructed-type reference observable", ratio)
	}
	arithmetic := proofs[Subject{Package: "example.com/audited/values", Symbol: "Arithmetic"}]
	if !arithmetic.Observable {
		t.Fatalf("math/big arithmetic subject unobservable: %+v", arithmetic)
	}
	// Entropy enters through math/rand's constructor at the caller,
	// never through the admitted package: the subject constructing its
	// own source refuses on that construction, and so does the test
	// constructing the source it feeds to the parameter-taking subject
	// (its own package's source carries the construction). The bare
	// parameter-taking subject, judged alone, refuses on its open
	// world — a *rand.Rand it never constructs is a value it cannot
	// close over — not on the entropy bar; both directions fail closed.
	for _, tc := range []struct{ pkg, symbol, reason string }{
		{"example.com/audited/entropylocal", "RandLocal", "math/rand"},
		{"example.com/audited/entropyparam", "TestRandParam", "math/rand"},
		{"example.com/audited/entropyparam", "RandParam", "reachability is not closed"},
	} {
		proof := proofs[Subject{Package: tc.pkg, Symbol: tc.symbol}]
		if proof.Observable || !strings.Contains(proof.Reason, tc.reason) {
			t.Fatalf("%s.%s = %+v, want refused naming %q", tc.pkg, tc.symbol, proof, tc.reason)
		}
	}
	indirect := proofs[Subject{Package: "example.com/audited/values", Symbol: "Indirect"}]
	if !indirect.Observable {
		t.Fatalf("Indirect = %+v, want the admission holding for a locally closed dynamic target and a same-named pure method", indirect)
	}
	year := proofs[Subject{Package: "example.com/audited/calendar", Symbol: "Year"}]
	if !year.Observable {
		t.Fatalf("Year = %+v, want the calendar decomposition observable", year)
	}
	stamp := proofs[Subject{Package: "example.com/audited/stamp", Symbol: "Stamp"}]
	if stamp.Observable || !strings.Contains(stamp.Reason, "time.UTC") {
		t.Fatalf("Stamp = %+v, want the refusal naming the Location global - the ambient timezone channel, not the calendar arithmetic", stamp)
	}
	bound := proofs[Subject{Package: "example.com/audited/boundmethod", Symbol: "Bound"}]
	if !bound.Observable || bound.Reason != "" {
		t.Fatalf("Bound = %+v, want the method value admitted as the method its wrapper declares", bound)
	}
	poisoned := proofs[Subject{Package: "example.com/audited/poisoned", Symbol: "Poisoned"}]
	if poisoned.Observable || !strings.Contains(poisoned.Reason, "package scan: reaches unaudited standard operation time.UTC") {
		t.Fatalf("Poisoned = %+v, want the dependency's assignment to time.UTC refusing the clean subject", poisoned)
	}
	span := proofs[Subject{Package: "example.com/audited/span", Symbol: "Span"}]
	if !span.Observable {
		t.Fatalf("fixed-argument time subject unobservable: %+v", span)
	}
	// Each ambient reach refuses in its own package, naming itself:
	// the timer channel, Parse, and the Unix constructor that installs
	// the local zone on the value it builds.
	for _, tc := range []struct{ pkg, symbol, reach string }{
		{"example.com/audited/timer", "Wait", "time.After"},
		{"example.com/audited/parsed", "Parsed", "time.Parse"},
		{"example.com/audited/unixzone", "Epoch", "time.Unix"},
	} {
		proof := proofs[Subject{Package: tc.pkg, Symbol: tc.symbol}]
		if proof.Observable || !strings.Contains(proof.Reason, tc.reach) {
			t.Fatalf("%s.%s = %+v, want refused naming %s", tc.pkg, tc.symbol, proof, tc.reach)
		}
	}
	now := proofs[Subject{Package: "example.com/audited/clock", Symbol: "Now"}]
	if now.Observable || !strings.Contains(now.Reason, "time.Now") {
		t.Fatalf("Now = %+v, want the ambient clock read refused by name", now)
	}
	mirror := proofs[Subject{Package: "example.com/audited/mirror", Symbol: "Mirror"}]
	if mirror.Observable || mirror.Reason == "" {
		t.Fatalf("Mirror = %+v, want reflective value dispatch refused - the comparator admission must not open reflect", mirror)
	}
	shared := proofs[Subject{Package: "example.com/audited/shared", Symbol: "Shared"}]
	if !shared.Observable || shared.Reason != "" {
		t.Fatalf("Shared = %+v, want the receiver-qualified time methods admitted in startup flow", shared)
	}
	localized := proofs[Subject{Package: "example.com/audited/localmethod", Symbol: "Localized"}]
	if localized.Observable || !strings.Contains(localized.Reason, "time.Local") {
		t.Fatalf("Localized = %+v, want (Time).Local refused by name — it installs the ambient zone", localized)
	}
	kind := proofs[Subject{Package: "example.com/audited/elem", Symbol: "Kind"}]
	if !kind.Observable || kind.Reason != "" {
		t.Fatalf("Kind = %+v, want (Type).Elem admitted in startup flow", kind)
	}
	named := proofs[Subject{Package: "example.com/audited/elemname", Symbol: "Named"}]
	if !named.Observable || named.Reason != "" {
		t.Fatalf("Named = %+v, want the view method admitted with the descriptor surface", named)
	}
	views := proofs[Subject{Package: "example.com/audited/views", Symbol: "Views"}]
	if !views.Observable || views.Reason != "" {
		t.Fatalf("Views = %+v, want the descriptor-view surface admitted in startup flow", views)
	}
	lookup := proofs[Subject{Package: "example.com/audited/lookup", Symbol: "Lookup"}]
	if lookup.Observable || !strings.Contains(lookup.Reason, "startup effect: reaches unaudited standard operation reflect.MethodByName") {
		t.Fatalf("Lookup = %+v, want the reflective-dispatch channel refused by name", lookup)
	}
	fieldfunc := proofs[Subject{Package: "example.com/audited/fieldfunc", Symbol: "Found"}]
	if !fieldfunc.Observable || fieldfunc.Reason != "" {
		t.Fatalf("fieldfunc = %+v, want FieldByNameFunc admitted with a pure callback, constant and loaded", fieldfunc)
	}
	fieldeffect := proofs[Subject{Package: "example.com/audited/fieldeffect", Symbol: "Found"}]
	if fieldeffect.Observable || !strings.Contains(fieldeffect.Reason, "startup effect: reaches unaudited standard operation time.Local") {
		t.Fatalf("fieldeffect = %+v, want the loaded callback's body classified — its refused method named", fieldeffect)
	}
	fieldconst := proofs[Subject{Package: "example.com/audited/fieldconst", Symbol: "Found"}]
	if fieldconst.Observable || !strings.Contains(fieldconst.Reason, "startup effect: reaches unaudited standard operation time.Local") {
		t.Fatalf("fieldconst = %+v, want the constant callback's body classified — its refused method named", fieldconst)
	}
	pointerish := proofs[Subject{Package: "example.com/audited/kindptr", Symbol: "Pointerish"}]
	if pointerish.Observable || !strings.Contains(pointerish.Reason, "package scan: reaches unaudited standard operation reflect.Pointer") {
		t.Fatalf("Pointerish = %+v, want the address-sharing Kind constant refused at the fold", pointerish)
	}
	deref := proofs[Subject{Package: "example.com/audited/elemvalue", Symbol: "Deref"}]
	if deref.Observable || !strings.Contains(deref.Reason, "unsafe pointer reachable") {
		t.Fatalf("Deref = %+v, want the Value producer's reachability refusal, never Elem's", deref)
	}
}

// The admission sets are exactly the audited names: constructors and
// execution-free references in, every ambient or reflective neighbor
// out (REQ-closure-observability-audited-set).
func TestAuditedPureStandardBounds(t *testing.T) {
	t.Parallel()
	// math/big is a member of the audited-pure package set, admitted
	// whole there and not operation by operation here.
	if !isSourceOnlyStandardPackage(true, "math/big") || isSourceOnlyStandardPackage(false, "math/big") {
		t.Error("math/big membership: want admitted on an audited toolchain only")
	}
	for _, tc := range []struct{ pkg, name string }{
		{"flag", "NewFlagSet"}, {"flag", "CommandLine"}, {"flag", "FlagSet"}, {"flag", "Flag"}, {"flag", "Value"},
		{"flag", "Getter"}, {"flag", "ErrorHandling"}, {"flag", "ContinueOnError"}, {"flag", "ExitOnError"}, {"flag", "PanicOnError"},
		{"net/url", "QueryEscape"}, {"net/url", "QueryUnescape"}, {"net/url", "PathEscape"}, {"net/url", "PathUnescape"},
		{"net/url", "User"}, {"net/url", "UserPassword"}, {"net/url", "URL"}, {"net/url", "Values"}, {"net/url", "Userinfo"},
		{"net/url", "String"}, {"net/url", "EscapedPath"}, {"net/url", "ResolveReference"}, {"net/url", "Hostname"},
		{"net/url", "Port"}, {"net/url", "Encode"}, {"net/url", "Get"}, {"net/url", "Set"}, {"net/url", "MarshalBinary"},
		{"net/url", "Username"}, {"net/url", "Password"}, {"net/url", "EscapedFragment"}, {"net/url", "Redacted"},
		{"net/url", "IsAbs"}, {"net/url", "RequestURI"}, {"net/url", "AppendBinary"}, {"net/url", "Clone"},
		{"net/url", "Add"}, {"net/url", "Del"}, {"net/url", "Has"}, {"net/url", "Unwrap"}, {"net/url", "Timeout"},
		{"net/url", "Temporary"}, {"net/url", "Error"}, {"net/url", "EscapeError"}, {"net/url", "InvalidHostError"},
		{"path/filepath", "Clean"}, {"path/filepath", "IsLocal"}, {"path/filepath", "Localize"},
		{"path/filepath", "ToSlash"}, {"path/filepath", "FromSlash"}, {"path/filepath", "SplitList"},
		{"path/filepath", "Split"}, {"path/filepath", "Join"}, {"path/filepath", "Ext"},
		{"path/filepath", "IsAbs"}, {"path/filepath", "Rel"}, {"path/filepath", "Base"},
		{"path/filepath", "Dir"}, {"path/filepath", "VolumeName"}, {"path/filepath", "Match"}, {"path/filepath", "HasPrefix"},
		{"path/filepath", "Separator"}, {"path/filepath", "ListSeparator"}, {"path/filepath", "WalkFunc"},
		{"time", "Date"}, {"time", "Time"}, {"time", "Month"},
		{"time", "January"}, {"time", "February"}, {"time", "March"},
		{"time", "April"}, {"time", "May"}, {"time", "June"},
		{"time", "July"}, {"time", "August"}, {"time", "September"},
		{"time", "October"}, {"time", "November"}, {"time", "December"},
		{"time", "Add"}, {"time", "Sub"}, {"time", "Before"}, {"time", "Equal"}, {"time", "Compare"}, {"time", "IsZero"},
		{"time", "Format"}, {"time", "AppendFormat"}, {"time", "String"}, {"time", "Truncate"}, {"time", "Round"},
		{"time", "In"}, {"time", "Zone"}, {"time", "ZoneBounds"}, {"time", "Weekday"}, {"time", "Sunday"}, {"time", "Saturday"},
		{"time", "Year"}, {"time", "Day"}, {"time", "YearDay"}, {"time", "ISOWeek"}, {"time", "Clock"},
		{"time", "Second"}, {"time", "Minute"}, {"time", "Hour"}, {"time", "Nanosecond"}, {"time", "Microsecond"}, {"time", "Millisecond"},
		{"time", "UnixNano"}, {"time", "FixedZone"}, {"time", "ParseDuration"},
		{"time", "Duration"}, {"time", "Hours"}, {"time", "Minutes"}, {"time", "Seconds"}, {"time", "Milliseconds"}, {"time", "Microseconds"}, {"time", "Nanoseconds"}, {"time", "Abs"},
		{"time", "Layout"}, {"time", "ANSIC"}, {"time", "RFC3339"}, {"time", "RFC3339Nano"}, {"time", "Kitchen"}, {"time", "DateOnly"}, {"time", "TimeOnly"}, {"time", "DateTime"}, {"time", "StampNano"},
		{"fmt", "Stringer"}, {"fmt", "Sprint"},
	} {
		if !classBPureStandard(true, tc.pkg, tc.name) {
			t.Errorf("classBPureStandard(true, %s, %s) = false, want audited", tc.pkg, tc.name)
		}
	}
	for _, name := range auditset.FlagNonAuditedNames() {
		if classBPureStandard(true, "flag", name) {
			t.Errorf("classBPureStandard(true, flag, %s) = true, want outside the audited set", name)
		}
	}
	for _, tc := range []struct{ pkg, name string }{
		{"net/url", "Parse"}, {"net/url", "ParseRequestURI"}, {"net/url", "ParseQuery"}, {"net/url", "Query"},
		{"net/url", "JoinPath"}, {"net/url", "UnmarshalBinary"},
		{"path/filepath", "Abs"}, {"path/filepath", "EvalSymlinks"}, {"path/filepath", "Glob"},
		{"path/filepath", "Walk"}, {"path/filepath", "WalkDir"}, {"path/filepath", "ErrBadPattern"},
		{"path/filepath", "SkipDir"}, {"path/filepath", "SkipAll"},
		{"time", "Now"}, {"time", "UTC"}, {"time", "Local"},
		{"time", "LoadLocation"}, {"time", "LoadLocationFromTZData"}, {"time", "Since"}, {"time", "Until"},
		// A name shared by a pure declaration and an ambient one is
		// excluded whole: After (the timer channel), the Unix constructors
		// (they install the local zone), Location (the method returns the
		// time.UTC variable), AddDate (re-enters Date through it) — the
		// bare names; the audited method forms admit by receiver in
		// timeMethods, Location's (a pointer into package time's own
		// state) and Local's (the ambient zone) among the refused.
		{"time", "After"}, {"time", "Unix"}, {"time", "UnixMilli"}, {"time", "UnixMicro"}, {"time", "Location"}, {"time", "AddDate"},
		{"time", "AfterFunc"}, {"time", "Sleep"}, {"time", "Tick"},
		{"time", "NewTimer"}, {"time", "NewTicker"}, {"time", "Parse"}, {"time", "ParseInLocation"},
		{"time", "Reset"}, {"time", "Stop"},
		{"math/big", "NewInt"}, {"math/big", "Int"},
		{"fmt", "State"}, {"fmt", "Print"}, {"fmt", "Formatter"},
	} {
		if classBPureStandard(true, tc.pkg, tc.name) {
			t.Errorf("classBPureStandard(true, %s, %s) = true, want outside the audited set", tc.pkg, tc.name)
		}
	}
	if !classBPureStandard(true, "reflect", "DeepEqual") {
		t.Error("classBPureStandard(true, reflect, DeepEqual) = false, want the invoke-nothing comparator audited")
	}
	for _, name := range []string{"ValueOf", "Value", "New", "MakeFunc", "Indirect", "Set", "SetInt", "Interface", "Index", "Method", "MethodByName", "Call", "Pointer", "UnsafePointer", "Ptr", "Slice", "Key"} {
		if classBPureStandard(true, "reflect", name) {
			t.Errorf("classBPureStandard(true, reflect, %s) = true, want reflect closed beyond its invoke-nothing members", name)
		}
	}
	if classBPureStandard(true, "example.com/big", "NewInt") || classBPureStandard(true, "example.com/reflect", "DeepEqual") {
		t.Error("an admission leaked to a non-standard package path")
	}
}

// The harness failure/logging channel is exactly the output-only method
// list; the harness's ambient-input and mutation surfaces and its
// structural operations stay outside it
// (REQ-closure-observability-harness-logging).
func TestAuditedHarnessLoggingBounds(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"Fatal", "Fatalf", "Error", "Errorf", "Log", "Logf", "Skip", "Skipf", "SkipNow", "Fail", "FailNow"} {
		if !auditedHarnessLogging(true, "testing", name) {
			t.Errorf("auditedHarnessLogging(true, testing, %s) = false, want audited", name)
		}
	}
	for _, name := range []string{"Setenv", "Chdir", "TempDir", "Run", "Cleanup", "Helper", "Short", "Deadline", "Context", "Parallel", "Name", "Failed", "Skipped"} {
		if auditedHarnessLogging(true, "testing", name) {
			t.Errorf("auditedHarnessLogging(true, testing, %s) = true, want outside the audited set", name)
		}
	}
	if auditedHarnessLogging(true, "os", "Fatal") || auditedHarnessLogging(true, "log", "Fatal") {
		t.Error("auditedHarnessLogging admits a non-testing package")
	}
}

// A subject whose only reachable effect is the audited harness channel
// earns the observation proof yet stays unverifiable in the legacy
// projection: the admission is observation evidence, never purity
// evidence.
func TestHarnessLoggingIsNotPurityEvidence(t *testing.T) {
	t.Parallel()
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	fixtures := newFixturePrograms(t, h)
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/harnesslog"
	fixtures.supply(t, pkg)
	result, err := computeTier2Result(h, pkg, "TestLogOnly")
	if err != nil {
		t.Fatal(err)
	}
	if !result.unverifiable {
		t.Fatal("harness-logging-only subject reports verifiable in the legacy projection")
	}
	if !strings.Contains(result.reason, "test harness logging") {
		t.Fatalf("legacy reason = %q, want the harness-logging classification", result.reason)
	}
	found := false
	for _, effect := range result.effects {
		if effect.packagePath == "testing" && effect.symbol == "Log" {
			found = true
			if !effect.observable {
				t.Fatal("audited harness fact recorded as blocking")
			}
		}
	}
	if !found {
		t.Fatalf("effects = %+v, want the recorded testing.Log harness fact", result.effects)
	}
	// A subject mixing the harness channel with a causal effect must keep
	// the causal reason in the legacy projection: the harness fact ranks
	// below every other classification.
	fixtures.supply(t, pkg)
	mixed, err := computeTier2Result(h, pkg, "TestReadFileFatal")
	if err != nil {
		t.Fatal(err)
	}
	if !mixed.unverifiable || !strings.Contains(mixed.reason, "file I/O") {
		t.Fatalf("mixed-effect legacy reason = %q, want the file I/O cause over harness logging", mixed.reason)
	}
	// A weakest-rank sibling (the ambient clock's unaudited-standard read)
	// must also win: the harness fact is strictly weakest, never a tie it
	// can take lexicographically.
	fixtures.supply(t, "github.com/greatliontech/gofresh/internal/closure/testdata/harnessclock")
	sibling, err := computeTier2Result(h, "github.com/greatliontech/gofresh/internal/closure/testdata/harnessclock", "TestLogAmbientClock")
	if err != nil {
		t.Fatal(err)
	}
	if !sibling.unverifiable || !strings.Contains(sibling.reason, "unaudited standard operation") {
		t.Fatalf("rank-sibling legacy reason = %q, want the unaudited-standard cause over harness logging", sibling.reason)
	}
}

// The harness-channel admission is sound only while every testing-package
// declaration of an audited name is the harness's shared embedded core or
// an outcome-only delegate to it. This walks the toolchain's actual
// declarations, so a drifting toolchain fails here instead of silently
// widening the admission (REQ-closure-observability-harness-logging).
func TestHarnessLoggingDeclarationInventory(t *testing.T) {
	t.Parallel()
	// Source mode is load-bearing: export data materializes only the
	// exported surface, and the admission must refuse an audited-name
	// method on an unexported body-local type too.
	testingPkg := testenv.CachedStdlibPackage(t, os.Environ(), "testing")
	if testingPkg == nil || testingPkg.Types == nil {
		t.Fatal("loaded nil testing package or types")
	}
	if len(testingPkg.Syntax) == 0 {
		t.Fatal("testing loaded without syntax — the inventory no longer type-checks from source and cannot see unexported declarations")
	}
	audited := map[string]bool{}
	for _, name := range []string{"Fatal", "Fatalf", "Error", "Errorf", "Log", "Logf", "Skip", "Skipf", "SkipNow", "Fail", "FailNow"} {
		audited[name] = true
	}
	scope := testingPkg.Types.Scope()
	for _, typeName := range scope.Names() {
		object := scope.Lookup(typeName)
		if _, isFunc := object.(*types.Func); isFunc && audited[object.Name()] {
			// The classifier matches by package and symbol name alone, so a
			// package-level function declaration would be admitted too.
			t.Errorf("testing declares audited harness name %s as a package-level function — re-audit the harness-logging channel before trusting this toolchain", object.Name())
			continue
		}
		named, ok := object.Type().(*types.Named)
		if !ok {
			continue
		}
		for i := 0; i < named.NumMethods(); i++ {
			method := named.Method(i)
			if !audited[method.Name()] || typeName == "common" {
				continue
			}
			if typeName == "F" && method.Name() == "Fail" {
				// Audited by hand: an outcome-only misuse panic delegating
				// to the shared core (the spec's recorded exception).
				continue
			}
			t.Errorf("testing.%s declares audited harness name %s outside the shared core — re-audit the harness-logging channel before trusting this toolchain", typeName, method.Name())
		}
	}
	if scope.Lookup("common") == nil {
		t.Error("testing package no longer declares the shared embedded core type this audit assumes — re-audit the harness-logging channel")
	}
}

// The subtest-driver admission is sound only while the driver names are
// declared exactly where the audit looked: Run as a method of T, B, and
// M alone (T and B admitted, M the test-main driver the receiver check
// excludes), Fuzz as a method of F alone (never admitted - reflective
// dispatch over corpus files), and neither as a package-level function.
// A drifting toolchain fails here instead of silently widening
// (REQ-closure-observability-subtest-driver).
func TestHarnessSubtestDriverDeclarationInventory(t *testing.T) {
	t.Parallel()
	testingPkg := testenv.CachedStdlibPackage(t, os.Environ(), "testing")
	if testingPkg == nil || testingPkg.Types == nil {
		t.Fatal("loaded nil testing package or types")
	}
	if len(testingPkg.Syntax) == 0 {
		t.Fatal("testing loaded without syntax — the inventory no longer type-checks from source and cannot see unexported declarations")
	}
	allowedRun := map[string]bool{"T": true, "B": true, "M": true}
	scope := testingPkg.Types.Scope()
	for _, typeName := range scope.Names() {
		object := scope.Lookup(typeName)
		if _, isFunc := object.(*types.Func); isFunc && (object.Name() == "Run" || object.Name() == "Fuzz") {
			t.Errorf("testing declares driver name %s as a package-level function — re-audit the subtest-driver channel before trusting this toolchain", object.Name())
			continue
		}
		named, ok := object.Type().(*types.Named)
		if !ok {
			continue
		}
		for i := 0; i < named.NumMethods(); i++ {
			method := named.Method(i)
			switch method.Name() {
			case "Run":
				if !allowedRun[typeName] {
					t.Errorf("testing.%s declares driver name Run outside the audited receivers — re-audit the subtest-driver channel before trusting this toolchain", typeName)
				}
			case "Fuzz":
				if typeName != "F" {
					t.Errorf("testing.%s declares driver name Fuzz outside *testing.F — re-audit the subtest-driver channel before trusting this toolchain", typeName)
				}
			}
		}
	}
	for _, typeName := range scope.Names() {
		object := scope.Lookup(typeName)
		iface, ok := object.Type().Underlying().(*types.Interface)
		if !ok {
			continue
		}
		for i := 0; i < iface.NumExplicitMethods(); i++ {
			if name := iface.ExplicitMethod(i).Name(); name == "Run" || name == "Fuzz" {
				t.Errorf("testing interface %s declares driver name %s — re-audit the subtest-driver channel before trusting this toolchain", typeName, name)
			}
		}
	}
	for _, want := range []string{"T", "B", "M", "F"} {
		if scope.Lookup(want) == nil {
			t.Errorf("testing package no longer declares %s — the subtest-driver audit assumes the harness type family", want)
		}
	}
}

// The audited linkname-target floor: a file whose every //go:linkname
// is the two-argument pull form naming an audited target drops exactly
// the opaque-linkage effect; one-argument forms, unaudited targets, and
// mixed files keep the fail-closed floor
// (REQ-closure-blindspot's resolved disposition at the file-scan floor).
func TestAuditedLinknameFloorBounds(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		text string
		want bool
	}{
		"audited pull form": {"//go:linkname runtime_getAuxv runtime.getAuxv\n", true},
		"all three audited": {"//go:linkname a runtime.getAuxv\n//go:linkname b runtime.vgetrandom\n//go:linkname c syscall.prlimit\n", true},
		"no linkname":       {"package x\n", true},
		"one-argument form": {"//go:linkname exported\n", false},
		"unaudited target":  {"//go:linkname a runtime.rand\n", false},
		"mixed":             {"//go:linkname a runtime.getAuxv\n//go:linkname b runtime.rand\n", false},
		"unparsable":        {"//go:linkname\n", false},
		// Text-scan occurrences outside real directives stay fail-safe:
		// a string literal's closing quote and a block comment's
		// terminator stick to the parsed target token, so neither can
		// match an audited target — the floor is kept (a spurious
		// floor, never a lost one).
		"string literal unaudited": {"var s = \"//go:linkname a runtime.rand\"\n", false},
		"block comment unaudited":  {"/* //go:linkname a runtime.rand */\n", false},
		"string literal audited":   {"var s = \"//go:linkname a runtime.getAuxv\"\n", false},
		// go1.27's std-sanctioned spelling shares the grammar and the
		// policy; the directive name matches as a whole field, so a
		// one-argument linknamestd export marker can never parse as a
		// two-argument linkname pull — the fail-open shape a prefix
		// match would admit when the marker's bare name collides with
		// an audited target.
		"linknamestd audited pull":        {"//go:linknamestd a runtime.getAuxv\n", true},
		"linknamestd one-argument form":   {"//go:linknamestd exported\n", false},
		"linknamestd audited-name marker": {"//go:linknamestd runtime.getAuxv\n", false},
		"linknamestd unaudited target":    {"//go:linknamestd a runtime.rand\n", false},
		"unknown directive suffix":        {"//go:linknamex a runtime.getAuxv\n", false},
	} {
		if got := auditedLinknamesOnly(true, tc.text); got != tc.want {
			t.Errorf("%s: auditedLinknamesOnly = %v, want %v", name, got, tc.want)
		}
	}
}

// A false audit verdict — an unlisted surface or an unaudited build
// selection, resolved once per analysis at the Hasher's construction —
// keeps every toolchain-source admission's ordinary fail-closed
// classification: the direction that makes an unaudited stdlib refuse
// instead of silently inheriting a stale proof.
func TestUnauditedToolchainDropsAdmissions(t *testing.T) {
	t.Parallel()
	if classBPureStandard(false, "fmt", "Sprint") {
		t.Error("classBPureStandard admits fmt.Sprint on an unaudited toolchain")
	}
	if isSourceOnlyStandardPackage(false, "strings") || isSourceOnlyStandardPackage(false, "math/big") {
		t.Error("isSourceOnlyStandardPackage admits strings or math/big on an unaudited toolchain")
	}
	if auditedStandardSymbol(false, "sync", "Lock") {
		t.Error("auditedStandardSymbol admits sync.Lock on an unaudited toolchain")
	}
	if auditedStandardSymbol(false, "sync", "Get") {
		t.Error("auditedStandardSymbol admits sync.Get on an unaudited toolchain")
	}
	if classBPureStandard(false, "reflect", "TypeOf") {
		t.Error("classBPureStandard admits reflect.TypeOf on an unaudited toolchain")
	}
	if auditedHarnessLogging(false, "testing", "Fatal") {
		t.Error("auditedHarnessLogging admits testing.Fatal on an unaudited toolchain")
	}
	if fmtFprintFamily(false, "fmt", "Fprintf") {
		t.Error("fmtFprintFamily admits fmt.Fprintf on an unaudited toolchain")
	}
	if auditedLinknamesOnly(false, "//go:linkname a runtime.getAuxv\n") {
		t.Error("auditedLinknamesOnly drops the opaque-linkage floor on an unaudited toolchain")
	}
	atomicPkg := types.NewPackage("sync/atomic", "atomic")
	tparam := types.NewTypeParam(types.NewTypeName(token.NoPos, atomicPkg, "T", nil), types.NewInterfaceType(nil, nil))
	generic := types.NewNamed(types.NewTypeName(token.NoPos, atomicPkg, "Pointer", nil), types.NewStruct(nil, nil), nil)
	generic.SetTypeParams([]*types.TypeParam{tparam})
	inst, err := types.Instantiate(nil, generic, []types.Type{types.Typ[types.Int]}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := auditedAtomicPointerElem(false, inst.(*types.Named)); ok {
		t.Error("auditedAtomicPointerElem admits sync/atomic.Pointer on an unaudited toolchain")
	}
	if driver := harnessSubtestDriverForTest(t); auditedHarnessSubtestDriver(false, driver) {
		t.Error("auditedHarnessSubtestDriver admits (*T).Run on an unaudited toolchain")
	}
}

// The drops test's probes are non-vacuous only if the fakes are
// admitted on the audited toolchain; this companion pins that half so
// the drop assertions cannot rot into always-false trivia.
func TestAuditedToolchainAdmitsTheDropFakes(t *testing.T) {
	t.Parallel()
	if !auditedLinknamesOnly(true, "//go:linkname a runtime.getAuxv\n") {
		t.Error("the audited-pull linkname line is not admitted on the audited toolchain")
	}
	atomicPkg := types.NewPackage("sync/atomic", "atomic")
	tparam := types.NewTypeParam(types.NewTypeName(token.NoPos, atomicPkg, "T", nil), types.NewInterfaceType(nil, nil))
	generic := types.NewNamed(types.NewTypeName(token.NoPos, atomicPkg, "Pointer", nil), types.NewStruct(nil, nil), nil)
	generic.SetTypeParams([]*types.TypeParam{tparam})
	inst, err := types.Instantiate(nil, generic, []types.Type{types.Typ[types.Int]}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := auditedAtomicPointerElem(true, inst.(*types.Named)); !ok {
		t.Error("the instantiated atomic.Pointer fake is not admitted on the audited toolchain")
	}
	if !auditedHarnessSubtestDriver(true, harnessSubtestDriverForTest(t)) {
		t.Error("the mini-SSA (*T).Run is not admitted on the audited toolchain")
	}
}

// harnessSubtestDriverForTest builds a minimal SSA (*T).Run in a
// package named and pathed "testing" — the smallest value the driver
// predicate's shape checks accept.
func harnessSubtestDriverForTest(t testing.TB) *ssa.Function {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "testing.go", `package testing

type T struct{}

func (t *T) Run(name string, f func(*T)) bool { return true }
`, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg := types.NewPackage("testing", "testing")
	ssaPkg, _, err := ssautil.BuildPackage(&types.Config{}, fset, pkg, []*ast.File{file}, ssa.SanityCheckFunctions)
	if err != nil {
		t.Fatal(err)
	}
	tType := ssaPkg.Type("T").Type()
	sel := ssaPkg.Prog.MethodSets.MethodSet(types.NewPointer(tType)).Lookup(pkg, "Run")
	if sel == nil {
		t.Fatal("no (*T).Run in the mini testing package")
	}
	fn := ssaPkg.Prog.MethodValue(sel)
	if fn == nil {
		t.Fatal("no SSA function for (*T).Run")
	}
	return fn
}

// net/url's escaping and composition are admitted by symbol — outside
// the always-external net tree, never as a whole package — while every
// operation reaching its GODEBUG settings refuses naming itself;
// path/filepath's lexical operations are admitted by symbol while its
// filesystem reaches and its error variables refuse naming themselves
// (REQ-closure-observability-audited-set).
func TestNetURLAndFilepathAdmissions(t *testing.T) {
	t.Parallel()
	if isSourceOnlyStandardPackage(true, "net/url") || isAlwaysExternalPackage("net/url") || !isAlwaysExternalPackage("net/http") || !isAlwaysExternalPackage("net") {
		t.Fatal("net/url membership: want by symbol only, outside the always-external net tree, the tree itself unchanged")
	}
	// A package admitted by symbol is never always-external: the
	// admission at the selector ladder would otherwise override the
	// tree's classification with no test failing.
	for _, pkgPath := range auditset.SymbolPackages() {
		if isAlwaysExternalPackage(pkgPath) || isSourceOnlyStandardPackage(true, pkgPath) {
			t.Fatalf("%s is admitted by symbol and classified whole", pkgPath)
		}
	}
	dir := t.TempDir()
	for _, sub := range []string{"urlhost", "urlvalues", "lexical", "absolute", "walking", "linking", "globbing", "walkfn", "badpattern", "viaglobal", "sentineleof", "mutatedeof"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, dir, "go.mod", "module example.com/pathaudit\n\ngo 1.26\n")
	writeFile(t, dir, "urlhost/urlhost.go", `package urlhost

import "net/url"

func Host(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("k", url.QueryEscape("v w"))
	return u.Host + "?" + q.Encode()
}
`)
	writeFile(t, dir, "urlvalues/urlvalues.go", `package urlvalues

import "net/url"

func Compose(host, k, v string) string {
	q := url.Values{}
	q.Set(k, url.QueryEscape(v))
	u := url.URL{Scheme: "https", Host: host, Path: url.PathEscape("a b"), RawQuery: q.Encode(), User: url.UserPassword("u", "p")}
	return u.Redacted() + " " + u.Hostname() + ":" + u.Port()
}
`)
	writeFile(t, dir, "linking/linking.go", `package linking

import "path/filepath"

func Real(p string) string {
	r, _ := filepath.EvalSymlinks(p)
	return r
}
`)
	writeFile(t, dir, "globbing/globbing.go", `package globbing

import "path/filepath"

func Count(pattern string) int {
	m, _ := filepath.Glob(pattern)
	return len(m)
}
`)
	writeFile(t, dir, "walkfn/walkfn.go", `package walkfn

import (
	"io/fs"
	"path/filepath"
)

func Count(root string) int {
	n := 0
	var visit filepath.WalkFunc = func(string, fs.FileInfo, error) error { n++; return nil }
	_ = filepath.Walk(root, visit)
	return n
}
`)
	// The file fold admits a selector of a package admitted whole, so
	// the walk's standard-global arm is the sole guard of such a
	// package's exported variables outside the unmutated sentinel-global
	// set — encoding/base64.StdEncoding's shape.
	writeFile(t, dir, "viaglobal/viaglobal.go", `package viaglobal

import "encoding/base64"

func Ended() bool { return base64.StdEncoding != nil }
`)
	writeFile(t, dir, "sentineleof/sentineleof.go", `package sentineleof

import "io"

func Ended() bool { return io.EOF != nil }
`)
	writeFile(t, dir, "mutatedeof/mutatedeof.go", `package mutatedeof

import "io"

func Clobber() bool {
	io.EOF = nil
	return io.EOF != nil
}
`)
	writeFile(t, dir, "badpattern/badpattern.go", `package badpattern

import "path/filepath"

func Bad(pattern string) bool {
	_, err := filepath.Match(pattern, "x")
	return err == filepath.ErrBadPattern
}
`)
	writeFile(t, dir, "lexical/lexical.go", `package lexical

import "path/filepath"

func Stem(p string) string {
	base := filepath.Base(filepath.Clean(p))
	ok, _ := filepath.Match("*.go", base)
	if !ok {
		return filepath.Join(filepath.Dir(p), base)
	}
	return base[:len(base)-len(filepath.Ext(base))] + string(filepath.Separator)
}
`)
	writeFile(t, dir, "absolute/absolute.go", `package absolute

import "path/filepath"

func Abs(p string) string {
	a, _ := filepath.Abs(p)
	return a
}
`)
	writeFile(t, dir, "walking/walking.go", `package walking

import (
	"io/fs"
	"path/filepath"
)

func Count(root string) int {
	n := 0
	_ = filepath.WalkDir(root, func(string, fs.DirEntry, error) error { n++; return nil })
	return n
}
`)
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	// A refusal names its tier: the file fold's carries the "package
	// scan: " prefix, the walk's does not — so each tier's arm is
	// pinned on its own (REQ-closure-observability-audited-set).
	cases := []struct{ pkg, symbol, refusal string }{
		{"urlhost", "Host", "package scan: reaches unaudited standard operation net/url.Parse"},
		{"urlvalues", "Compose", ""},
		{"lexical", "Stem", ""},
		{"absolute", "Abs", "package scan: reaches unaudited standard operation path/filepath.Abs"},
		{"walking", "Count", "package scan: reaches unaudited standard operation path/filepath.WalkDir"},
		{"linking", "Real", "package scan: reaches unaudited standard operation path/filepath.EvalSymlinks"},
		{"globbing", "Count", "package scan: reaches unaudited standard operation path/filepath.Glob"},
		{"walkfn", "Count", "package scan: reaches unaudited standard operation path/filepath.Walk"},
		{"badpattern", "Bad", "package scan: reaches unaudited standard operation path/filepath.ErrBadPattern"},
		{"viaglobal", "Ended", "reaches standard global encoding/base64.StdEncoding"},
		{"sentineleof", "Ended", ""},
		{"mutatedeof", "Clobber", "reaches standard global io.EOF"},
	}
	subjects := make([]Subject, 0, len(cases))
	for _, tc := range cases {
		subjects = append(subjects, Subject{Package: "example.com/pathaudit/" + tc.pkg, Symbol: tc.symbol})
	}
	proofs, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		proof := proofs[Subject{Package: "example.com/pathaudit/" + tc.pkg, Symbol: tc.symbol}]
		if tc.refusal == "" && !proof.Observable {
			t.Errorf("%s.%s = %+v, want observable", tc.pkg, tc.symbol, proof)
		}
		if tc.refusal != "" && (proof.Observable || proof.Reason != tc.refusal) {
			t.Errorf("%s.%s = %+v, want exactly %q", tc.pkg, tc.symbol, proof, tc.refusal)
		}
	}
}

// The benchmark harness's pacing — b.N, b.Loop, the timer controls — is
// harness protocol: benchmarks reading it and the tests beside them
// prove observable, while every other benchmark surface keeps its
// class (REQ-closure-observability-benchmark-pacing).
func TestBenchmarkPacingIsHarnessProtocol(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"N", "Loop", "ResetTimer", "StartTimer", "StopTimer"} {
		if !auditedHarnessPacing(true, "testing", name) || auditedHarnessPacing(false, "testing", name) {
			t.Errorf("testing.%s: want pacing on an audited toolchain only", name)
		}
		if _, classified := classBEffect("testing", name); classified {
			t.Errorf("testing.%s classifies at the file fold — a package-wide blocker", name)
		}
	}
	for _, name := range []string{"Elapsed", "ReportMetric", "ReportAllocs", "SetBytes", "RunParallel", "Parallel", "Short"} {
		if auditedHarnessPacing(true, "testing", name) {
			t.Errorf("testing.%s admitted as pacing", name)
		}
	}
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/pacing\n\ngo 1.26\n")
	writeFile(t, dir, "pacing.go", "package pacing\n\nfunc Sum(n int) int {\n\ts := 0\n\tfor i := 0; i < n; i++ {\n\t\ts += i\n\t}\n\treturn s\n}\n")
	writeFile(t, dir, "pacing_test.go", `package pacing

import "testing"

func TestSum(t *testing.T) {
	if Sum(3) != 3 {
		t.Fatal(Sum(3))
	}
}

func BenchmarkCount(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Sum(i)
	}
}

func BenchmarkLoop(b *testing.B) {
	for b.Loop() {
		Sum(8)
	}
}

func BenchmarkTimers(b *testing.B) {
	b.StopTimer()
	x := Sum(4)
	b.StartTimer()
	b.ResetTimer()
	for b.Loop() {
		Sum(x)
	}
}

func BenchmarkMethodValue(b *testing.B) {
	loop := b.Loop
	for loop() {
		Sum(5)
	}
}

func BenchmarkInterface(b *testing.B) {
	var pacer interface{ Loop() bool } = b
	for pacer.Loop() {
		Sum(6)
	}
}

func BenchmarkResultField(b *testing.B) {
	r := testing.BenchmarkResult{N: 3}
	for b.Loop() {
		Sum(r.N)
	}
}
`)
	// Every other benchmark surface keeps its class — and the file fold
	// is package-wide, so the refused reader lives in its own package.
	if err := os.MkdirAll(filepath.Join(dir, "elapsed"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "elapsed/elapsed_test.go", "package elapsed\n\nimport \"testing\"\n\nfunc BenchmarkElapsed(b *testing.B) {\n\tfor b.Loop() {\n\t}\n\t_ = b.Elapsed()\n}\n")
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ pkg, symbol, refusal string }{
		{"pacing", "TestSum", ""}, {"pacing", "BenchmarkCount", ""}, {"pacing", "BenchmarkLoop", ""}, {"pacing", "BenchmarkTimers", ""},
		{"pacing", "BenchmarkMethodValue", ""}, {"pacing", "BenchmarkInterface", ""}, {"pacing", "BenchmarkResultField", ""},
		{"pacing/elapsed", "BenchmarkElapsed", "package scan: reaches testing.Elapsed (test runtime execution)"},
	}
	subjects := make([]Subject, 0, len(cases))
	for _, tc := range cases {
		subjects = append(subjects, Subject{Package: "example.com/" + tc.pkg, Symbol: tc.symbol})
	}
	proofs, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	// The maximal tier records nothing for pacing, so the benchmark
	// package is verifiable there too — the conservative tier no more
	// restrictive than the precise one on the harness's own protocol.
	var pacingSubjects []Subject
	for _, tc := range cases {
		if tc.pkg == "pacing" {
			pacingSubjects = append(pacingSubjects, Subject{Package: "example.com/pacing", Symbol: tc.symbol})
		}
	}
	closures, _, err := h.ComputeMaximalBatch(pacingSubjects)
	if err != nil {
		t.Fatal(err)
	}
	if len(closures) != len(pacingSubjects) {
		t.Fatalf("maximal closures = %d, want %d", len(closures), len(pacingSubjects))
	}
	for subject, cl := range closures {
		if cl.Unverifiable {
			t.Errorf("maximal %s = %+v, want verifiable", subject.Symbol, cl)
		}
	}
	for _, tc := range cases {
		proof := proofs[Subject{Package: "example.com/" + tc.pkg, Symbol: tc.symbol}]
		if tc.refusal == "" && (!proof.Observable || proof.Reason != "") {
			t.Errorf("%s = %+v, want observable", tc.symbol, proof)
		}
		if tc.refusal != "" && (proof.Observable || proof.Reason != tc.refusal) {
			t.Errorf("%s = %+v, want exactly %q", tc.symbol, proof, tc.refusal)
		}
	}
}

// A pacing call is an audited harness fact, not purity evidence: the
// legacy projection stays unverifiable with the pacing reason and the
// recorded fact observable, and a subject mixing pacing with a causal
// effect keeps the causal reason
// (REQ-closure-observability-benchmark-pacing).
func TestBenchmarkPacingIsNotPurityEvidence(t *testing.T) {
	t.Parallel()
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	fixtures := newFixturePrograms(t, h)
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/benchpacing"
	fixtures.supply(t, pkg)
	result, err := computeTier2Result(h, pkg, "BenchmarkLoopOnly")
	if err != nil {
		t.Fatal(err)
	}
	if !result.unverifiable || !strings.Contains(result.reason, "benchmark pacing") {
		t.Fatalf("pacing-only subject = unverifiable %v reason %q, want the recorded harness fact", result.unverifiable, result.reason)
	}
	found := false
	for _, effect := range result.effects {
		if effect.packagePath == "testing" && effect.symbol == "Loop" {
			found = true
			if !effect.observable {
				t.Fatal("pacing harness fact recorded as blocking")
			}
		}
	}
	if !found {
		t.Fatalf("effects = %+v, want the recorded testing.Loop harness fact", result.effects)
	}
	fixtures.supply(t, pkg)
	mixed, err := computeTier2Result(h, pkg, "BenchmarkLoopReadsFile")
	if err != nil {
		t.Fatal(err)
	}
	if !mixed.unverifiable || !strings.Contains(mixed.reason, "file I/O") || strings.Contains(mixed.reason, "benchmark pacing") {
		t.Fatalf("mixed subject reason = %q, want the causal file read over the harness fact", mixed.reason)
	}
	// The pacing field is B's alone: a BenchmarkResult's N records no
	// harness fact — the walk sees a plain struct field — while the
	// Loop beside it is still recorded.
	fixtures.supply(t, pkg)
	other, err := computeTier2Result(h, pkg, "BenchmarkResultField")
	if err != nil {
		t.Fatal(err)
	}
	if !other.unverifiable || !strings.Contains(other.reason, "benchmark pacing") {
		t.Fatalf("BenchmarkResultField = unverifiable %v reason %q, want the Loop fact recorded", other.unverifiable, other.reason)
	}
	for _, effect := range other.effects {
		if effect.packagePath == "testing" && effect.symbol == "B.N" {
			t.Fatalf("BenchmarkResult.N recorded as the harness's count: %+v", other.effects)
		}
	}
	// The harness's remaining reporting surface records nothing at all:
	// the fallback exemption every testing symbol has, its body walked.
	fixtures.supply(t, pkg)
	reporting, err := computeTier2Result(h, pkg, "BenchmarkReporting")
	if err != nil {
		t.Fatal(err)
	}
	if reporting.unverifiable || len(reporting.effects) != 0 {
		t.Fatalf("reporting-only subject = unverifiable %v effects %+v, want nothing recorded", reporting.unverifiable, reporting.effects)
	}
}

// The typed testing scan's memo serves the classification table, so
// the strategy moves with it (REQ-closure-testing-scan-memo).
func TestTestingScanStrategyVersion(t *testing.T) {
	t.Parallel()
	if testingScanStrategy != "gofresh/testing-scan@6" {
		t.Fatalf("testing-scan strategy = %q, want @6 — the harness lifecycle Context read rejoined the table", testingScanStrategy)
	}
}

// The pacing admission is sound only while the pacing names are declared
// exactly where the audit looked: Loop and the timer controls as methods
// of B alone, N as a field of B — BenchmarkResult and the fuzz result
// declare an N too, which the field arm's receiver check excludes — and
// none as a package-level function. A drifting toolchain fails here
// instead of silently widening (REQ-closure-observability-benchmark-pacing).
func TestBenchmarkPacingDeclarationInventory(t *testing.T) {
	t.Parallel()
	testingPkg := testenv.CachedStdlibPackage(t, os.Environ(), "testing")
	if testingPkg == nil || testingPkg.Types == nil || len(testingPkg.Syntax) == 0 {
		t.Fatal("loaded testing package without types or syntax")
	}
	pacing := map[string]bool{"Loop": true, "ResetTimer": true, "StartTimer": true, "StopTimer": true}
	scope := testingPkg.Types.Scope()
	fieldN := map[string]bool{}
	declaredOnB := map[string]bool{}
	for _, typeName := range scope.Names() {
		object := scope.Lookup(typeName)
		if _, isFunc := object.(*types.Func); isFunc && (pacing[object.Name()] || object.Name() == "N") {
			t.Errorf("testing declares pacing name %s as a package-level function — re-audit the benchmark-pacing channel before trusting this toolchain", object.Name())
			continue
		}
		named, ok := object.Type().(*types.Named)
		if !ok {
			continue
		}
		for i := 0; i < named.NumMethods(); i++ {
			method := named.Method(i)
			if pacing[method.Name()] && typeName != "B" {
				t.Errorf("testing.%s declares pacing name %s outside B — re-audit the benchmark-pacing channel before trusting this toolchain", typeName, method.Name())
			}
			if typeName == "B" && pacing[method.Name()] {
				declaredOnB[method.Name()] = true
			}
		}
		if structure, ok := named.Underlying().(*types.Struct); ok {
			for i := 0; i < structure.NumFields(); i++ {
				if structure.Field(i).Name() == "N" {
					fieldN[typeName] = true
				}
			}
		}
	}
	for name := range pacing {
		if !declaredOnB[name] {
			t.Errorf("testing.B no longer declares %s — the admission names a method that does not exist", name)
		}
	}
	for _, known := range []string{"B", "BenchmarkResult", "fuzzResult"} {
		if !fieldN[known] {
			t.Errorf("testing.%s no longer declares field N — re-audit the field arm's receiver check", known)
		}
		delete(fieldN, known)
	}
	if len(fieldN) != 0 {
		t.Errorf("testing declares field N on %v beyond the audited three — re-audit the field arm's receiver check", fieldN)
	}
}

// Non-RTA scanned closures invoking audited standard-library interface methods,
// nested closures appending to captured slice variables, mutually recursive
// interface invokes across loop phis, variadic constructors returning interfaces,
// and map/slice container propagation (slices.Clone, slices.SortFunc, map-of-slices,
// and struct-field maps) all close under audited observability
// (REQ-closure-observability-dispatch, REQ-closure-observability-audited-set).
func TestObservabilityInterfaceContainerAndMutualInvokeClosure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/ifclosure\n\ngo 1.26\n")
	writeFile(t, dir, "ifclosure.go", `package ifclosure

import (
	"cmp"
	"context"
	"slices"
)

type Source interface {
	Name() string
	Check(ctx context.Context) error
}

type memSource struct {
	name string
}

func (m *memSource) Name() string { return m.name }

func (m *memSource) Check(ctx context.Context) error {
	checkCtx := func() error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	return checkCtx()
}

type unionSource struct {
	members []Source
}

func NewUnionSource(prefix string, members ...Source) Source {
	return &unionSource{members: slices.Clone(members)}
}

func (u *unionSource) Name() string {
	if len(u.members) == 0 {
		return ""
	}
	return u.members[0].Name()
}

func (u *unionSource) Check(ctx context.Context) error {
	for _, m := range u.members {
		if err := m.Check(ctx); err != nil {
			return err
		}
	}
	return nil
}

type Tree interface {
	Entry(name string) Entry
	Entries() []Entry
}

type Entry interface {
	Name() string
	Tree() Tree
}

type memTree struct {
	entries []Entry
}

type memEntry struct {
	name string
	sub  Tree
}

func (e *memEntry) Name() string { return e.name }
func (e *memEntry) Tree() Tree   { return e.sub }

func (t *memTree) Entry(name string) Entry {
	for _, e := range t.entries {
		if e.Name() == name {
			return e
		}
	}
	return nil
}

func (t *memTree) Entries() []Entry {
	return slices.Clone(t.entries)
}

type BuildResult struct {
	Root  Tree
	Trees map[string]Tree
}

func BuildHierarchy(paths []string) BuildResult {
	dirEntries := make(map[string][]Entry)
	for _, p := range paths {
		e := Entry(&memEntry{name: p, sub: &memTree{}})
		dirEntries["root"] = append(dirEntries["root"], e)
	}
	entries := dirEntries["root"]
	slices.SortFunc(entries, func(a, b Entry) int {
		return cmp.Compare(a.Name(), b.Name())
	})
	root := Tree(&memTree{entries: entries})
	trees := make(map[string]Tree)
	trees[""] = root
	for _, e := range root.Entries() {
		trees[e.Name()] = e.Tree()
	}
	return BuildResult{Root: root, Trees: trees}
}

func WalkMutual(root Tree, parts []string) string {
	cur := root
	for _, p := range parts {
		e := cur.Entry(p)
		if e == nil {
			return ""
		}
		cur = e.Tree()
	}
	for _, e := range cur.Entries() {
		return e.Name()
	}
	return ""
}
`)
	writeFile(t, dir, "ifclosure_test.go", `package ifclosure

import (
	"context"
	"testing"
)

func TestAllPatterns(t *testing.T) {
	ctx := context.Background()
	var staged []Source
	add := func(name string) Source {
		s := Source(&memSource{name: name})
		staged = append(staged, s)
		return s
	}
	s1 := add("a")
	s2 := add("b")
	u := NewUnionSource("p", s1, s2)
	for _, s := range staged {
		if s.Name() == "" {
			t.Fatal("empty")
		}
	}
	if err := u.Check(ctx); err != nil {
		t.Fatal(err)
	}
	res := BuildHierarchy([]string{"b", "a"})
	_ = WalkMutual(res.Root, []string{"a"})
	if sub := res.Trees["a"]; sub != nil {
		_ = sub.Entries()
	}
}
`)
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subj := Subject{Package: "example.com/ifclosure", Symbol: "TestAllPatterns"}
	proofs, err := h.ComputeObservabilityBatch([]Subject{subj})
	if err != nil {
		t.Fatal(err)
	}
	if proof := proofs[subj]; !proof.Observable || proof.Reason != "" {
		t.Fatalf("TestAllPatterns = %+v, want observable with empty reason", proof)
	}

	// Verify soundness of RTA seed collection for enumerated open-signature
	// subjects (variadic constructor results & caller-populated helper maps)
	// and backing-array alias tracking across slices.Compact.
	if err := os.MkdirAll(filepath.Join(dir, "soundness"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "soundness/soundness.go", `package soundness

import (
	"os"
	"slices"
)

type Op interface {
	Run() string
}

type pureOp struct{ v string }

func (p *pureOp) Run() string { return p.v }

type envOp struct{}

func (*envOp) Run() string { return os.Getenv("X") }

type unionOp struct{ ops []Op }

func NewUnionOp(tag string, ops ...Op) Op {
	return &unionOp{ops: slices.Clone(ops)}
}

func (u *unionOp) Run() string {
	for _, op := range u.ops {
		return op.Run()
	}
	return ""
}

func makeOpMap() map[string]Op {
	return make(map[string]Op)
}

func UseUnion(op Op) string {
	return op.Run()
}

func UseLiteralUnion(op Op) string {
	return op.Run()
}

func UseHolder(u *unionOp) string {
	return u.Run()
}

func UseMap(m map[string]Op) string {
	if op := m["k"]; op != nil {
		return op.Run()
	}
	return ""
}

func Caller() string {
	u := NewUnionOp("t", &envOp{})
	m := makeOpMap()
	m["k"] = &envOp{}
	return UseUnion(u) + UseLiteralUnion(&unionOp{ops: []Op{&envOp{}}}) + UseHolder(&unionOp{ops: []Op{&envOp{}}}) + UseMap(m)
}

func UsePure() string {
	op := Op(&pureOp{v: "clean"})
	return op.Run()
}
`)
	writeFile(t, dir, "soundness/soundness_test.go", `package soundness

import (
	"slices"
	"testing"
)

func TestCompactAliasMutation(t *testing.T) {
	s := make([]Op, 2)
	p := Op(&pureOp{v: "ok"})
	s[0] = p
	s[1] = p
	s2 := slices.Compact(s)
	s2[0] = &envOp{}
	_ = s[0].Run()
}

func TestBinarySearchFuncTargetMutation(t *testing.T) {
	s := make([]Op, 1)
	s[0] = &pureOp{v: "ok"}
	slices.BinarySearchFunc([]int{1}, s, func(_ int, target []Op) int {
		target[0] = &envOp{}
		return 0
	})
	_ = s[0].Run()
}
`)
	if err := os.MkdirAll(filepath.Join(dir, "soundness_open"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "soundness_open/open.go", `package soundness_open

import "slices"

type Op interface {
	Run() string
}

type pureOp struct{}

func (*pureOp) Run() string { return "ok" }

var GlobalOp Op

type globalHolderOp struct {
	op Op
}

func (g *globalHolderOp) Run() string {
	if g.op != nil {
		return g.op.Run()
	}
	return ""
}

func UseOpenGlobal(op Op) string {
	return op.Run()
}

func CallerOpen() string {
	return UseOpenGlobal(&globalHolderOp{op: GlobalOp})
}

func UseFromUncalledCaller(op Op) string {
	return op.Run()
}

func UncalledExportedCaller(ext Op) string {
	return UseFromUncalledCaller(ext)
}

func UseSliceFromBinarySearch(ops []Op) string {
	if len(ops) > 0 {
		return ops[0].Run()
	}
	return ""
}

func CallerBinarySearch() string {
	s := make([]Op, 1)
	s[0] = &pureOp{}
	slices.BinarySearchFunc([]int{1}, s, func(_ int, target []Op) int {
		target[0] = GlobalOp
		return 0
	})
	return UseSliceFromBinarySearch(s)
}
`)
	h2, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	pureSubj := Subject{Package: "example.com/ifclosure/soundness", Symbol: "UsePure"}
	bsearchTestSubj := Subject{Package: "example.com/ifclosure/soundness", Symbol: "TestBinarySearchFuncTargetMutation"}
	soundnessSubjects := []Subject{
		{Package: "example.com/ifclosure/soundness", Symbol: "UseUnion"},
		{Package: "example.com/ifclosure/soundness", Symbol: "UseLiteralUnion"},
		{Package: "example.com/ifclosure/soundness", Symbol: "UseHolder"},
		{Package: "example.com/ifclosure/soundness", Symbol: "UseMap"},
		{Package: "example.com/ifclosure/soundness", Symbol: "TestCompactAliasMutation"},
	}
	openSubjects := []Subject{
		{Package: "example.com/ifclosure/soundness_open", Symbol: "UseOpenGlobal"},
		{Package: "example.com/ifclosure/soundness_open", Symbol: "UseFromUncalledCaller"},
		{Package: "example.com/ifclosure/soundness_open", Symbol: "UseSliceFromBinarySearch"},
	}
	allSoundness := append(append([]Subject{pureSubj, bsearchTestSubj}, soundnessSubjects...), openSubjects...)
	sProofs, err := h2.ComputeObservabilityBatch(allSoundness)
	if err != nil {
		t.Fatal(err)
	}
	sRooted, err := h2.ComputeRootedFunctions(context.Background(), allSoundness)
	if err != nil {
		t.Fatal(err)
	}
	hasEnvOpRun := func(rf RootedFunctions) bool {
		return rf.Complete && rf.Fns["example.com/ifclosure/soundness\x00envOp.Run"]
	}
	if p := sProofs[pureSubj]; !p.Observable || !p.EffectFree {
		t.Fatalf("UsePure observability = %+v, want Observable && EffectFree", p)
	}
	if !sRooted[pureSubj].Complete || hasEnvOpRun(sRooted[pureSubj]) {
		t.Fatalf("UsePure rooted functions = %+v, want Complete without envOp.Run", sRooted[pureSubj])
	}
	if p := sProofs[bsearchTestSubj]; p.Observable || p.EffectFree {
		t.Errorf("TestBinarySearchFuncTargetMutation observability = %+v, want fail-closed (!Observable && !EffectFree)", p)
	}
	if !hasEnvOpRun(sRooted[bsearchTestSubj]) {
		t.Errorf("TestBinarySearchFuncTargetMutation rooted functions = %+v, want Complete with envOp.Run included", sRooted[bsearchTestSubj])
	}
	for _, ss := range soundnessSubjects {
		if p := sProofs[ss]; !p.Observable || p.EffectFree {
			t.Errorf("%s observability = %+v, want Observable && !EffectFree (reaches os.Getenv)", ss.Symbol, p)
		}
		if !hasEnvOpRun(sRooted[ss]) {
			t.Errorf("%s rooted functions = %+v, want Complete with envOp.Run included", ss.Symbol, sRooted[ss])
		}
	}
	for _, os := range openSubjects {
		if p := sProofs[os]; p.Observable || p.EffectFree || !(strings.Contains(p.Reason, "open subject world") || strings.Contains(p.Reason, "reachability is not closed")) {
			t.Errorf("%s observability = %+v, want fail-closed open/unclosed refusal", os.Symbol, p)
		}
		if sRooted[os].Complete {
			t.Errorf("%s rooted functions = %+v, want !Complete", os.Symbol, sRooted[os])
		}
	}

	for _, pkgDir := range []string{
		"ctxval", "helperextract_closed", "helperextract_open", "wholecopy", "uncalledstore",
		"reflectset", "cleanupclosed", "cleanupunclosed", "reflectcall",
		"stdlibinvoke", "namedsig_closed", "namedsig_open", "structbox_open", "addrtaken_open",
	} {
		if err := os.MkdirAll(filepath.Join(dir, pkgDir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, dir, "ctxval/ctxval_test.go", `package ctxval

import (
	"context"
	"fmt"
	"os"
	"testing"
)

type envStringer struct{}

func (envStringer) String() string { return os.Getenv("CTX_VAL_ENV") }

var GlobalStringer fmt.Stringer

func TestContextValueSprintEnvStringer(t *testing.T) {
	ctx := context.WithValue(t.Context(), "k", envStringer{})
	_ = fmt.Sprint(ctx.Value("k"))
}

func TestContextValueOpenPayloadInvoke(t *testing.T) {
	ctx := context.WithValue(t.Context(), "k", GlobalStringer)
	if s, ok := ctx.Value("k").(fmt.Stringer); ok {
		_ = s.String()
	}
}

func TestContextCancelWithOpenValuePayload(t *testing.T) {
	ctx := context.WithValue(t.Context(), "k", GlobalStringer)
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	<-cctx.Done()
	_ = cctx.Err()
}
`)
	writeFile(t, dir, "helperextract_closed/closed.go", `package helperextract_closed

import "os"

type Op interface {
	Run() string
}

type envOp struct{}

func (*envOp) Run() string { return os.Getenv("HELPER_EXTRACT_ENV") }

type Holder struct {
	Op Op
}

func extract(h *Holder) Op {
	return h.Op
}

func UseHolderExtract(h *Holder) string {
	return extract(h).Run()
}

func (h *Holder) RunViaExtract() string {
	return extract(h).Run()
}

func ClosedExtractCaller() string {
	h := &Holder{Op: &envOp{}}
	return UseHolderExtract(h) + h.RunViaExtract()
}
`)
	writeFile(t, dir, "helperextract_open/open.go", `package helperextract_open

type Op interface {
	Run() string
}

var GlobalOp Op

type Holder struct {
	Op Op
}

func extract(h *Holder) Op {
	return h.Op
}

func UseHolderExtractOpen(h *Holder) string {
	return extract(h).Run()
}

func (h *Holder) RunViaExtractOpen() string {
	return extract(h).Run()
}

func OpenExtractCaller() string {
	h := &Holder{Op: GlobalOp}
	return UseHolderExtractOpen(h) + h.RunViaExtractOpen()
}
`)
	writeFile(t, dir, "wholecopy/wholecopy.go", `package wholecopy

type Op interface {
	Run() string
}

type Holder struct {
	Op Op
}

func UseWholeCopied(h *Holder) string {
	if h.Op != nil {
		return h.Op.Run()
	}
	return ""
}

func OverwriteFromParam(src Holder) string {
	dst := &Holder{}
	*dst = src
	return UseWholeCopied(dst)
}
`)
	writeFile(t, dir, "uncalledstore/uncalledstore.go", `package uncalledstore

type Op interface {
	Run() string
}

type pureOp struct{}

func (*pureOp) Run() string { return "pure" }

type Holder struct {
	Op Op
}

func UseUncalledStored(h *Holder) string {
	return h.Op.Run()
}

func (h *Holder) MethodTarget() string {
	return h.Op.Run()
}

func ClosedSeedCaller() string {
	h := &Holder{Op: &pureOp{}}
	return UseUncalledStored(h) + h.MethodTarget()
}

func SetAndCall(op Op) string {
	h := &Holder{Op: op}
	return UseUncalledStored(h)
}

func UncalledMethodCaller(ext *Holder) string {
	return ext.MethodTarget()
}
`)
	writeFile(t, dir, "reflectset/reflectset.go", `package reflectset

type Op interface {
	Run() string
}

type pureOp struct{}

func (*pureOp) Run() string { return "pure" }

type Holder struct {
	Op Op
}

func UseReflectMutated(h *Holder) string {
	return h.Op.Run()
}

func (h *Holder) RunReflectMutated() string {
	return h.Op.Run()
}

func NewPureHolder() *Holder {
	return &Holder{Op: &pureOp{}}
}
`)
	writeFile(t, dir, "reflectset/reflectset_test.go", `package reflectset_test

import (
	"reflect"
	"testing"

	"example.com/ifclosure/reflectset"
)

var GlobalOp reflectset.Op

func TestMutateViaReflect(t *testing.T) {
	h := reflectset.NewPureHolder()
	reflect.ValueOf(h).Elem().FieldByName("Op").Set(reflect.ValueOf(GlobalOp))
	_ = reflectset.UseReflectMutated(h)
	_ = h.RunReflectMutated()
}
`)
	writeFile(t, dir, "cleanupclosed/cleanup_test.go", `package cleanupclosed

import (
	"os"
	"testing"
)

var sharedCounter int

func mutateShared() {
	sharedCounter++
}

func cleanupEnv() {
	_ = os.Getenv("CLEANUP_CLOSED_ENV")
}

func fuzzHelper(data []byte) {
	if len(data) > 0 {
		sharedCounter += int(data[0])
	}
}

func TestClosedCleanup(t *testing.T) {
	t.Cleanup(mutateShared)
}

func TestClosedCleanupEnv(t *testing.T) {
	t.Cleanup(cleanupEnv)
}

func FuzzClosedTarget(f *testing.F) {
	f.Add([]byte("seed"))
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzHelper(data)
	})
}
`)
	writeFile(t, dir, "cleanupunclosed/cleanup_test.go", `package cleanupunclosed

import "testing"

var GlobalCleanupHook func()

func TestUnclosedCleanup(t *testing.T) {
	t.Cleanup(GlobalCleanupHook)
}
`)
	writeFile(t, dir, "reflectcall/reflectcall_test.go", `package reflectcall

import (
	"reflect"
	"testing"
)

type Mutator struct{}

var mutated bool

func (Mutator) Do() {
	mutated = true
}

func TestReflectMethodCall(t *testing.T) {
	reflect.ValueOf(Mutator{}).MethodByName("Do").Call(nil)
}
`)
	writeFile(t, dir, "stdlibinvoke/stdlibinvoke_test.go", `package stdlibinvoke

import (
	"io"
	"os"
	"testing"
)

type pureReader struct{}

func (pureReader) Read(p []byte) (int, error) { return 0, io.EOF }

type evilReader struct{}

func (evilReader) Read(p []byte) (int, error) {
	_ = os.Getenv("STDLIB_INVOKE_ENV")
	return 0, io.EOF
}

type sink struct{}

func (*sink) Write(p []byte) (int, error) { return len(p), nil }

func (*sink) ReadFrom(r io.Reader) (int64, error) {
	var buf [8]byte
	_, err := r.Read(buf[:])
	return 0, err
}

func TestStdlibInvokeReadFrom(t *testing.T) {
	s := &sink{}
	_, _ = s.ReadFrom(pureReader{})
	_, _ = io.Copy(s, evilReader{})
}
`)
	writeFile(t, dir, "namedsig_closed/namedsig_test.go", `package namedsig_closed

import (
	"os"
	"testing"
)

type Installer interface {
	Install() string
}

type EnvInstaller func() string

func (f EnvInstaller) Install() string { return f() }

func pureFn() string { return "pure" }

func envFn() string { return os.Getenv("NAMED_SIG_ENV") }

func TestMixedNamedSig(t *testing.T) {
	_ = EnvInstaller(pureFn).Install()
	var r Installer = EnvInstaller(envFn)
	_ = r.Install()
}
`)
	writeFile(t, dir, "namedsig_open/namedsig_test.go", `package namedsig_open

import "testing"

type Installer interface {
	Install() string
}

type OpenInstaller func() string

func (f OpenInstaller) Install() string { return f() }

type PtrInstaller func() string

func (f PtrInstaller) Install() string { return f() }

var (
	GlobalInstaller OpenInstaller
	GlobalFn        func() string
)

func pureFn() string { return "pure" }

func TestOpenGlobalNamedSig(t *testing.T) {
	_ = OpenInstaller(pureFn).Install()
	var r Installer = GlobalInstaller
	if r != nil {
		_ = r.Install()
	}
}

func overwritePtr(dst *PtrInstaller) {
	*dst = PtrInstaller(GlobalFn)
}

func TestPointerMutatedNamedSig(t *testing.T) {
	f := PtrInstaller(pureFn)
	overwritePtr(&f)
	_ = f.Install()
}
`)
	writeFile(t, dir, "structbox_open/structbox_test.go", `package structbox_open

import "testing"

type Op interface {
	Run() string
}

type pureOp struct{}

func (*pureOp) Run() string { return "pure" }

type Holder struct {
	Op Op
}

type Saver interface {
	Save(*Holder)
}

type Worker struct {
	op Op
}

func (w *Worker) Run() string {
	if w != nil && w.op != nil {
		return w.op.Run()
	}
	return ""
}

func (w *Worker) Save(h *Holder) {
	h.Op = w
}

var (
	GlobalOpenWorker *Worker
	GlobalOp         Op
)

func UseSavedHolder(h *Holder) string {
	(&Worker{}).Save(h)
	return h.Op.Run()
}

func TestStaticOnly(t *testing.T) {
	h := &Holder{}
	(&Worker{}).Save(h)
	_ = h.Op.Run()
}

func TestBoxedOpen(t *testing.T) {
	var s Saver = GlobalOpenWorker
	h := &Holder{}
	if s != nil {
		s.Save(h)
		_ = h.Op.Run()
	}
}

type SliceOp []Op

func (s SliceOp) Run() string {
	if len(s) > 0 && s[0] != nil {
		return s[0].Run()
	}
	return ""
}

func TestMixedSliceRecv(t *testing.T) {
	_ = SliceOp{&pureOp{}}.Run()
	var r Op = SliceOp{GlobalOp}
	_ = r.Run()
}
`)
	writeFile(t, dir, "addrtaken_open/addrtaken_test.go", `package addrtaken_open

import "testing"

type Op interface {
	Run() string
}

type pureOp struct{}

func (*pureOp) Run() string { return "pure" }

type Holder struct {
	Op Op
}

func SetHolder(h *Holder, op Op) {
	h.Op = op
}

var (
	GlobalSetter = SetHolder
	GlobalOp     Op
)

func TestStaticCaller(t *testing.T) {
	h := &Holder{}
	SetHolder(h, &pureOp{})
	_ = h.Op.Run()
}

func TestDynamicOpenCaller(t *testing.T) {
	h := &Holder{}
	if GlobalSetter != nil {
		GlobalSetter(h, GlobalOp)
		_ = h.Op.Run()
	}
}
`)

	h3, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctxSprintSubj := Subject{Package: "example.com/ifclosure/ctxval", Symbol: "TestContextValueSprintEnvStringer"}
	ctxOpenSubj := Subject{Package: "example.com/ifclosure/ctxval", Symbol: "TestContextValueOpenPayloadInvoke"}
	ctxCancelSubj := Subject{Package: "example.com/ifclosure/ctxval", Symbol: "TestContextCancelWithOpenValuePayload"}
	extractFnClosed := Subject{Package: "example.com/ifclosure/helperextract_closed", Symbol: "UseHolderExtract"}
	extractMethClosed := Subject{Package: "example.com/ifclosure/helperextract_closed", Symbol: "Holder.RunViaExtract"}
	extractFnOpen := Subject{Package: "example.com/ifclosure/helperextract_open", Symbol: "UseHolderExtractOpen"}
	extractMethOpen := Subject{Package: "example.com/ifclosure/helperextract_open", Symbol: "Holder.RunViaExtractOpen"}
	wholeCopySubj := Subject{Package: "example.com/ifclosure/wholecopy", Symbol: "UseWholeCopied"}
	uncalledFnSubj := Subject{Package: "example.com/ifclosure/uncalledstore", Symbol: "UseUncalledStored"}
	uncalledMethSubj := Subject{Package: "example.com/ifclosure/uncalledstore", Symbol: "Holder.MethodTarget"}
	reflectFnSubj := Subject{Package: "example.com/ifclosure/reflectset", Symbol: "UseReflectMutated"}
	reflectMethSubj := Subject{Package: "example.com/ifclosure/reflectset", Symbol: "Holder.RunReflectMutated"}
	closedCleanupSubj := Subject{Package: "example.com/ifclosure/cleanupclosed", Symbol: "TestClosedCleanup"}
	closedCleanupEnvSubj := Subject{Package: "example.com/ifclosure/cleanupclosed", Symbol: "TestClosedCleanupEnv"}
	closedFuzzSubj := Subject{Package: "example.com/ifclosure/cleanupclosed", Symbol: "FuzzClosedTarget"}
	unclosedCleanupSubj := Subject{Package: "example.com/ifclosure/cleanupunclosed", Symbol: "TestUnclosedCleanup"}
	reflectCallSubj := Subject{Package: "example.com/ifclosure/reflectcall", Symbol: "TestReflectMethodCall"}
	stdlibInvokeSubj := Subject{Package: "example.com/ifclosure/stdlibinvoke", Symbol: "TestStdlibInvokeReadFrom"}
	namedSigClosedSubj := Subject{Package: "example.com/ifclosure/namedsig_closed", Symbol: "TestMixedNamedSig"}
	namedSigOpenGlobalSubj := Subject{Package: "example.com/ifclosure/namedsig_open", Symbol: "TestOpenGlobalNamedSig"}
	namedSigPtrMutSubj := Subject{Package: "example.com/ifclosure/namedsig_open", Symbol: "TestPointerMutatedNamedSig"}
	structBoxStaticSubj := Subject{Package: "example.com/ifclosure/structbox_open", Symbol: "TestStaticOnly"}
	structBoxOpenSubj := Subject{Package: "example.com/ifclosure/structbox_open", Symbol: "TestBoxedOpen"}
	structBoxUseSavedSubj := Subject{Package: "example.com/ifclosure/structbox_open", Symbol: "UseSavedHolder"}
	sliceRecvSubj := Subject{Package: "example.com/ifclosure/structbox_open", Symbol: "TestMixedSliceRecv"}
	addrTakenStaticSubj := Subject{Package: "example.com/ifclosure/addrtaken_open", Symbol: "TestStaticCaller"}
	addrTakenDynamicSubj := Subject{Package: "example.com/ifclosure/addrtaken_open", Symbol: "TestDynamicOpenCaller"}

	extraSubjects := []Subject{
		ctxSprintSubj, ctxOpenSubj, ctxCancelSubj,
		extractFnClosed, extractMethClosed,
		extractFnOpen, extractMethOpen,
		wholeCopySubj, uncalledFnSubj, uncalledMethSubj,
		reflectFnSubj, reflectMethSubj,
		closedCleanupSubj, closedCleanupEnvSubj, closedFuzzSubj, unclosedCleanupSubj, reflectCallSubj,
		stdlibInvokeSubj, namedSigClosedSubj, namedSigOpenGlobalSubj, namedSigPtrMutSubj,
		structBoxStaticSubj, structBoxOpenSubj, structBoxUseSavedSubj, sliceRecvSubj,
		addrTakenStaticSubj, addrTakenDynamicSubj,
	}
	eProofs, err := h3.ComputeObservabilityBatch(extraSubjects)
	if err != nil {
		t.Fatal(err)
	}
	eRooted, err := h3.ComputeRootedFunctions(context.Background(), extraSubjects)
	if err != nil {
		t.Fatal(err)
	}
	binRooted, err := h3.ComputeBinaryRootedFunctions(context.Background(), []string{
		"example.com/ifclosure/cleanupclosed",
		"example.com/ifclosure/cleanupunclosed",
		"example.com/ifclosure/reflectcall",
	})
	if err != nil {
		t.Fatal(err)
	}

	if p := eProofs[ctxSprintSubj]; !p.Observable || p.EffectFree {
		t.Errorf("TestContextValueSprintEnvStringer observability = %+v, want Observable && !EffectFree", p)
	}
	if rf := eRooted[ctxSprintSubj]; !rf.Complete || !rf.Fns["example.com/ifclosure/ctxval\x00envStringer.String"] {
		t.Errorf("TestContextValueSprintEnvStringer rooted = %+v, want Complete with envStringer.String", rf)
	}
	if p := eProofs[ctxOpenSubj]; p.Observable || p.EffectFree {
		t.Errorf("TestContextValueOpenPayloadInvoke observability = %+v, want fail-closed", p)
	}
	if p := eProofs[ctxCancelSubj]; !p.Observable || !p.EffectFree {
		t.Errorf("TestContextCancelWithOpenValuePayload observability = %+v, want Observable && EffectFree", p)
	}

	for _, cs := range []Subject{extractFnClosed, extractMethClosed} {
		if p := eProofs[cs]; !p.Observable || p.EffectFree {
			t.Errorf("%s observability = %+v, want Observable && !EffectFree", cs.Symbol, p)
		}
		if rf := eRooted[cs]; !rf.Complete || !rf.Fns["example.com/ifclosure/helperextract_closed\x00envOp.Run"] {
			t.Errorf("%s rooted = %+v, want Complete with envOp.Run", cs.Symbol, rf)
		}
	}

	for _, openSubj := range []Subject{
		extractFnOpen, extractMethOpen,
		wholeCopySubj, uncalledFnSubj, uncalledMethSubj,
		reflectFnSubj, reflectMethSubj,
		unclosedCleanupSubj,
		structBoxUseSavedSubj,
	} {
		if p := eProofs[openSubj]; p.Observable || p.EffectFree {
			t.Errorf("%s (%s) observability = %+v, want fail-closed", openSubj.Package, openSubj.Symbol, p)
		}
		if rf := eRooted[openSubj]; rf.Complete {
			t.Errorf("%s (%s) rooted = %+v, want !Complete", openSubj.Package, openSubj.Symbol, rf)
		}
	}

	for _, openTestSubj := range []Subject{
		namedSigOpenGlobalSubj, namedSigPtrMutSubj,
		structBoxStaticSubj, structBoxOpenSubj, sliceRecvSubj,
		addrTakenStaticSubj, addrTakenDynamicSubj,
	} {
		if p := eProofs[openTestSubj]; p.Observable || p.EffectFree {
			t.Errorf("%s (%s) observability = %+v, want fail-closed", openTestSubj.Package, openTestSubj.Symbol, p)
		}
	}

	if p := eProofs[stdlibInvokeSubj]; p.EffectFree {
		t.Errorf("TestStdlibInvokeReadFrom observability = %+v, want !EffectFree", p)
	}
	if rf := eRooted[stdlibInvokeSubj]; rf.Complete && !rf.Fns["example.com/ifclosure/stdlibinvoke\x00evilReader.Read"] {
		t.Errorf("TestStdlibInvokeReadFrom rooted = %+v, want !Complete or evilReader.Read included", rf)
	}

	if p := eProofs[namedSigClosedSubj]; !p.Observable || p.EffectFree {
		t.Errorf("TestMixedNamedSig observability = %+v, want Observable && !EffectFree", p)
	}
	if rf := eRooted[namedSigClosedSubj]; !rf.Complete || !rf.Fns["example.com/ifclosure/namedsig_closed\x00envFn"] {
		t.Errorf("TestMixedNamedSig rooted = %+v, want Complete with envFn", rf)
	}

	for _, soloSubj := range []Subject{
		structBoxStaticSubj, structBoxOpenSubj,
		addrTakenStaticSubj, addrTakenDynamicSubj,
	} {
		hSolo, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		soloProofs, err := hSolo.ComputeObservabilityBatch([]Subject{soloSubj})
		if err != nil {
			t.Fatal(err)
		}
		if p := soloProofs[soloSubj]; p.Observable || p.EffectFree {
			t.Errorf("solo %s (%s) observability = %+v, want fail-closed", soloSubj.Package, soloSubj.Symbol, p)
		}
	}

	if p := eProofs[closedCleanupSubj]; !p.Observable || !p.EffectFree {
		t.Errorf("TestClosedCleanup observability = %+v, want Observable && EffectFree", p)
	}
	if rf := eRooted[closedCleanupSubj]; !rf.Complete || !rf.Fns["example.com/ifclosure/cleanupclosed\x00mutateShared"] {
		t.Errorf("TestClosedCleanup rooted = %+v, want Complete with mutateShared", rf)
	}
	if p := eProofs[closedCleanupEnvSubj]; p.Observable || p.EffectFree {
		t.Errorf("TestClosedCleanupEnv observability = %+v, want !Observable && !EffectFree", p)
	}
	if rf := eRooted[closedCleanupEnvSubj]; !rf.Complete || !rf.Fns["example.com/ifclosure/cleanupclosed\x00cleanupEnv"] {
		t.Errorf("TestClosedCleanupEnv rooted = %+v, want Complete with cleanupEnv", rf)
	}
	if p := eProofs[closedFuzzSubj]; p.Observable || p.EffectFree {
		t.Errorf("FuzzClosedTarget observability = %+v, want !Observable && !EffectFree", p)
	}
	if rf := eRooted[closedFuzzSubj]; !rf.Complete || !rf.Fns["example.com/ifclosure/cleanupclosed\x00fuzzHelper"] {
		t.Errorf("FuzzClosedTarget rooted = %+v, want Complete with fuzzHelper", rf)
	}
	if brf := binRooted["example.com/ifclosure/cleanupclosed"]; !brf.Complete ||
		!brf.Fns["example.com/ifclosure/cleanupclosed\x00mutateShared"] ||
		!brf.Fns["example.com/ifclosure/cleanupclosed\x00cleanupEnv"] ||
		!brf.Fns["example.com/ifclosure/cleanupclosed\x00fuzzHelper"] {
		t.Errorf("cleanupclosed binary rooted = %+v, want Complete with mutateShared, cleanupEnv, and fuzzHelper", brf)
	}
	if brf := binRooted["example.com/ifclosure/cleanupunclosed"]; brf.Complete {
		t.Errorf("cleanupunclosed binary rooted = %+v, want !Complete", brf)
	}
	if rf := eRooted[reflectCallSubj]; rf.Complete {
		t.Errorf("TestReflectMethodCall rooted = %+v, want !Complete", rf)
	}
	if brf := binRooted["example.com/ifclosure/reflectcall"]; brf.Complete {
		t.Errorf("reflectcall binary rooted = %+v, want !Complete", brf)
	}
}

func TestObservabilityDotlessModuleAndPromotedEmbedding(t *testing.T) {
	t.Parallel()

	// 1. Dotless user module ("module app"): user types, globals, signatures,
	// and promoted wrappers must never be misclassified as standard library.
	dotlessDir := t.TempDir()
	writeFile(t, dotlessDir, "go.mod", "module app\n\ngo 1.26\n")
	writeFile(t, dotlessDir, "app.go", `package app

import "errors"

type Op interface {
	Run() string
}

type SliceOp []func() string

func (s SliceOp) Run() string {
	for _, fn := range s {
		return fn()
	}
	return ""
}

var GlobalSlice SliceOp

var ErrSentinel = errors.New("app sentinel")

type PureEmbed struct{}

func (PureEmbed) Pure() int { return 7 }

type NamedOuter struct {
	PureEmbed
}

type FuncBox struct {
	Fn func() string
}

func (b FuncBox) Call() string {
	if b.Fn != nil {
		return b.Fn()
	}
	return ""
}

var GlobalFn func() string

type NamedHook func() string

func (h NamedHook) Run() string {
	if h != nil {
		return h()
	}
	return ""
}

var GlobalHook NamedHook
`)
	writeFile(t, dotlessDir, "app_test.go", `package app

import (
	"errors"
	"os"
	"testing"
)

func TestPlant(t *testing.T) {
	GlobalSlice = append(GlobalSlice, func() string { return os.Getenv("DOTLESS_PLANTED") })
	GlobalFn = func() string { return os.Getenv("DOTLESS_FN") }
	GlobalHook = func() string { return os.Getenv("DOTLESS_HOOK") }
}

func TestDotlessOpenSliceOp(t *testing.T) {
	var op Op = GlobalSlice
	_ = op.Run()
}

func TestDotlessClosedSliceOp(t *testing.T) {
	local := SliceOp{func() string { return os.Getenv("DOTLESS_CLOSED") }}
	_ = local.Run()
}

func TestDotlessNamedPromotedPure(t *testing.T) {
	var r interface{ Pure() int } = NamedOuter{}
	if r.Pure() != 7 {
		t.Fatal("unexpected")
	}
}

func TestDotlessOpenBox(t *testing.T) {
	b := FuncBox{Fn: GlobalFn}
	_ = b.Call()
}

func TestDotlessOpenNamedHook(t *testing.T) {
	var op Op = GlobalHook
	_ = op.Run()
}

func TestDotlessSentinel(t *testing.T) {
	if !errors.Is(ErrSentinel, ErrSentinel) {
		t.Fatal("unexpected")
	}
}
`)
	if err := os.MkdirAll(filepath.Join(dotlessDir, "closedhook"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dotlessDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dotlessDir, "pure"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dotlessDir, "sub/sub.go", `package sub

func Add(a, b int) int {
	return a + b
}
`)
	writeFile(t, dotlessDir, "pure/pure.go", `package pure

import "app/sub"

func PureCrossSub(x int) int {
	return sub.Add(x, 1)
}
`)
	writeFile(t, dotlessDir, "pure/pure_test.go", `package pure

import "testing"

func TestDotlessMultiPkgPure(t *testing.T) {
	if PureCrossSub(41) != 42 {
		t.Fatal("unexpected")
	}
}
`)
	writeFile(t, dotlessDir, "closedhook/closedhook_test.go", `package closedhook

import (
	"os"
	"testing"
)

type Op interface {
	Run() string
}

type NamedHook func() string

func (h NamedHook) Run() string {
	return h()
}

func TestDotlessClosedNamedHook(t *testing.T) {
	var op Op = NamedHook(func() string { return os.Getenv("DOTLESS_CLOSED_HOOK") })
	_ = op.Run()
}
`)

	hDotless, err := newAt(dotlessDir)
	if err != nil {
		t.Fatal(err)
	}
	dotlessOpenSlice := Subject{Package: "app", Symbol: "TestDotlessOpenSliceOp"}
	dotlessClosedSlice := Subject{Package: "app", Symbol: "TestDotlessClosedSliceOp"}
	dotlessClosedHook := Subject{Package: "app/closedhook", Symbol: "TestDotlessClosedNamedHook"}
	dotlessPromotedPure := Subject{Package: "app", Symbol: "TestDotlessNamedPromotedPure"}
	dotlessOpenBox := Subject{Package: "app", Symbol: "TestDotlessOpenBox"}
	dotlessOpenHook := Subject{Package: "app", Symbol: "TestDotlessOpenNamedHook"}
	dotlessSentinel := Subject{Package: "app", Symbol: "TestDotlessSentinel"}
	dotlessCrossProd := Subject{Package: "app/pure", Symbol: "PureCrossSub"}
	dotlessCrossTest := Subject{Package: "app/pure", Symbol: "TestDotlessMultiPkgPure"}

	dMaximal, _, err := hDotless.ComputeMaximalBatch([]Subject{dotlessCrossProd})
	if err != nil {
		t.Fatal(err)
	}
	if m := dMaximal[dotlessCrossProd]; m.Unverifiable || m.Hash == "" {
		t.Errorf("dotless multi-pkg PureCrossSub maximal = %+v, want verifiable non-empty hash", m)
	}

	dProofs, err := hDotless.ComputeObservabilityBatch([]Subject{
		dotlessOpenSlice, dotlessClosedSlice, dotlessClosedHook, dotlessPromotedPure,
		dotlessOpenBox, dotlessOpenHook, dotlessSentinel,
		dotlessCrossProd, dotlessCrossTest,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []Subject{dotlessOpenSlice, dotlessOpenBox, dotlessOpenHook} {
		if p := dProofs[s]; p.Observable || p.EffectFree {
			t.Errorf("dotless %s observability = %+v, want fail-closed", s.Symbol, p)
		}
	}
	for _, s := range []Subject{dotlessClosedSlice, dotlessClosedHook} {
		if p := dProofs[s]; !p.Observable || p.EffectFree {
			t.Errorf("dotless %s observability = %+v, want Observable && !EffectFree", s.Symbol, p)
		}
	}
	for _, s := range []Subject{dotlessPromotedPure, dotlessSentinel, dotlessCrossProd, dotlessCrossTest} {
		if p := dProofs[s]; !p.Observable || !p.EffectFree {
			t.Errorf("dotless %s observability = %+v, want Observable && EffectFree", s.Symbol, p)
		}
	}

	// 2. Pointer-embedded structs, embedded slice carriers, unnamed-struct
	// promoted wrappers, and reflect-mutated function-field stores.
	embedDir := t.TempDir()
	for _, sub := range []string{"ptrworker", "embedslice", "unnamedwrap", "reflectfunc"} {
		if err := os.MkdirAll(filepath.Join(embedDir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, embedDir, "go.mod", "module example.com/promotedembed\n\ngo 1.26\n")
	writeFile(t, embedDir, "ptrworker/ptrworker.go", `package ptrworker

import "os"

type Op interface {
	Run() string
}

type Holder struct {
	Op Op
}

type Saver interface {
	Save(h *Holder)
}

type Worker struct {
	Fn func() string
}

func (w *Worker) Run() string {
	if w.Fn != nil {
		return w.Fn()
	}
	return ""
}

func (w *Worker) Save(h *Holder) {
	h.Op = w
}

type OuterPtr struct {
	*Worker
}

var GlobalOpenWorker *Worker

func init() {
	GlobalOpenWorker = &Worker{Fn: func() string { return os.Getenv("PTR_EMBED_WORKER") }}
}

func BoxOuter(s Saver, h *Holder) {
	s.Save(h)
}

func UseSavedWorker(h *Holder) string {
	return h.Op.Run()
}
`)
	writeFile(t, embedDir, "ptrworker/ptrworker_test.go", `package ptrworker

import "testing"

func TestPromotedPtrWorkerBoxedOpen(t *testing.T) {
	var h Holder
	var s Saver = &OuterPtr{Worker: GlobalOpenWorker}
	BoxOuter(s, &h)
	_ = UseSavedWorker(&h)
}
`)
	writeFile(t, embedDir, "embedslice/embedslice.go", `package embedslice

import "os"

type Op interface {
	Run() string
}

type SliceOp []func() string

func (s SliceOp) Run() string {
	for _, fn := range s {
		return fn()
	}
	return ""
}

type OuterSlice struct {
	SliceOp
}

var GlobalSlice SliceOp

func PlantSlice() {
	GlobalSlice = append(GlobalSlice, func() string { return os.Getenv("EMBED_SLICE_ENV") })
}
`)
	writeFile(t, embedDir, "embedslice/embedslice_test.go", `package embedslice

import "testing"

func TestPlant(t *testing.T) {
	PlantSlice()
}

func TestEmbeddedSliceBoxed(t *testing.T) {
	var op Op = &OuterSlice{SliceOp: GlobalSlice}
	_ = op.Run()
}

func TestEmbeddedSliceMethodExpr(t *testing.T) {
	_ = OuterSlice.Run(OuterSlice{SliceOp: GlobalSlice})
}
`)
	writeFile(t, embedDir, "unnamedwrap/unnamedwrap.go", `package unnamedwrap

import (
	"io"
	"time"
)

type LocReader interface {
	Local() time.Time
}

type pureLoc struct{}

func (pureLoc) Local() time.Time { return time.Time{} }

type PureRunner interface {
	RunPure() int
}

type PureEmbed struct{}

func (PureEmbed) RunPure() int { return 42 }

var GlobalReader io.Reader
var GlobalErr error
`)
	writeFile(t, embedDir, "unnamedwrap/unnamedwrap_test.go", `package unnamedwrap

import (
	"io"
	"testing"
	"time"
)

func TestUnnamedTimeLocal(t *testing.T) {
	var alt LocReader = pureLoc{}
	_ = alt
	var r LocReader = struct{ time.Time }{Time: time.Unix(0, 0).UTC()}
	_ = r.Local()
}

func TestUnnamedIOReader(t *testing.T) {
	var r io.Reader = struct{ io.Reader }{Reader: GlobalReader}
	buf := make([]byte, 1)
	_, _ = r.Read(buf)
}

func TestUnnamedUniverseError(t *testing.T) {
	var e error = struct{ error }{error: GlobalErr}
	_ = e.Error()
}

func TestUnnamedPureEmbed(t *testing.T) {
	var r PureRunner = struct{ PureEmbed }{}
	if r.RunPure() != 42 {
		t.Fatal("unexpected")
	}
}
`)
	writeFile(t, embedDir, "reflectfunc/reflectfunc.go", `package reflectfunc

import (
	"os"
	"reflect"
)

type Op interface {
	Run() string
}

type Holder struct {
	Op Op
}

type pureOp struct{}

func (*pureOp) Run() string { return "ok" }

type envOp struct{}

func (*envOp) Run() string { return os.Getenv("REFLECT_FUNC_ENV") }

type FuncBox struct {
	F func(*Holder, Op)
}

func setHolder(h *Holder, op Op) {
	h.Op = op
}

func UseReflectFuncField(h *Holder) string {
	return h.Op.Run()
}

func PlantViaReflect() string {
	var fb FuncBox
	fb.F = setHolder
	fb.F(&Holder{}, &pureOp{})
	var h Holder
	v := reflect.ValueOf(&fb).Elem().Field(0).Addr()
	if ptr, ok := v.Interface().(*func(*Holder, Op)); ok && *ptr != nil {
		(*ptr)(&h, &envOp{})
	}
	return UseReflectFuncField(&h)
}
`)
	writeFile(t, embedDir, "reflectfunc/reflectfunc_test.go", `package reflectfunc

import "testing"

func TestPlantReflect(t *testing.T) {
	_ = PlantViaReflect()
}
`)

	hEmbed, err := newAt(embedDir)
	if err != nil {
		t.Fatal(err)
	}
	ptrWorkerTestSubj := Subject{Package: "example.com/promotedembed/ptrworker", Symbol: "TestPromotedPtrWorkerBoxedOpen"}
	ptrWorkerProdSubj := Subject{Package: "example.com/promotedembed/ptrworker", Symbol: "UseSavedWorker"}
	embedSliceBoxedSubj := Subject{Package: "example.com/promotedembed/embedslice", Symbol: "TestEmbeddedSliceBoxed"}
	embedSliceExprSubj := Subject{Package: "example.com/promotedembed/embedslice", Symbol: "TestEmbeddedSliceMethodExpr"}
	unnamedTimeSubj := Subject{Package: "example.com/promotedembed/unnamedwrap", Symbol: "TestUnnamedTimeLocal"}
	unnamedReaderSubj := Subject{Package: "example.com/promotedembed/unnamedwrap", Symbol: "TestUnnamedIOReader"}
	unnamedErrSubj := Subject{Package: "example.com/promotedembed/unnamedwrap", Symbol: "TestUnnamedUniverseError"}
	unnamedPureSubj := Subject{Package: "example.com/promotedembed/unnamedwrap", Symbol: "TestUnnamedPureEmbed"}
	reflectFuncSubj := Subject{Package: "example.com/promotedembed/reflectfunc", Symbol: "UseReflectFuncField"}

	emProofs, err := hEmbed.ComputeObservabilityBatch([]Subject{
		ptrWorkerTestSubj, ptrWorkerProdSubj,
		embedSliceBoxedSubj, embedSliceExprSubj,
		unnamedTimeSubj, unnamedReaderSubj, unnamedErrSubj, unnamedPureSubj,
		reflectFuncSubj,
	})
	if err != nil {
		t.Fatal(err)
	}
	emRooted, err := hEmbed.ComputeRootedFunctions(context.Background(), []Subject{ptrWorkerProdSubj, reflectFuncSubj})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []Subject{
		ptrWorkerTestSubj, ptrWorkerProdSubj,
		embedSliceBoxedSubj, embedSliceExprSubj,
		unnamedTimeSubj, unnamedReaderSubj, unnamedErrSubj,
		reflectFuncSubj,
	} {
		if p := emProofs[s]; p.Observable || p.EffectFree {
			t.Errorf("%s (%s) observability = %+v, want fail-closed", s.Package, s.Symbol, p)
		}
	}
	for _, s := range []Subject{ptrWorkerProdSubj, reflectFuncSubj} {
		if rf := emRooted[s]; rf.Complete {
			t.Errorf("%s (%s) rooted = %+v, want !Complete", s.Package, s.Symbol, rf)
		}
	}
	if p := emProofs[unnamedPureSubj]; !p.Observable || !p.EffectFree {
		t.Errorf("TestUnnamedPureEmbed observability = %+v, want Observable && EffectFree", p)
	}
}

func TestObservabilityStartupPruningAssemblyAndOpenWorldClosures(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for _, sub := range []string{
		"startupprune",
		"startupmutated",
		"startupasync",
		"startuplinkname",
		"startupshadow",
		"startupunreached",
		"startupfuzz",
		"startupshadowfalse",
		"openworld",
		"ctxtimer",
		"sentinelmut",
		"sentinellinkname",
		"iowrap",
		"iowrapmut",
		"iowrapmr",
		"ctxmut",
		"customsimd",
		"mixedasmwiden",
		"hwprobe",
		"hwcapok",
		"hwcapmut",
		"hwcapbadtype",
		"hwcapconflict",
		"initasmonce",
		"asmtestcollide",
		"startupinitnohelper",
		"startupwidenedshared",
	} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, root, "go.mod", "module example.com/startupopen\n\ngo 1.26\n")

	// 1. Unmutated zero-global dead-branch pruning (including *bool flag pointer
	// pattern) and runtime.GOARCH/GOOS constant-branch pruning in package init.
	writeFile(t, root, "startupprune/startupprune.go", `package startupprune

import (
	"fmt"
	"os"
	"runtime"
)

var (
	deadHook     func()
	deadToggle   bool
	displayFeats *bool
)

func init() {
	if deadHook != nil {
		deadHook()
		_ = os.Getenv("DEAD_HOOK_ENV")
	}
	if deadToggle {
		_ = os.Getenv("DEAD_TOGGLE_ENV")
	}
	if displayFeats != nil && *displayFeats {
		fmt.Println("features")
		os.Exit(1)
	}
	if runtime.GOARCH == "wasm" || runtime.GOOS == "plan9" {
		_ = os.Getenv("DEAD_ARCH_ENV")
	}
}

func Add(a, b int) int {
	return a + b
}
`)
	writeFile(t, root, "startupprune/startupprune_test.go", `package startupprune

import "testing"

func TestAdd(t *testing.T) {
	if Add(2, 3) != 5 {
		t.Fatal("unexpected sum")
	}
}
`)

	// Negative control A: when the package global is mutated in init, its
	// branch is live and must refuse fail-closed on the startup effect.
	writeFile(t, root, "startupmutated/startupmutated.go", `package startupmutated

import "os"

var liveToggle bool

func init() {
	liveToggle = true
	if liveToggle {
		_ = os.Getenv("LIVE_TOGGLE_ENV")
	}
}

func Sub(a, b int) int {
	return a - b
}
`)
	writeFile(t, root, "startupmutated/startupmutated_test.go", `package startupmutated

import "testing"

func TestSub(t *testing.T) {
	if Sub(5, 3) != 2 {
		t.Fatal("unexpected diff")
	}
}
`)

	// Negative control B: an async goroutine spawned in init() executes
	// concurrently with post-init functions and can observe post-init global
	// writes, so it must NOT prune based on sync-init-only unmutated globals.
	writeFile(t, root, "startupasync/startupasync.go", `package startupasync

import "os"

var postInitToggle bool

func init() {
	go func() {
		if postInitToggle {
			_ = os.Getenv("ASYNC_STARTUP_ENV")
		}
	}()
}

func EnableToggle() {
	postInitToggle = true
}

func Mul(a, b int) int {
	return a * b
}
`)
	writeFile(t, root, "startupasync/startupasync_test.go", `package startupasync

import "testing"

func TestMul(t *testing.T) {
	EnableToggle()
	if Mul(3, 4) != 12 {
		t.Fatal("unexpected product")
	}
}
`)

	// Negative control C: a //go:linkname global alias cannot be proven
	// unmutated by SSA stores on the local *ssa.Global alone and must refuse.
	writeFile(t, root, "startuplinkname/startuplinkname.go", `package startuplinkname

import (
	"os"
	_ "unsafe"
)

//go:linkname linkedToggle example.com/startupopen/startuplinkname.aliasToggle
var linkedToggle bool

var aliasToggle = true

func init() {
	if linkedToggle {
		_ = os.Getenv("LINKNAME_STARTUP_ENV")
	}
}

func Ident(x int) int {
	if aliasToggle {
		return x
	}
	return 0
}
`)
	writeFile(t, root, "startuplinkname/startuplinkname_test.go", `package startuplinkname

import "testing"

func TestIdent(t *testing.T) {
	if Ident(7) != 7 {
		t.Fatal("unexpected value")
	}
}
`)

	// Negative control D: a local parameter shadowing an unmutated zero global
	// must never be pruned as if it were the zero global.
	writeFile(t, root, "startupshadow/startupshadow.go", `package startupshadow

import "os"

var shadowToggle bool

func shadowHelper(shadowToggle bool) {
	if shadowToggle {
		_ = os.Getenv("SHADOW_STARTUP_ENV")
	}
}

func init() {
	shadowHelper(true)
}

func Neg(x int) int {
	return -x
}
`)
	writeFile(t, root, "startupshadow/startupshadow_test.go", `package startupshadow

import "testing"

func TestNeg(t *testing.T) {
	if Neg(4) != -4 {
		t.Fatal("unexpected neg")
	}
}
`)

	// 2. Open-world subject enumeration:
	// - Carrier-free equality-only error parameter: both direct call
	//   (CustomErr.Is) and indirect errors.Is-only dispatch (IndirectErr.Is
	//   with zero direct .Is static call sites), plus strconv.ErrRange /
	//   strconv.ErrSyntax sentinel comparisons.
	// - Audited context.Context cancellation checks (ctx.Done(), ctx.Err())
	//   under context.Background, t.Context, and context.WithCancel.
	// - Generic helper with concrete instantiations calling an open-world function.
	// - Bound interface method value converted to a named function type (*ssa.ChangeType).
	// - Audited io.NopCloser wrapping strings.NewReader.
	writeFile(t, root, "openworld/openworld.go", `package openworld

import (
	"context"
	"errors"
	"io"
	"strconv"
)

var ErrCustom = errors.New("custom error")

type CustomErr struct {
	Code int
}

func (e *CustomErr) Error() string {
	return "custom"
}

func (e *CustomErr) Is(target error) bool {
	return target == ErrCustom || target == strconv.ErrRange || target == strconv.ErrSyntax
}

type IndirectErr struct {
	Op string
}

func (e *IndirectErr) Error() string {
	return e.Op
}

func (e *IndirectErr) Is(target error) bool {
	return target == ErrCustom
}

func CheckCancelOnly(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

type Runner interface {
	Run() int
}

type ConstRunner struct {
	V int
}

func (r ConstRunner) Run() int {
	return r.V
}

type HookFn func() int

func CallHook(fn HookFn) int {
	return fn()
}

func DispatchBoundConverted(r Runner) int {
	var h HookFn = r.Run
	return CallHook(h)
}

func ApplyGeneric[T ~int](v T) int {
	return OpenTarget(func(y int) int { return int(v) + y })
}

func OpenTarget(f func(int) int) int {
	return f(7)
}

func ReadNopCloser(rc io.ReadCloser) (int, error) {
	var buf [4]byte
	n, _ := rc.Read(buf[:])
	return n, rc.Close()
}
`)
	writeFile(t, root, "openworld/openworld_test.go", `package openworld

import (
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
)

func TestOpenWorldAdmissions(t *testing.T) {
	ce := &CustomErr{Code: 1}
	if !ce.Is(ErrCustom) || !ce.Is(strconv.ErrRange) {
		t.Fatal("expected Is match")
	}
	var ie error = &IndirectErr{Op: "read"}
	if !errors.Is(ie, ErrCustom) {
		t.Fatal("expected errors.Is match")
	}
	if err := CheckCancelOnly(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := CheckCancelOnly(t.Context()); err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := CheckCancelOnly(cctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	if DispatchBoundConverted(ConstRunner{V: 11}) != 11 {
		t.Fatal("unexpected bound converted result")
	}
	if res := ApplyGeneric[int](3); res != 10 {
		t.Fatal("unexpected generic result")
	}
	n, err := ReadNopCloser(io.NopCloser(strings.NewReader("abcd")))
	if err != nil || n != 4 {
		t.Fatalf("ReadNopCloser = %d, %v", n, err)
	}
}
`)

	// Negative control for unenumerated context caller: when a caller obtains
	// its parent context from an unclosed slice of functions and wraps it in
	// context.WithTimeout, the callee must refuse fail-closed.
	writeFile(t, root, "ctxtimer/ctxtimer.go", `package ctxtimer

import (
	"context"
	"time"
)

func CheckWithTimerInProgram(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func PassDynamicCtx(fns []func() context.Context) error {
	ctx, cancel := context.WithTimeout(fns[0](), time.Millisecond)
	defer cancel()
	return CheckWithTimerInProgram(ctx)
}
`)
	writeFile(t, root, "ctxtimer/ctxtimer_test.go", `package ctxtimer

import (
	"context"
	"testing"
)

func TestTimerContextRefuses(t *testing.T) {
	_ = PassDynamicCtx([]func() context.Context{context.Background})
}
`)

	// Negative control E: unreached sibling function mutating a zero global and
	// calling os.Setenv inside if flag must NOT have its if body pruned as a
	// startup-only declaration, preserving package-wide process-hazard refusal.
	writeFile(t, root, "startupunreached/startupunreached.go", `package startupunreached

import "os"

var unreachedFlag bool

func EnableAndPollute() {
	unreachedFlag = true
	if unreachedFlag {
		_ = os.Setenv("POLLUTE_ENV", "1")
	}
}

func PureId(x int) int {
	return x
}
`)

	// Negative control F: a helper shared between init() and an f.Fuzz callback
	// executes post-startup and must not prune branches on a fuzz-mutated global.
	writeFile(t, root, "startupfuzz/startupfuzz.go", `package startupfuzz
`)
	writeFile(t, root, "startupfuzz/startupfuzz_test.go", `package startupfuzz

import (
	"os"
	"testing"
)

var fuzzToggle bool

func sharedHelper() {
	if fuzzToggle {
		_ = os.Getenv("FUZZ_STARTUP_ENV")
	}
}

func init() {
	sharedHelper()
}

func FuzzSharedHelper(f *testing.F) {
	f.Add(1)
	f.Fuzz(func(t *testing.T, x int) {
		if x > 0 {
			fuzzToggle = true
		}
		sharedHelper()
	})
}
`)

	// Negative control G: parameter shadowing universe identifier "false" must
	// not be treated as boolean literal false when checking if zeroFlag != false.
	writeFile(t, root, "startupshadowfalse/startupshadowfalse.go", `package startupshadowfalse

import "os"

var zeroFlag bool

func checkShadow(false bool) {
	if zeroFlag != false {
		_ = os.Getenv("SHADOW_FALSE_ENV")
	}
}

func init() {
	checkShadow(true)
}

func Double(x int) int {
	return x * 2
}
`)

	// Sentinel & io/context wrapper controls:
	// - First-party errors.New global overwritten in func init() (init#1) must not
	//   narrow to *errors.errorString.
	writeFile(t, root, "sentinelmut/sentinelmut.go", `package sentinelmut

import (
	"errors"
	"os"
)

var ErrMut = errors.New("initial")

type evilSentinel struct{}

func (evilSentinel) Error() string {
	return os.Getenv("EVIL_SENTINEL_ENV")
}

func init() {
	ErrMut = evilSentinel{}
}

func ReadSentinel() string {
	return ErrMut.Error()
}

func FormatMutSentinel(err error) string {
	return err.Error()
}

func CallFormatMutSentinel() string {
	return FormatMutSentinel(ErrMut)
}
`)

	// - First-party errors.New global with //go:linkname hazard must refuse.
	writeFile(t, root, "sentinellinkname/sentinellinkname.go", `package sentinellinkname

import (
	"errors"
	_ "unsafe"
)

//go:linkname ErrLinked example.com/startupopen/sentinellinkname.errAlias
var ErrLinked = errors.New("linked")

var errAlias error

func ReadLinkedSentinel() string {
	return ErrLinked.Error()
}
`)

	// - io.LimitReader over a nil-error reader synthesizes io.EOF; unmutated
	//   io.EOF collects *errors.errorString cleanly.
	writeFile(t, root, "iowrap/iowrap.go", `package iowrap

import "io"

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	return 0, nil
}

func ReadLimitedEOF() string {
	r := io.LimitReader(zeroReader{}, 0)
	var buf [4]byte
	_, err := r.Read(buf[:])
	if err != nil {
		return err.Error()
	}
	return ""
}
`)

	// - Mutated io.EOF refuses io.LimitReader error narrowing.
	writeFile(t, root, "iowrapmut/iowrapmut.go", `package iowrapmut

import (
	"io"
	"os"
)

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	return 0, nil
}

type evilIOErr struct{}

func (evilIOErr) Error() string {
	return os.Getenv("EVIL_IO_EOF_ENV")
}

func PoisonEOF() {
	io.EOF = evilIOErr{}
}

func ReadLimitedMutatedEOF() string {
	r := io.LimitReader(zeroReader{}, 0)
	var buf [4]byte
	_, err := r.Read(buf[:])
	if err != nil {
		return err.Error()
	}
	return ""
}
`)

	// - io.MultiReader.WriteTo(w) invokes w.Write even when wrapped readers lack
	//   WriteTo; must not skip (*io.multiReader).WriteTo as a pure reader wrapper.
	writeFile(t, root, "iowrapmr/iowrapmr.go", `package iowrapmr

import (
	"io"
	"os"
)

type oneByteReader struct{}

func (oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 0 {
		p[0] = 'x'
		return 1, nil
	}
	return 0, io.EOF
}

type evilErr struct{}

func (evilErr) Error() string {
	return os.Getenv("EVIL_MR_WRITETO_ENV")
}

type evilWriter struct{}

func (evilWriter) Write(p []byte) (int, error) {
	return 0, evilErr{}
}

func MultiReaderWriteToErr() string {
	wt := io.MultiReader(oneByteReader{}).(io.WriterTo)
	_, err := wt.WriteTo(evilWriter{})
	if err != nil {
		return err.Error()
	}
	return ""
}
`)

	// - Mutated context.Canceled refuses ctx.Err() sentinel narrowing.
	writeFile(t, root, "ctxmut/ctxmut.go", `package ctxmut

import (
	"context"
	"os"
)

type evilCtxErr struct{}

func (evilCtxErr) Error() string {
	return os.Getenv("EVIL_CTX_CANCELED_ENV")
}

func PoisonCanceled() {
	context.Canceled = evilCtxErr{}
}

func ReadMutatedCanceledErr() string {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx.Err().Error()
}
`)

	// 3. Module/version-independent mechanical per-TEXT .s verification under
	// arbitrary package paths (example.com/startupopen/customsimd and hwprobe),
	// plus verified read-only pull //go:linkname on internal/cpu.HWCap.
	writeFile(t, root, "customsimd/a.h", "#include \"b.h\"\n")
	writeFile(t, root, "customsimd/b.h", "#define ADD_STEP(dst, src) \\\n\tADDL src, dst\n")
	writeFile(t, root, "customsimd/customsimd_amd64.go", `//go:build amd64

package customsimd

func PureKernel(x uint32) uint32
func ReadCounter() uint64

func UsePureKernel(x uint32) uint32 {
	return PureKernel(x)
}

func UseReadCounter() uint64 {
	return ReadCounter()
}
`)
	writeFile(t, root, "customsimd/tables_amd64.s", `#include "textflag.h"

DATA ·sharedTable+0(SB)/4, $0x12345678
GLOBL ·sharedTable(SB), RODATA, $4
`)
	writeFile(t, root, "customsimd/customsimd_amd64.s", `#include "textflag.h"
#include "a.h"

DATA localConst<>+0(SB)/4, $7
GLOBL localConst<>(SB), RODATA, $4

TEXT ·PureKernel(SB), NOSPLIT, $0-12
	MOVL x+0(FP), AX
	MOVL ·sharedTable+0(SB), BX
	ADD_STEP(AX, BX)
	ADDL localConst<>+0(SB), AX
	MOVL AX, ret+8(FP)
	RET

TEXT ·ReadCounter(SB), NOSPLIT, $0-8
	BYTE $0x0f; BYTE $0x01; BYTE $0xf9
	MOVQ AX, ret+0(FP)
	RET
`)
	writeFile(t, root, "customsimd/customsimd_arm64.go", `//go:build arm64

package customsimd

func PureKernel(x uint32) uint32
func ReadCounter() uint64

func UsePureKernel(x uint32) uint32 {
	return PureKernel(x)
}

func UseReadCounter() uint64 {
	return ReadCounter()
}
`)
	writeFile(t, root, "customsimd/tables_arm64.s", `#include "textflag.h"

DATA ·sharedTable+0(SB)/4, $0x12345678
GLOBL ·sharedTable(SB), RODATA, $4
`)
	writeFile(t, root, "customsimd/customsimd_arm64.s", `#include "textflag.h"

DATA localConst<>+0(SB)/4, $7
GLOBL localConst<>(SB), RODATA, $4

TEXT ·PureKernel(SB), NOSPLIT, $0-12
	MOVWU x+0(FP), R0
	MOVWU ·sharedTable+0(SB), R1
	ADDW R1, R0, R0
	MOVWU localConst<>+0(SB), R2
	ADDW R2, R0, R0
	MOVWU R0, ret+8(FP)
	RET

TEXT ·ReadCounter(SB), NOSPLIT, $0-8
	WORD $0xd53be040
	MOVD R0, ret+0(FP)
	RET
`)
	writeFile(t, root, "customsimd/customsimd_other.go", `//go:build !amd64 && !arm64

package customsimd

import "os"

func UsePureKernel(x uint32) uint32 {
	return x + 0x12345678 + 7
}

func UseReadCounter() uint64 {
	_ = os.Getenv("COUNTER_FALLBACK")
	return 0
}
`)

	// Widened scan importing a mixed pure/impure .s package must refuse because
	// verifiedPackageAssemblyMaximalPure rejects packages with impure TEXT symbols.
	writeFile(t, root, "mixedasmwiden/mixedasmwiden.go", `package mixedasmwiden

import (
	"reflect"

	"example.com/startupopen/customsimd"
)

type box struct{}

func (box) M() uint32 { return customsimd.UsePureKernel(1) }

var dynMethod = "M"

func WidenedWithMixedAsm() int {
	v := reflect.ValueOf(box{}).MethodByName(dynMethod)
	return int(v.Call(nil)[0].Uint())
}
`)

	// Static CPU-feature queries (both in init() via a package function variable
	// and range-over-int brand loop, and directly at subject time) vs per-core
	// APIC ID reads under an arbitrary package path (zero package-name allowlist).
	writeFile(t, root, "hwprobe/hwprobe_amd64.go", `//go:build amd64

package hwprobe

func asmCpuid(op uint32) (eax, ebx, ecx, edx uint32)
func asmXgetbv(index uint32) (eax, edx uint32)

var (
	cpuidFn      func(op uint32) (eax, ebx, ecx, edx uint32)
	initFeatures uint32
)

func init() {
	cpuidFn = asmCpuid
	_, ebx, _, _ := cpuidFn(1)
	logicalCount := (ebx >> 16) & 0xff
	var brand uint32
	for i := range uint32(3) {
		a, b, c, d := cpuidFn(0x80000002 + i)
		brand ^= a ^ b ^ c ^ d
	}
	initFeatures = logicalCount ^ brand
}

func ProbeStaticFeatures() uint32 {
	_, ebx, ecx, edx := asmCpuid(1)
	maskedEBX := ebx & 0x00ffffff
	xlo, xhi := asmXgetbv(0)
	return initFeatures ^ maskedEBX ^ ecx ^ edx ^ xlo ^ xhi
}

func ProbeLogicalCoreID() uint32 {
	_, ebx, _, _ := asmCpuid(1)
	return ebx >> 24
}
`)
	writeFile(t, root, "hwprobe/hwprobe_amd64.s", `#include "textflag.h"

TEXT ·asmCpuid(SB), NOSPLIT, $0-24
	XORQ CX, CX
	MOVL op+0(FP), AX
	CPUID
	MOVL AX, eax+8(FP)
	MOVL BX, ebx+12(FP)
	MOVL CX, ecx+16(FP)
	MOVL DX, edx+20(FP)
	RET

TEXT ·asmXgetbv(SB), NOSPLIT, $0-16
	MOVL index+0(FP), CX
	BYTE $0x0f; BYTE $0x01; BYTE $0xd0
	MOVL AX, eax+8(FP)
	MOVL DX, edx+12(FP)
	RET
`)
	writeFile(t, root, "hwprobe/hwprobe_arm64.go", `//go:build arm64

package hwprobe

func getInstAttr() uint64
func getMpidr() uint64

func ProbeStaticFeatures() uint32 {
	return uint32(getInstAttr())
}

func ProbeLogicalCoreID() uint32 {
	return uint32(getMpidr())
}
`)
	writeFile(t, root, "hwprobe/hwprobe_arm64.s", `#include "textflag.h"

TEXT ·getInstAttr(SB), NOSPLIT, $0-8
	WORD $0xd5380600
	MOVD R0, ret+0(FP)
	RET

TEXT ·getMpidr(SB), NOSPLIT, $0-8
	WORD $0xd53800a0
	MOVD R0, ret+0(FP)
	RET
`)
	writeFile(t, root, "hwprobe/hwprobe_other.go", `//go:build !amd64 && !arm64

package hwprobe

import "os"

func ProbeStaticFeatures() uint32 {
	return 1
}

func ProbeLogicalCoreID() uint32 {
	_ = os.Getenv("APIC_FALLBACK")
	return 0
}
`)

	// Verified read-only pull //go:linkname on internal/cpu.HWCap (including
	// freestanding file-level directive separated by a blank line) vs mutated,
	// bad-type, and conflicting-target negative controls.
	writeFile(t, root, "hwcapok/hwcapok.go", `package hwcapok

import _ "unsafe"

//go:linkname hwcap internal/cpu.HWCap

var hwcap uint

func ReadHWCapMask() bool {
	return (hwcap & 1) != 0
}
`)
	writeFile(t, root, "hwcapmut/hwcapmut.go", `package hwcapmut

import _ "unsafe"

//go:linkname hwcap internal/cpu.HWCap
var hwcap uint

func badGeneric[T any]() {
	hwcap = 1
}

func ReadMutatedHWCap() bool {
	return (hwcap & 1) != 0
}
`)
	writeFile(t, root, "hwcapbadtype/hwcapbadtype.go", `package hwcapbadtype

import _ "unsafe"

//go:linkname hwcap internal/cpu.HWCap
var hwcap string

func ReadStringHWCap() int {
	return len(hwcap)
}
`)
	writeFile(t, root, "hwcapconflict/hwcapconflict.go", `package hwcapconflict

import _ "unsafe"

//go:linkname hwcap internal/cpu.HWCap
//go:linkname hwcap runtime.buildVersion
var hwcap uint

func ReadConflictHWCap() bool {
	return (hwcap & 1) != 0
}
`)

	// Impure assembly reached from init() through stdlib sync.Once.Do while the
	// subject itself is pure Go must be refused.
	writeFile(t, root, "initasmonce/initasmonce.go", `package initasmonce

import "sync"

var once sync.Once

func rdtscInit()

func init() {
	once.Do(rdtscInit)
}

func PureGoSubject() int {
	return 42
}
`)
	writeFile(t, root, "initasmonce/initasmonce_amd64.s", `//go:build amd64

#include "textflag.h"

TEXT ·rdtscInit(SB), NOSPLIT, $0-0
	BYTE $0x0f; BYTE $0x01; BYTE $0xf9
	RET
`)
	writeFile(t, root, "initasmonce/initasmonce_arm64.s", `//go:build arm64

#include "textflag.h"

TEXT ·rdtscInit(SB), NOSPLIT, $0-0
	WORD $0xd53800a0
	RET
`)

	// Assembly GLOBL colliding with an in-package _test.go variable must fail
	// closed deterministically across compartments.
	writeFile(t, root, "asmtestcollide/asmtestcollide.go", `package asmtestcollide

func LoadLut() uint64

func UseCollide() uint64 {
	return LoadLut()
}
`)
	writeFile(t, root, "asmtestcollide/asmtestcollide_test.go", `package asmtestcollide

import "testing"

var testTable uint64

func TestCollide(t *testing.T) {
	testTable = 7
	_ = UseCollide()
}
`)
	writeFile(t, root, "asmtestcollide/asmtestcollide_amd64.s", `//go:build amd64

#include "textflag.h"

DATA ·testTable+0(SB)/8, $1
GLOBL ·testTable(SB), RODATA, $8

TEXT ·LoadLut(SB), NOSPLIT, $0-8
	MOVQ ·testTable+0(SB), AX
	MOVQ AX, ret+0(FP)
	RET
`)
	writeFile(t, root, "asmtestcollide/asmtestcollide_arm64.s", `//go:build arm64

#include "textflag.h"

DATA ·testTable+0(SB)/8, $1
GLOBL ·testTable(SB), RODATA, $8

TEXT ·LoadLut(SB), NOSPLIT, $0-8
	MOVD ·testTable+0(SB), R0
	MOVD R0, ret+0(FP)
	RET
`)

	// Dead startup if branch directly inside func init() with no named startup
	// helper functions (plus a defined boolean type) must prune os.Exit(1).
	writeFile(t, root, "startupinitnohelper/startupinitnohelper.go", `package startupinitnohelper

import "os"

type customBool bool

var (
	initDebugFlag customBool
	initDebugHook func()
)

func init() {
	if initDebugHook != nil || initDebugFlag {
		os.Exit(1)
	}
}

func EnableLater() {
	initDebugFlag = true
	initDebugHook = func() {}
}

func PureNoHelper(x int) int {
	return x + 1
}
`)

	// Closed subject mutating a startup-zero global and calling a helper shared
	// with init() must NOT prune the helper's if body in the Tier-1 package scan.
	writeFile(t, root, "startupwidenedshared/startupwidenedshared.go", `package startupwidenedshared

import "runtime"

var sharedZero bool

func sharedHelper() {
	if sharedZero {
		runtime.GOMAXPROCS(0)
	}
}

func init() {
	sharedHelper()
}

func WidenedMutate() {
	sharedZero = true
	sharedHelper()
}
`)

	// Detached file-scope //go:linkname (separated from var decl by blank line)
	// must disqualify zero-global startup pruning via idx.linknameByName.
	writeFile(t, root, "startupdetachedlink/startupdetachedlink.go", `package startupdetachedlink

import (
	"os"
	_ "unsafe"
)

//go:linkname detachedZero example.com/other.detachedZero

var detachedZero bool

func init() {
	if detachedZero {
		os.Exit(1)
	}
}

func ReadDetached(x int) int {
	return x + 1
}
`)

	// Non-canonical CPUID assembly wrapper (hardcoding leaf 1 and shifting EBX>>24
	// into the EAX return slot while Go passes leaf 0) must be rejected fail-closed.
	writeFile(t, root, "badcpuid/badcpuid_amd64.go", `//go:build amd64

package badcpuid

func sneakyCpuid(op uint32) (eax, ebx, ecx, edx uint32)

func ProbeSneaky() uint32 {
	eax, _, _, _ := sneakyCpuid(0)
	return eax
}
`)
	writeFile(t, root, "badcpuid/badcpuid_amd64.s", `//go:build amd64

#include "textflag.h"

TEXT ·sneakyCpuid(SB), NOSPLIT, $0-24
	MOVL $1, AX
	XORQ CX, CX
	CPUID
	SHRL $24, BX
	MOVL BX, eax+8(FP)
	MOVL $0, ebx+12(FP)
	MOVL $0, ecx+16(FP)
	MOVL $0, edx+20(FP)
	RET
`)
	writeFile(t, root, "badcpuid/badcpuid_other.go", `//go:build !amd64

package badcpuid

import "os"

func ProbeSneaky() uint32 {
	return uint32(os.Getpid())
}
`)

	// Assembly-backed method with receiver (`TEXT ·Box·AsmMethod(SB)`)
	// must fail closed rather than bypassing receiver/symbol verification.
	writeFile(t, root, "asmmethod/asmmethod_asm.go", `//go:build amd64 || arm64

package asmmethod

type Box struct{ X int }

func (b Box) AsmMethod() int

func CallAsmMethod(x int) int {
	return Box{X: x}.AsmMethod()
}
`)
	writeFile(t, root, "asmmethod/asmmethod_amd64.s", `//go:build amd64

#include "textflag.h"

TEXT ·Box·AsmMethod(SB), NOSPLIT, $0-16
	MOVQ $0, ret+8(FP)
	RET
`)
	writeFile(t, root, "asmmethod/asmmethod_arm64.s", `//go:build arm64

#include "textflag.h"

TEXT ·Box·AsmMethod(SB), NOSPLIT, $0-16
	MOVD $0, ret+8(FP)
	RET
`)
	writeFile(t, root, "asmmethod/asmmethod_other.go", `//go:build !amd64 && !arm64

package asmmethod

import "os"

func CallAsmMethod(x int) int {
	return os.Getpid() + x
}
`)

	h, err := newAt(root)
	if err != nil {
		t.Fatal(err)
	}
	addSubj := Subject{Package: "example.com/startupopen/startupprune", Symbol: "Add"}
	testAddSubj := Subject{Package: "example.com/startupopen/startupprune", Symbol: "TestAdd"}
	subSubj := Subject{Package: "example.com/startupopen/startupmutated", Symbol: "Sub"}
	mulSubj := Subject{Package: "example.com/startupopen/startupasync", Symbol: "Mul"}
	linknameSubj := Subject{Package: "example.com/startupopen/startuplinkname", Symbol: "Ident"}
	shadowSubj := Subject{Package: "example.com/startupopen/startupshadow", Symbol: "Neg"}
	isSubj := Subject{Package: "example.com/startupopen/openworld", Symbol: "CustomErr.Is"}
	indirectIsSubj := Subject{Package: "example.com/startupopen/openworld", Symbol: "IndirectErr.Is"}
	cancelSubj := Subject{Package: "example.com/startupopen/openworld", Symbol: "CheckCancelOnly"}
	boundSubj := Subject{Package: "example.com/startupopen/openworld", Symbol: "DispatchBoundConverted"}
	openTargetSubj := Subject{Package: "example.com/startupopen/openworld", Symbol: "OpenTarget"}
	nopCloserSubj := Subject{Package: "example.com/startupopen/openworld", Symbol: "ReadNopCloser"}
	testOpenSubj := Subject{Package: "example.com/startupopen/openworld", Symbol: "TestOpenWorldAdmissions"}
	timerCtxSubj := Subject{Package: "example.com/startupopen/ctxtimer", Symbol: "CheckWithTimerInProgram"}
	unreachedSubj := Subject{Package: "example.com/startupopen/startupunreached", Symbol: "PureId"}
	fuzzStartupSubj := Subject{Package: "example.com/startupopen/startupfuzz", Symbol: "FuzzSharedHelper"}
	shadowFalseSubj := Subject{Package: "example.com/startupopen/startupshadowfalse", Symbol: "Double"}
	sentinelMutSubj := Subject{Package: "example.com/startupopen/sentinelmut", Symbol: "ReadSentinel"}
	formatMutSentinelSubj := Subject{Package: "example.com/startupopen/sentinelmut", Symbol: "FormatMutSentinel"}
	sentinelLinkSubj := Subject{Package: "example.com/startupopen/sentinellinkname", Symbol: "ReadLinkedSentinel"}
	ioWrapOKSubj := Subject{Package: "example.com/startupopen/iowrap", Symbol: "ReadLimitedEOF"}
	ioWrapMutSubj := Subject{Package: "example.com/startupopen/iowrapmut", Symbol: "ReadLimitedMutatedEOF"}
	ioWrapMRSubj := Subject{Package: "example.com/startupopen/iowrapmr", Symbol: "MultiReaderWriteToErr"}
	ctxMutSubj := Subject{Package: "example.com/startupopen/ctxmut", Symbol: "ReadMutatedCanceledErr"}
	pureSimdSubj := Subject{Package: "example.com/startupopen/customsimd", Symbol: "UsePureKernel"}
	counterSimdSubj := Subject{Package: "example.com/startupopen/customsimd", Symbol: "UseReadCounter"}
	widenedMixedAsmSubj := Subject{Package: "example.com/startupopen/mixedasmwiden", Symbol: "WidenedWithMixedAsm"}
	staticFeatSubj := Subject{Package: "example.com/startupopen/hwprobe", Symbol: "ProbeStaticFeatures"}
	logicalCoreSubj := Subject{Package: "example.com/startupopen/hwprobe", Symbol: "ProbeLogicalCoreID"}
	hwcapOKSubj := Subject{Package: "example.com/startupopen/hwcapok", Symbol: "ReadHWCapMask"}
	hwcapMutSubj := Subject{Package: "example.com/startupopen/hwcapmut", Symbol: "ReadMutatedHWCap"}
	hwcapBadTypeSubj := Subject{Package: "example.com/startupopen/hwcapbadtype", Symbol: "ReadStringHWCap"}
	hwcapConflictSubj := Subject{Package: "example.com/startupopen/hwcapconflict", Symbol: "ReadConflictHWCap"}
	initAsmOnceSubj := Subject{Package: "example.com/startupopen/initasmonce", Symbol: "PureGoSubject"}
	asmTestCollideSubj := Subject{Package: "example.com/startupopen/asmtestcollide", Symbol: "UseCollide"}
	initNoHelperSubj := Subject{Package: "example.com/startupopen/startupinitnohelper", Symbol: "PureNoHelper"}
	widenedSharedSubj := Subject{Package: "example.com/startupopen/startupwidenedshared", Symbol: "WidenedMutate"}
	detachedLinkSubj := Subject{Package: "example.com/startupopen/startupdetachedlink", Symbol: "ReadDetached"}
	badCpuidSubj := Subject{Package: "example.com/startupopen/badcpuid", Symbol: "ProbeSneaky"}
	asmMethodSubj := Subject{Package: "example.com/startupopen/asmmethod", Symbol: "CallAsmMethod"}

	proofs, err := h.ComputeObservabilityBatch([]Subject{
		addSubj, testAddSubj,
		subSubj, mulSubj, linknameSubj, shadowSubj,
		unreachedSubj, fuzzStartupSubj, shadowFalseSubj,
		isSubj, indirectIsSubj, cancelSubj, boundSubj, openTargetSubj, nopCloserSubj, testOpenSubj,
		timerCtxSubj,
		sentinelMutSubj, formatMutSentinelSubj, sentinelLinkSubj,
		ioWrapOKSubj, ioWrapMutSubj, ioWrapMRSubj, ctxMutSubj,
		pureSimdSubj, counterSimdSubj, widenedMixedAsmSubj,
		staticFeatSubj, logicalCoreSubj,
		hwcapOKSubj, hwcapMutSubj, hwcapBadTypeSubj, hwcapConflictSubj,
		initAsmOnceSubj, asmTestCollideSubj, initNoHelperSubj, widenedSharedSubj,
		detachedLinkSubj, badCpuidSubj, asmMethodSubj,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []Subject{
		addSubj, testAddSubj,
		initNoHelperSubj,
		isSubj, indirectIsSubj, cancelSubj, boundSubj, openTargetSubj, nopCloserSubj, testOpenSubj,
		ioWrapOKSubj,
		pureSimdSubj,
		staticFeatSubj,
		hwcapOKSubj,
	} {
		if p := proofs[s]; !p.Observable || !p.EffectFree {
			t.Errorf("%s (%s) observability = %+v, want Observable && EffectFree", s.Package, s.Symbol, p)
		}
	}
	for _, s := range []Subject{
		subSubj, mulSubj, linknameSubj, shadowSubj,
		unreachedSubj, fuzzStartupSubj, shadowFalseSubj, widenedSharedSubj,
		timerCtxSubj,
		formatMutSentinelSubj, sentinelLinkSubj,
		counterSimdSubj, widenedMixedAsmSubj,
		logicalCoreSubj,
		hwcapMutSubj, hwcapBadTypeSubj, hwcapConflictSubj,
		initAsmOnceSubj, asmTestCollideSubj,
		detachedLinkSubj, badCpuidSubj, asmMethodSubj,
	} {
		if p := proofs[s]; p.Observable || p.EffectFree {
			t.Errorf("%s (%s) observability = %+v, want fail-closed (!Observable && !EffectFree)", s.Package, s.Symbol, p)
		}
	}
	for _, s := range []Subject{
		sentinelMutSubj, ioWrapMutSubj, ioWrapMRSubj, ctxMutSubj,
	} {
		if p := proofs[s]; p.EffectFree {
			t.Errorf("%s (%s) observability = %+v, want !EffectFree on mutated/evil error target", s.Package, s.Symbol, p)
		}
	}
	if p := proofs[widenedSharedSubj]; !strings.HasPrefix(p.Reason, "package scan:") {
		t.Errorf("%s (%s) reason = %q, want Tier-1 package scan backstop refusal", widenedSharedSubj.Package, widenedSharedSubj.Symbol, p.Reason)
	}

	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		simdRooted, err := h.ComputeRootedFunctions(context.Background(), []Subject{pureSimdSubj, counterSimdSubj, asmMethodSubj})
		if err != nil {
			t.Fatalf("ComputeRootedFunctions on customsimd: %v", err)
		}
		if !simdRooted[pureSimdSubj].Complete {
			t.Errorf("ComputeRootedFunctions(%v) = %+v, want Complete=true for verified pure .s leaf", pureSimdSubj, simdRooted[pureSimdSubj])
		}
		if simdRooted[counterSimdSubj].Complete {
			t.Errorf("ComputeRootedFunctions(%v) = %+v, want Complete=false for unverified raw-opcode .s leaf", counterSimdSubj, simdRooted[counterSimdSubj])
		}
		if simdRooted[asmMethodSubj].Complete {
			t.Errorf("ComputeRootedFunctions(%v) = %+v, want Complete=false for rejected assembly method", asmMethodSubj, simdRooted[asmMethodSubj])
		}
	}
}

func TestVerifyNonStdAssemblyMechanicalInvariants(t *testing.T) {
	t.Parallel()

	readMem := func(files map[string]string) func(string) ([]byte, error) {
		return func(full string) ([]byte, error) {
			content, ok := files[filepath.Base(full)]
			if !ok {
				return nil, os.ErrNotExist
			}
			return []byte(content), nil
		}
	}

	// 1. Multi-file RODATA ·sym sharing, file-local <>sym isolation, constant
	// arithmetic +0+4(SB) offsets, ·g(SB) RODATA symbol (not g register),
	// cross-header #include, and R14 overwrite before read on amd64.
	validAmd64Files := map[string]string{
		"a.h": "#include \"b.h\"\n",
		"b.h": "#define MIX_PAIR(a, b) \\\n\tXORL b, a; \\\n\tADDL $1, a\n",
		"tables.s": `#include "textflag.h"
DATA ·sharedLUT+0(SB)/4, $0xdeadbeef
DATA ·sharedLUT+0+4(SB)/4, $0xcafebabe
GLOBL ·sharedLUT(SB), RODATA, $8
DATA ·g+0(SB)/8, $0x0102030405060708
GLOBL ·g(SB), RODATA, $8
`,
		"kernel.s": `#include "textflag.h"
#include "a.h"

DATA fileLUT<>+0(SB)/4, $0x11223344
GLOBL fileLUT<>(SB), RODATA, $4

TEXT ·PureSIMD(SB), NOSPLIT, $0-16
	MOVL x+0(FP), AX
	CMPL AX, $0
	JEQ zero_r14
	MOVQ ·g+0(SB), R14
	JMP done_r14
zero_r14:
	XORL R14, R14
done_r14:
	ANDL $0, AX
	MOVL ·sharedLUT+0+4(SB)(AX*4), BX
	MOVL fileLUT<>+0(SB)(AX*4), CX
	ADDL R14, BX
	MIX_PAIR(BX, CX)
	MOVL BX, ret+8(FP)
	RET

TEXT ·StaticXgetbv(SB), NOSPLIT, $0-16
	MOVL idx+0(FP), CX
	BYTE $0x0f; BYTE $0x01; BYTE $0xd0
	MOVL AX, eax+8(FP)
	MOVL DX, edx+12(FP)
	RET

TEXT ·ImpureRdtscp(SB), NOSPLIT, $0-8
	BYTE $0x0f; BYTE $0x01; BYTE $0xf9
	MOVQ AX, ret+0(FP)
	RET

TEXT ·ImpureControlReg(SB), NOSPLIT, $0-4
	LDMXCSR csr+0(FP)
	RET

TEXT ·ImpureWordOnAmd64(SB), NOSPLIT, $0-0
	WORD $0xd5380000
	RET
`,
	}
	vpAmd64, ok := verifyNonStdAssemblyFiles(
		"amd64",
		"example.com/any-pkg/simd",
		"/virtual/pkg",
		[]string{"tables.s", "kernel.s"},
		[]string{"a.h", "b.h"},
		nil,
		readMem(validAmd64Files),
	)
	if !ok || vpAmd64 == nil {
		t.Fatalf("verifyNonStdAssemblyFiles(amd64) on valid multi-file package failed")
	}
	for _, pureName := range []string{"PureSIMD", "StaticXgetbv"} {
		sum, found := vpAmd64.funcs[pureName]
		if !found || sum.impureKind != "" || sum.cpuidArgs != 0 {
			t.Errorf("amd64 %s summary = %+v (found=%v), want pure non-cpuid summary", pureName, sum, found)
		}
	}
	for _, impureName := range []string{"ImpureRdtscp", "ImpureControlReg", "ImpureWordOnAmd64"} {
		sum, found := vpAmd64.funcs[impureName]
		if !found || sum.impureKind == "" {
			t.Errorf("amd64 %s summary = %+v (found=%v), want non-empty impureKind", impureName, sum, found)
		}
	}

	validArm64Files := map[string]string{
		"feat.s": `#include "textflag.h"
TEXT ·StaticArm64Features(SB), NOSPLIT, $0-24
	WORD $0xd5380000
	WORD $0xd5380600
	WORD $0xd2800002
	WORD $0x04225022
	WORD $0x04635023
	WORD $0xd37df042
	LSL $1, R2, R2
	MOVD R0, a+0(FP)
	MOVD R2, b+8(FP)
	MOVD R3, c+16(FP)
	RET

TEXT ·ImpureArm64Mpidr(SB), NOSPLIT, $0-8
	WORD $0xd53800a0
	MOVD R0, ret+0(FP)
	RET

TEXT ·ImpureByteOnArm64(SB), NOSPLIT, $0-0
	BYTE $0x0f; BYTE $0x01; BYTE $0xd0
	RET

TEXT ·ImpureDwordOnArm64(SB), NOSPLIT, $0-0
	DWORD $0xd503201fd53be020
	RET
`,
	}
	vpArm64, okArm := verifyNonStdAssemblyFiles(
		"arm64",
		"example.com/any/armpkg",
		"/virtual/armpkg",
		[]string{"feat.s"},
		nil,
		nil,
		readMem(validArm64Files),
	)
	if !okArm || vpArm64 == nil {
		t.Fatalf("verifyNonStdAssemblyFiles(arm64) failed")
	}
	if sum := vpArm64.funcs["StaticArm64Features"]; sum.impureKind != "" || sum.cpuidArgs != 0 {
		t.Errorf("arm64 StaticArm64Features summary = %+v, want pure", sum)
	}
	for _, impureName := range []string{"ImpureArm64Mpidr", "ImpureByteOnArm64", "ImpureDwordOnArm64"} {
		if sum := vpArm64.funcs[impureName]; sum.impureKind == "" {
			t.Errorf("arm64 %s summary = %+v, want non-empty impureKind", impureName, sum)
		}
	}

	// Unsupported GOARCH values must fail closed unconditionally.
	for _, unsupportedArch := range []string{"", "386", "arm", "riscv64", "ppc64le", "s390x", "wasm"} {
		if _, okArch := verifyNonStdAssemblyFiles(
			unsupportedArch,
			"example.com/arch",
			"/virtual/arch",
			[]string{"f.s"},
			nil,
			nil,
			readMem(map[string]string{"f.s": "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"}),
		); okArch {
			t.Errorf("verifyNonStdAssemblyFiles(%q) = true, want fail-closed false", unsupportedArch)
		}
	}

	// Uppercase G(...) macro and lowercase frame-slot labels (g+0(FP), fs+8(FP))
	// remain admitted while bare g / FS registers are rejected.
	if vpUpperG, okUpperG := verifyNonStdAssemblyFiles(
		"amd64",
		"example.com/upperg",
		"/virtual/upperg",
		[]string{"gslot.s"},
		nil,
		nil,
		readMem(map[string]string{"gslot.s": "#include \"textflag.h\"\n#define G(a, b) XORQ b, a\nTEXT ·SlotG(SB), NOSPLIT, $0-24\n\tMOVQ g+0(FP), AX\n\tMOVQ fs+8(FP), BX\n\tG(AX, BX)\n\tMOVQ AX, ret+16(FP)\n\tRET\n"}),
	); !okUpperG || vpUpperG == nil || vpUpperG.funcs["SlotG"].impureKind != "" {
		t.Errorf("verifyNonStdAssemblyFiles rejected valid G macro / g+0(FP) stack slot: ok=%v vp=%+v", okUpperG, vpUpperG)
	}

	// Canonical 1-arg and 2-arg amd64 ABI0 CPUID wrappers vs non-canonical CPUID shapes
	// (including 32-bit +4(FP) return layout and conditional #ifdef inside CPUID TEXT).
	cpuidAsm := `#include "textflag.h"
TEXT ·Cpuid1_386Layout(SB), NOSPLIT, $0-20
	MOVL op+0(FP), AX
	XORL CX, CX
	CPUID
	MOVL AX, eax+4(FP)
	MOVL BX, ebx+8(FP)
	MOVL CX, ecx+12(FP)
	MOVL DX, edx+16(FP)
	RET

TEXT ·Cpuid1_Amd64(SB), NOSPLIT, $0-24
	MOVL op+0(FP), AX
	XORQ CX, CX
	CPUID
	MOVL AX, eax+8(FP)
	MOVL BX, ebx+12(FP)
	MOVL CX, ecx+16(FP)
	MOVL DX, edx+20(FP)
	RET

TEXT ·Cpuid2_Amd64(SB), NOSPLIT, $0-24
	MOVL op+0(FP), AX
	MOVL op2+4(FP), CX
	CPUID
	MOVL AX, eax+8(FP)
	MOVL BX, ebx+12(FP)
	MOVL CX, ecx+16(FP)
	MOVL DX, edx+20(FP)
	RET

TEXT ·BadIfdefCpuid(SB), NOSPLIT, $0-24
	MOVL op+0(FP), AX
	XORQ CX, CX
#ifdef NEVER_SET
	MOVL $1, AX
#endif
	CPUID
	MOVL AX, eax+8(FP)
	MOVL BX, ebx+12(FP)
	MOVL CX, ecx+16(FP)
	MOVL DX, edx+20(FP)
	RET

TEXT ·BadHardcodedLeaf(SB), NOSPLIT, $0-24
	MOVL $1, AX
	XORQ CX, CX
	CPUID
	MOVL AX, eax+8(FP)
	MOVL BX, ebx+12(FP)
	MOVL CX, ecx+16(FP)
	MOVL DX, edx+20(FP)
	RET

TEXT ·BadShiftedEBX(SB), NOSPLIT, $0-24
	MOVL op+0(FP), AX
	XORQ CX, CX
	CPUID
	SHRL $24, BX
	MOVL AX, eax+8(FP)
	MOVL BX, ebx+12(FP)
	MOVL CX, ecx+16(FP)
	MOVL DX, edx+20(FP)
	RET

TEXT ·BadPermutedSlots(SB), NOSPLIT, $0-24
	MOVL op+0(FP), AX
	XORQ CX, CX
	CPUID
	MOVL BX, eax+8(FP)
	MOVL AX, ebx+12(FP)
	MOVL CX, ecx+16(FP)
	MOVL DX, edx+20(FP)
	RET
`
	vpCPUID, okCPUID := verifyNonStdAssemblyFiles(
		"amd64",
		"example.com/cpuid",
		"/virtual/cpuid",
		[]string{"cpuid.s"},
		nil,
		nil,
		readMem(map[string]string{"cpuid.s": cpuidAsm}),
	)
	if !okCPUID || vpCPUID == nil {
		t.Fatalf("verifyNonStdAssemblyFiles(cpuidAsm) failed")
	}
	for fn, wantArgs := range map[string]int{"Cpuid1_Amd64": 1, "Cpuid2_Amd64": 2} {
		if sum := vpCPUID.funcs[fn]; sum.cpuidArgs != wantArgs || sum.impureKind != "" {
			t.Errorf("%s summary = %+v, want cpuidArgs=%d impureKind=\"\"", fn, sum, wantArgs)
		}
	}
	for _, badFn := range []string{"Cpuid1_386Layout", "BadIfdefCpuid", "BadHardcodedLeaf", "BadShiftedEBX", "BadPermutedSlots"} {
		if sum := vpCPUID.funcs[badFn]; sum.cpuidArgs != 0 || sum.impureKind == "" {
			t.Errorf("%s summary = %+v, want cpuidArgs=0 and non-empty impureKind", badFn, sum)
		}
	}
	u32 := types.Typ[types.Uint32]
	sig1 := types.NewSignatureType(nil, nil, nil,
		types.NewTuple(types.NewVar(token.NoPos, nil, "op", u32)),
		types.NewTuple(types.NewVar(token.NoPos, nil, "", u32), types.NewVar(token.NoPos, nil, "", u32), types.NewVar(token.NoPos, nil, "", u32), types.NewVar(token.NoPos, nil, "", u32)),
		false)
	sig2 := types.NewSignatureType(nil, nil, nil,
		types.NewTuple(types.NewVar(token.NoPos, nil, "op", u32), types.NewVar(token.NoPos, nil, "sub", u32)),
		types.NewTuple(types.NewVar(token.NoPos, nil, "", u32), types.NewVar(token.NoPos, nil, "", u32), types.NewVar(token.NoPos, nil, "", u32), types.NewVar(token.NoPos, nil, "", u32)),
		false)
	if !isCanonicalCPUIDSignature(sig1, 1) || isCanonicalCPUIDSignature(sig1, 2) || !isCanonicalCPUIDSignature(sig2, 2) || isCanonicalCPUIDSignature(sig2, 1) {
		t.Errorf("isCanonicalCPUIDSignature arity mismatch admitted or valid signature rejected")
	}

	// 2. Package-level rejections across amd64 and arm64.
	type rejectCase struct {
		arch string
		body string
	}
	for caseName, rc := range map[string]rejectCase{
		"writable-globl":        {"amd64", "#include \"textflag.h\"\nGLOBL ·writable(SB), NOPTR, $8\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"},
		"two-op-bss-globl":      {"amd64", "#include \"textflag.h\"\nGLOBL ·bss(SB), $8\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"},
		"zero-size-globl":       {"amd64", "#include \"textflag.h\"\nGLOBL ·empty(SB), RODATA, $0\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"},
		"globl-sub-flag":        {"amd64", "#include \"textflag.h\"\nGLOBL ·counter(SB), RODATA - 8, $8\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"},
		"globl-carry-flag":      {"amd64", "#include \"textflag.h\"\nGLOBL ·counter(SB), RODATA + RODATA, $8\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"},
		"globl-shift-tlsbss":    {"amd64", "#include \"textflag.h\"\nGLOBL ·tls(SB), RODATA | (1 << 8), $8\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"},
		"reserved-define":       {"amd64", "#include \"textflag.h\"\n#ifdef NEVER\n#define WORD CMPQ AX,\n#endif\nTEXT ·F(SB), NOSPLIT, $0-0\n\tWORD $0x050f\n\tRET\n"},
		"reserved-rdpid":        {"amd64", "#include \"textflag.h\"\n#define RDPID NOP\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"},
		"reserved-cntvct":       {"arm64", "#include \"textflag.h\"\n#define CNTVCT_EL0 MIDR_EL1\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"},
		"reserved-g":            {"arm64", "#include \"textflag.h\"\n#define g R0\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"},
		"reserved-init-macro":   {"amd64", "#include \"textflag.h\"\n#define init Helper\nTEXT ·init(SB), NOSPLIT, $0-0\n\tRET\n"},
		"reserved-undef":        {"amd64", "#include \"textflag.h\"\n#undef WORD\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"},
		"middledot-macro-alias": {"amd64", "#include \"textflag.h\"\n#define EvilVar SafeLut\nGLOBL ·SafeLut(SB), RODATA, $8\nTEXT ·F(SB), NOSPLIT, $0-8\n\tMOVQ ·EvilVar(SB), AX\n\tMOVQ AX, ret+0(FP)\n\tRET\n"},
		"asm-init-fn":           {"amd64", "#include \"textflag.h\"\nTEXT ·init(SB), NOSPLIT, $0-0\n\tRET\n"},
		"asm-method-text":       {"amd64", "#include \"textflag.h\"\nTEXT ·Box·M(SB), NOSPLIT, $0-8\n\tRET\n"},
		"abiinternal-text":      {"amd64", "#include \"textflag.h\"\nTEXT ·F<ABIInternal>(SB), NOSPLIT, $0-0\n\tRET\n"},
		"nested-ifdef-text":     {"amd64", "#include \"textflag.h\"\nTEXT ·Pure(SB), NOSPLIT, $0-0\n\tRET\n#ifdef NEVER\nTEXT ·Unused(SB), NOSPLIT, $0-0\n\tRET\n#endif\n"},
		"ifdef-text-spill":      {"amd64", "#include \"textflag.h\"\n#ifdef MAYBE\nTEXT ·CondFn(SB), NOSPLIT, $0-0\n\tRET\n#endif\n\tRDTSC\n\tRET\n"},
		"sb-store":              {"amd64", "#include \"textflag.h\"\nGLOBL ·ro(SB), RODATA, $8\nTEXT ·F(SB), NOSPLIT, $0-0\n\tMOVQ AX, ·ro(SB)\n\tRET\n"},
		"sb-neg-offset":         {"amd64", "#include \"textflag.h\"\nGLOBL ·ro(SB), RODATA, $8\nTEXT ·F(SB), NOSPLIT, $0-8\n\tMOVQ ·ro-8(SB), AX\n\tRET\n"},
		"sb-wrap-offset":        {"amd64", "#include \"textflag.h\"\nGLOBL ·ro(SB), RODATA, $8\nTEXT ·F(SB), NOSPLIT, $0-8\n\tMOVQ ·ro+0xfffffffffffffff8(SB), AX\n\tRET\n"},
		"sb-spaced-store":       {"amd64", "#include \"textflag.h\"\nGLOBL ·ro(SB), RODATA, $8\nTEXT ·F(SB), NOSPLIT, $0-0\n\tMOVQ AX, ·ro( SB )\n\tRET\n"},
		"sb-data-spaced":        {"amd64", "#include \"textflag.h\"\nGLOBL ·ro(SB), RODATA, $8\nDATA ·ro+0( SB )/8, $1\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"},
		"sb-rmw":                {"amd64", "#include \"textflag.h\"\nGLOBL ·ro(SB), RODATA, $8\nTEXT ·F(SB), NOSPLIT, $0-0\n\tXCHGQ AX, ·ro(SB)\n\tRET\n"},
		"sb-arm64-stxr":         {"arm64", "#include \"textflag.h\"\nGLOBL ·ro(SB), RODATA, $8\nTEXT ·F(SB), NOSPLIT, $0-0\n\tSTXR R0, ·ro(SB), R1\n\tRET\n"},
		"sb-arm64-casd":         {"arm64", "#include \"textflag.h\"\nGLOBL ·ro(SB), RODATA, $8\nTEXT ·F(SB), NOSPLIT, $0-0\n\tCASD R0, ·ro(SB), R1\n\tRET\n"},
		"sb-arm64-ldord":        {"arm64", "#include \"textflag.h\"\nGLOBL ·ro(SB), RODATA, $8\nTEXT ·F(SB), NOSPLIT, $0-0\n\tLDORD R0, ·ro(SB), R1\n\tRET\n"},
		"unverified-sb":         {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-8\n\tMOVQ ·goVar(SB), AX\n\tMOVQ AX, ret+0(FP)\n\tRET\n"},
		"cross-pkg-sb":          {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-8\n\tMOVQ runtime·goarm64(SB), AX\n\tMOVQ AX, ret+0(FP)\n\tRET\n"},
		"call-instr":            {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tCALL ·G(SB)\n\tRET\n"},
		"reg-label-spoof":       {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\nAX:\n\tJMP AX\n"},
		"tls-access":            {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tMOVQ (TLS), AX\n\tRET\n"},
		"tls-spaced":            {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tMOVQ 0( TLS ), AX\n\tRET\n"},
		"tls-bare":              {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tMOVQ TLS, AX\n\tRET\n"},
		"tls-scaled":            {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tMOVQ 0(AX)(TLS*1), BX\n\tRET\n"},
		"arm64-g-reg":           {"arm64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tMOVD 16(g), R0\n\tRET\n"},
		"arm64-r28-reg":         {"arm64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tMOVD R28, R0\n\tRET\n"},
		"arm64-r18-reg":         {"arm64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tMOVD R18, R0\n\tRET\n"},
		"arm64-param-r28":       {"arm64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tMOVD R(28), R0\n\tRET\n"},
		"arm64-spr-reg":         {"arm64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tMOVD SPR(21307), R0\n\tRET\n"},
		"amd64-gs-seg":          {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tMOVQ 0(GS), AX\n\tRET\n"},
		"amd64-fs-seg":          {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tMOVQ FS, AX\n\tRET\n"},
		"amd64-cr3-reg":         {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tMOVQ CR3, AX\n\tRET\n"},
		"amd64-dr0-reg":         {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tMOVQ DR0, AX\n\tRET\n"},
		"amd64-mrs-wrong-isa":   {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tMRS MIDR_EL1, R8\n\tRET\n"},
		"arm64-cpuid-wrong-isa": {"arm64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tCPUID\n\tRET\n"},
		"amd64-r14-entry-read":  {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-8\n\tMOVQ (R14), AX\n\tMOVQ AX, ret+0(FP)\n\tRET\n"},
		"amd64-r14-partial":     {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-8\n\tMOVW $0, R14W\n\tMOVQ R14, ret+0(FP)\n\tRET\n"},
		"amd64-r14-cmov":        {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-8\n\tCMOVQEQ CX, R14\n\tMOVQ R14, ret+0(FP)\n\tRET\n"},
		"amd64-r14-branch-skip": {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-16\n\tCMPQ x+0(FP), $0\n\tJEQ skip\n\tMOVQ $0, R14\nskip:\n\tMOVQ R14, ret+8(FP)\n\tRET\n"},
		"amd64-r14-ifdef-skip":  {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-8\n#ifdef MAYBE\n\tMOVQ $0, R14\n#endif\n\tMOVQ R14, ret+0(FP)\n\tRET\n"},
		"amd64-r14-masked-vmov": {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-8\n\tVMOVQ X0, K1, R14\n\tMOVQ R14, ret+0(FP)\n\tRET\n"},
		"arm64-tpidr-tls":       {"arm64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-8\n\tMOVD TPIDR_EL0, R0\n\tMOVD R0, ret+0(FP)\n\tRET\n"},
		"arm64-scxtnum-tls":     {"arm64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-8\n\tMOVD SCXTNUM_EL0, R0\n\tMOVD R0, ret+0(FP)\n\tRET\n"},
		"colon-operand-pair":    {"arm64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-8\n\tMOVD R0:CNTVCT_EL0\n\tMOVD R0, ret+0(FP)\n\tRET\n"},
		"colon-globl":           {"amd64", "#include \"textflag.h\"\nGLOBL ·ro(SB), $8:RODATA\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"},
		"ret-reg-tailjump":      {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET AX\n"},
		"ret-sb-tailcall":       {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET ·G(SB)\n"},
		"arm64-retaa":           {"arm64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRETAA\n"},
		"duffcopy-call":         {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tDUFFCOPY $0\n\tRET\n"},
		"duffzero-call":         {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tDUFFZERO $0\n\tRET\n"},
		"arm64-adr-pcrel":       {"arm64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-8\n\tADR 0(PC), R0\n\tMOVD R0, ret+0(FP)\n\tRET\n"},
		"arm64-adrp-pcrel":      {"arm64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-8\n\tADRP 4096(PC), R0\n\tMOVD R0, ret+0(FP)\n\tRET\n"},
		"amd64-leaq-pc":         {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-8\n\tLEAQ 0(PC), AX\n\tMOVQ AX, ret+0(FP)\n\tRET\n"},
		"amd64-movq-pc":         {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-8\n\tMOVQ 0x1000(PC), AX\n\tMOVQ AX, ret+0(FP)\n\tRET\n"},
		"arm64-cbz-pc-operand":  {"arm64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\nloop:\n\tCBZ PC, loop\n\tRET\n"},
		"amd64-spb-label-spoof": {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\nSPB:\n\tJMP SPB\n"},
		"arm64-pn0-label-spoof": {"arm64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\nPN0:\n\tB PN0\n"},
		"reserved-fpcr-macro":   {"arm64", "#include \"textflag.h\"\n#define FPCR R0\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"},
		"unclosed-quote-imm":    {"amd64", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tMOVQ $\"unclosed, AX\n\tRET\n"},
	} {
		if _, ok := verifyNonStdAssemblyFiles(
			rc.arch,
			"example.com/reject",
			"/virtual/reject",
			[]string{"bad.s"},
			nil,
			nil,
			readMem(map[string]string{"bad.s": rc.body}),
		); ok {
			t.Errorf("case %s (%s): verifyNonStdAssemblyFiles = true, want false", caseName, rc.arch)
		}
	}

	// Exhaustive #ifdef / #else R14 overwrite on both arms must pass on amd64.
	if vpIfElseR14, okIfElseR14 := verifyNonStdAssemblyFiles(
		"amd64",
		"example.com/r14ifelse",
		"/virtual/r14ifelse",
		[]string{"ok.s"},
		nil,
		nil,
		readMem(map[string]string{"ok.s": "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-8\n#ifdef MAYBE\n\tMOVQ $1, R14\n#else\n\tXORL R14, R14\n#endif\n\tMOVQ R14, ret+0(FP)\n\tRET\n"}),
	); !okIfElseR14 || vpIfElseR14 == nil || vpIfElseR14.funcs["F"].impureKind != "" {
		t.Errorf("verifyNonStdAssemblyFiles rejected exhaustive #ifdef/#else R14 kill: ok=%v vp=%+v", okIfElseR14, vpIfElseR14)
	}

	// Quoted character and string literals containing commas, semicolons,
	// parentheses, pseudo-register substrings, and middle-dot runes in DATA
	// initializers and TEXT immediate operands must parse as single literals
	// without false rejection, while unclosed quotes fail closed.
	quotedAsm := `#include "textflag.h"
GLOBL ·lut(SB), RODATA, $8
DATA ·lut+0(SB)/8, $"a,b;(·)"
TEXT ·QuotePure(SB), NOSPLIT, $0-8
	MOVQ $';', R14; CMPQ R14, $'·'
	CMPB ·lut(SB), $','
	CMPQ R14, $"x(SB)"
	CMPQ R14, $"y(TLS)"
	MOVQ R14, ret+0(FP)
	RET
`
	if vpQuote, okQuote := verifyNonStdAssemblyFiles(
		"amd64",
		"example.com/quoteasm",
		"/virtual/quoteasm",
		[]string{"q.s"},
		nil,
		nil,
		readMem(map[string]string{"q.s": quotedAsm}),
	); !okQuote || vpQuote == nil || vpQuote.funcs["QuotePure"].impureKind != "" {
		t.Errorf("verifyNonStdAssemblyFiles rejected quoted DATA/immediate literals: ok=%v vp=%+v", okQuote, vpQuote)
	}
	if !hasUnquotedColon(`$"unclosed`) || !hasUnquotedColon(`$'x`) {
		t.Errorf("hasUnquotedColon failed open on unclosed quote")
	}
	if _, okHybrid := verifyNonStdAssemblyFiles(
		"amd64",
		"example.com/quoteasm",
		"/virtual/quoteasm",
		[]string{"bad.s"},
		nil,
		nil,
		readMem(map[string]string{"bad.s": "#include \"textflag.h\"\nGLOBL ·lut(SB), RODATA, $8\nTEXT ·F(SB), NOSPLIT, $0-0\n\tMOVQ $\"x\"·lut(SB), AX\n\tRET\n"}),
	); okHybrid {
		t.Errorf("verifyNonStdAssemblyFiles admitted malformed quoted-prefix (SB) operand")
	}

	// Width-suffixed system/RNG/TSX/FPU mnemonics and conditional
	// or split BYTE sequences must classify as impure per TEXT symbol.
	impureAmd64Asm := `#include "textflag.h"
TEXT ·RdrandQ(SB), NOSPLIT, $0-0
	RDRANDQ AX
	RET
TEXT ·RdseedL(SB), NOSPLIT, $0-0
	RDSEEDL AX
	RET
TEXT ·WrfsbaseQ(SB), NOSPLIT, $0-0
	WRFSBASEQ AX
	RET
TEXT ·RdpmcOp(SB), NOSPLIT, $0-0
	RDPMC
	RET
TEXT ·TsxOp(SB), NOSPLIT, $0-0
	XTEST
	RET
TEXT ·StdFlag(SB), NOSPLIT, $0-0
	STD
	RET
TEXT ·FxrstorOp(SB), NOSPLIT, $0-0
	FXRSTOR 0(SP)
	RET
TEXT ·SmswOp(SB), NOSPLIT, $0-0
	SMSWQ AX
	RET
TEXT ·LslAmd64(SB), NOSPLIT, $0-0
	LSLQ AX, BX
	RET
TEXT ·PopfqOp(SB), NOSPLIT, $0-0
	POPFQ
	RET
TEXT ·PushfqOp(SB), NOSPLIT, $0-0
	PUSHFQ
	RET
TEXT ·LfsqOp(SB), NOSPLIT, $0-0
	LFSQ 0(SP), AX
	RET
TEXT ·GetcallerpcOp(SB), NOSPLIT, $0-0
	GETCALLERPC AX
	RET
TEXT ·UndefOp(SB), NOSPLIT, $0-0
	UNDEF
	RET
TEXT ·CondByte(SB), NOSPLIT, $0-0
#ifdef MAYBE
	BYTE $0x0f; BYTE $0x01; BYTE $0xd0
#endif
	RET
TEXT ·SplitByte(SB), NOSPLIT, $0-0
	BYTE $0x0f; BYTE $0x01
#ifdef NEVER
#endif
	BYTE $0xd0
	RET
`
	if vpImp, okImp := verifyNonStdAssemblyFiles(
		"amd64",
		"example.com/impureops",
		"/virtual/impureops",
		[]string{"imp.s"},
		nil,
		nil,
		readMem(map[string]string{"imp.s": impureAmd64Asm}),
	); !okImp || vpImp == nil {
		t.Fatalf("verifyNonStdAssemblyFiles(impureAmd64Asm) = %v, want ok=true with impure summaries", okImp)
	} else {
		for _, fn := range []string{"RdrandQ", "RdseedL", "WrfsbaseQ", "RdpmcOp", "TsxOp", "StdFlag", "FxrstorOp", "SmswOp", "LslAmd64", "PopfqOp", "PushfqOp", "LfsqOp", "GetcallerpcOp", "UndefOp", "CondByte", "SplitByte"} {
			if sum := vpImp.funcs[fn]; sum.impureKind == "" {
				t.Errorf("amd64 %s summary = %+v, want non-empty impureKind", fn, sum)
			}
		}
	}

	impureArm64Asm := `#include "textflag.h"
TEXT ·MovdMidrPure(SB), NOSPLIT, $0-8
	PCALIGNMAX $32, $16
	MOVD MIDR_EL1, R0
	MOVD R0, ret+0(FP)
	RET
TEXT ·SyslOp(SB), NOSPLIT, $0-0
	SYSL $0, R0
	RET
TEXT ·SvcEqOp(SB), NOSPLIT, $0-0
	SVC.EQ $0
	RET
TEXT ·MovdPmccntr(SB), NOSPLIT, $0-8
	MOVD PMCCNTR_EL0, R0
	MOVD R0, ret+0(FP)
	RET
TEXT ·MovdWriteFpcr(SB), NOSPLIT, $0-0
	MOVD R0, FPCR
	RET
TEXT ·MovdPstateDit(SB), NOSPLIT, $0-0
	MOVD $1, DIT
	RET
TEXT ·MovdMidrBadDst(SB), NOSPLIT, $0-0
	MOVD MIDR_EL1, RSP
	RET
TEXT ·WordClobberR18(SB), NOSPLIT, $0-0
	WORD $0xd2800012
	RET
TEXT ·WordReadR28(SB), NOSPLIT, $0-0
	WORD $0xd340ff80
	RET
`
	if vpImpArm, okImpArm := verifyNonStdAssemblyFiles(
		"arm64",
		"example.com/impurearm",
		"/virtual/impurearm",
		[]string{"imp.s"},
		nil,
		nil,
		readMem(map[string]string{"imp.s": impureArm64Asm}),
	); !okImpArm || vpImpArm == nil {
		t.Fatalf("verifyNonStdAssemblyFiles(impureArm64Asm) = %v, want ok=true", okImpArm)
	} else {
		if sum := vpImpArm.funcs["MovdMidrPure"]; sum.impureKind != "" || sum.cpuidArgs != 0 {
			t.Errorf("arm64 MovdMidrPure summary = %+v, want pure", sum)
		}
		for _, fn := range []string{"SyslOp", "SvcEqOp", "MovdPmccntr", "MovdWriteFpcr", "MovdPstateDit", "MovdMidrBadDst", "WordClobberR18", "WordReadR28"} {
			if sum := vpImpArm.funcs[fn]; sum.impureKind == "" {
				t.Errorf("arm64 %s summary = %+v, want non-empty impureKind", fn, sum)
			}
		}
	}

	// Uppercase .S extension (GAS C-preprocessed assembly) must be rejected.
	if _, okUpperS := verifyNonStdAssemblyFiles(
		"amd64",
		"example.com/uppers",
		"/virtual/uppers",
		[]string{"bad.S"},
		nil,
		nil,
		readMem(map[string]string{"bad.S": "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"}),
	); okUpperS {
		t.Errorf("verifyNonStdAssemblyFiles admitted uppercase .S assembly file")
	}
	if isAsm, _, isOther := classifyOtherNativeExt(".S"); isAsm || !isOther {
		t.Errorf("classifyOtherNativeExt(\".S\") = (isAsm=%v, isOther=%v), want (false, true)", isAsm, isOther)
	}

	// Cyclic #include between local headers must fail closed cleanly.
	if _, okCycle := verifyNonStdAssemblyFiles(
		"amd64",
		"example.com/cycle",
		"/virtual/cycle",
		[]string{"c.s"},
		[]string{"c1.h", "c2.h"},
		nil,
		readMem(map[string]string{
			"c1.h": "#include \"c2.h\"\n",
			"c2.h": "#include \"c1.h\"\n",
			"c.s":  "#include \"textflag.h\"\n#include \"c1.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n",
		}),
	); okCycle {
		t.Errorf("verifyNonStdAssemblyFiles admitted cyclic #include")
	}

	// Conditional #define, conditional #undef, trailing #define after TEXT, and
	// un-#include'd .h files in hFiles must NOT rewrite earlier/un-included sites.
	condMacroAsm := `#include "textflag.h"
#ifdef NEVER_DEFINED
#define OPT_REG MIDR_EL1
#endif
#define SAFE_REG MIDR_EL1
#ifdef MAYBE_UNDEF
#undef SAFE_REG
#endif
TEXT ·CondSneak(SB), NOSPLIT, $0-8
	MRS OPT_REG, R0
	MOVD R0, ret+0(FP)
	RET
TEXT ·UndefSneak(SB), NOSPLIT, $0-8
	MRS SAFE_REG, R0
	MOVD R0, ret+0(FP)
	RET
TEXT ·TrailingSneak(SB), NOSPLIT, $0-8
	MRS LATE_REG, R0
	MOVD R0, ret+0(FP)
	RET
#define LATE_REG MIDR_EL1
`
	if vpCond, okCond := verifyNonStdAssemblyFiles(
		"arm64",
		"example.com/cond",
		"/virtual/cond",
		[]string{"cond.s"},
		[]string{"unused.h"},
		nil,
		readMem(map[string]string{
			"unused.h": "#define OPT_REG MIDR_EL1\n#define LATE_REG MIDR_EL1\n",
			"cond.s":   condMacroAsm,
		}),
	); !okCond || vpCond == nil {
		t.Fatalf("verifyNonStdAssemblyFiles(condMacroAsm) = %v, want ok=true with impure summaries", okCond)
	} else {
		for _, fn := range []string{"CondSneak", "UndefSneak", "TrailingSneak"} {
			if sum := vpCond.funcs[fn]; sum.impureKind == "" {
				t.Errorf("%s summary = %+v, want non-empty impureKind", fn, sum)
			}
		}
	}
	if _, okFuncMacro := verifyNonStdAssemblyFiles(
		"amd64",
		"example.com/condfn",
		"/virtual/condfn",
		[]string{"condfn.s"},
		nil,
		nil,
		readMem(map[string]string{"condfn.s": "#include \"textflag.h\"\n#ifdef NEVER_DEFINED\n#define MAYBE_SAFE(x) MOVQ $0, AX\n#endif\nTEXT ·F(SB), NOSPLIT, $0-0\n\tMAYBE_SAFE(WORD $0x050f)\n\tRET\n"}),
	); okFuncMacro {
		t.Errorf("verifyNonStdAssemblyFiles admitted unexpanded function-like macro invocation")
	}

	// Multi-compartment typeScopes: a GLOBL colliding with a Go variable in the
	// test scope must be rejected even when absent from the base scope.
	basePkg := types.NewPackage("example.com/sc", "sc")
	testPkg := types.NewPackage("example.com/sc", "sc")
	testPkg.Scope().Insert(types.NewVar(token.NoPos, testPkg, "testLut", types.Typ[types.Int]))
	if _, ok := verifyNonStdAssemblyFiles(
		"amd64",
		"example.com/sc",
		"/virtual/sc",
		[]string{"lut.s"},
		nil,
		[]*types.Package{basePkg, testPkg},
		readMem(map[string]string{"lut.s": "#include \"textflag.h\"\nGLOBL ·testLut(SB), RODATA, $8\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"}),
	); ok {
		t.Errorf("verifyNonStdAssemblyFiles admitted GLOBL colliding with test-compartment Go variable")
	}

	// 3. Go stub signature safety: methods, carrier types, and uintptr are rejected
	// while basic scalars, slices, arrays, pointers, and carrier-free structs pass.
	i32 := types.Typ[types.Uint32]
	uptr := types.Typ[types.Uintptr]
	up := types.Typ[types.UnsafePointer]
	fnSig := types.NewSignatureType(nil, nil, nil, types.NewTuple(types.NewVar(token.NoPos, nil, "x", i32)), types.NewTuple(types.NewVar(token.NoPos, nil, "", types.NewSlice(i32))), false)
	if !asmSignatureCarrierFree(fnSig) {
		t.Errorf("asmSignatureCarrierFree rejected scalar/slice signature")
	}
	methodSig := types.NewSignatureType(types.NewVar(token.NoPos, nil, "recv", i32), nil, nil, nil, nil, false)
	if asmSignatureCarrierFree(methodSig) {
		t.Errorf("asmSignatureCarrierFree admitted method signature with receiver")
	}
	for badKind, badType := range map[string]types.Type{
		"uintptr":        uptr,
		"unsafe.Pointer": up,
		"interface":      types.Universe.Lookup("error").Type(),
		"func":           types.NewSignatureType(nil, nil, nil, nil, nil, false),
		"chan":           types.NewChan(types.SendRecv, i32),
		"map":            types.NewMap(i32, i32),
	} {
		badSig := types.NewSignatureType(nil, nil, nil, types.NewTuple(types.NewVar(token.NoPos, nil, "x", badType)), nil, false)
		if asmSignatureCarrierFree(badSig) {
			t.Errorf("asmSignatureCarrierFree admitted %s parameter", badKind)
		}
	}

	// 4. Unaudited toolchain gate & Program.Summaries memoization:
	// nonSSAGlobalHazards must block .s packages when audited == false or GOARCH == "".
	pureAsmDir := t.TempDir()
	writeFile(t, pureAsmDir, "pure.s", "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n")
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, filepath.Join(pureAsmDir, "pure.go"), "package p\nfunc F()\n", parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		pureTypesPkg := types.NewPackage("example.com/pureasm", "p")
		fakePkg := &packages.Package{
			PkgPath:    "example.com/pureasm",
			Dir:        pureAsmDir,
			GoFiles:    []string{filepath.Join(pureAsmDir, "pure.go")},
			OtherFiles: []string{filepath.Join(pureAsmDir, "pure.s")},
			Syntax:     []*ast.File{af},
			Types:      pureTypesPkg,
		}
		fakeProg := &program{
			GOARCH:    runtime.GOARCH,
			Pkgs:      []*packages.Package{fakePkg},
			Summaries: map[string]any{},
		}
		blockedUnaud, _ := nonSSAGlobalHazards(false, fakeProg)
		if !blockedUnaud["example.com/pureasm"] {
			t.Errorf("nonSSAGlobalHazards(audited=false) did not block .s package")
		}
		blockedAud, _ := nonSSAGlobalHazards(true, fakeProg)
		if blockedAud["example.com/pureasm"] {
			t.Errorf("nonSSAGlobalHazards(audited=true) blocked verified pure .s package")
		}
		noArchProg := &program{
			GOARCH:    "",
			Pkgs:      []*packages.Package{fakePkg},
			Summaries: map[string]any{},
		}
		blockedNoArch, _ := nonSSAGlobalHazards(true, noArchProg)
		if !blockedNoArch["example.com/pureasm"] {
			t.Errorf("nonSSAGlobalHazards(GOARCH=\"\") did not fail closed")
		}

		// p.ReadSource snapshot must take precedence over disk files so
		// concurrent disk edits cannot diverge from the pass's hashed content.
		snapProg := &program{
			GOARCH:    runtime.GOARCH,
			Pkgs:      []*packages.Package{fakePkg},
			Summaries: map[string]any{},
			ReadSource: func(_, _ string) ([]byte, error) {
				return []byte("#include \"textflag.h\"\nGLOBL ·mut(SB), NOPTR, $8\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"), nil
			},
		}
		blockedSnap, _ := nonSSAGlobalHazards(true, snapProg)
		if !blockedSnap["example.com/pureasm"] {
			t.Errorf("nonSSAGlobalHazards(audited=true) ignored p.ReadSource snapshot")
		}

		// Dotless user modules (`module mymod` -> PkgPath "mymod" with non-nil
		// Module) must NOT be skipped as standard-library packages: pure verified
		// .s populates verifiedAsm["mymod"], while linkname/native hazards populate
		// blockedPkgs["mymod"] and linknamedVars.
		dotlessTypesPkg := types.NewPackage("mymod", "mymod")
		dotlessGoFile, err := parser.ParseFile(fset, filepath.Join(pureAsmDir, "dotless.go"), "package mymod\nimport _ \"unsafe\"\n//go:linkname hooked other.sym\nvar hooked bool\nfunc F()\n", parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		dotlessPkg := &packages.Package{
			PkgPath:    "mymod",
			Module:     &packages.Module{Path: "mymod"},
			Dir:        pureAsmDir,
			GoFiles:    []string{filepath.Join(pureAsmDir, "dotless.go")},
			OtherFiles: []string{filepath.Join(pureAsmDir, "pure.s")},
			Syntax:     []*ast.File{dotlessGoFile},
			Types:      dotlessTypesPkg,
		}
		dotlessPureProg := &program{
			GOARCH:    runtime.GOARCH,
			Pkgs:      []*packages.Package{dotlessPkg},
			Summaries: map[string]any{},
		}
		dotlessHaz := nonSSAGlobalHazardsSummary(true, dotlessPureProg)
		if dotlessHaz.blockedPkgs["mymod"] {
			t.Errorf("dotless user module with verified pure .s was blocked")
		}
		if dotlessHaz.verifiedAsm["mymod"] == nil || !dotlessHaz.verifiedAsm["mymod"].ok {
			t.Errorf("dotless user module verifiedAsm[\"mymod\"] = %+v, want verified", dotlessHaz.verifiedAsm["mymod"])
		}
		if !dotlessHaz.linknamedVars[pkgVarKey{pkgPath: "mymod", name: "hooked"}] {
			t.Errorf("dotless user module //go:linkname variable was skipped by nonSSAGlobalHazardsSummary")
		}
		dotlessImpureProg := &program{
			GOARCH:    runtime.GOARCH,
			Pkgs:      []*packages.Package{dotlessPkg},
			Summaries: map[string]any{},
			ReadSource: func(_, _ string) ([]byte, error) {
				return []byte("#include \"textflag.h\"\nGLOBL ·mut(SB), NOPTR, $8\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRET\n"), nil
			},
		}
		if blockedDotless, _ := nonSSAGlobalHazards(true, dotlessImpureProg); !blockedDotless["mymod"] {
			t.Errorf("dotless user module with writable .s GLOBL was not blocked")
		}
	}

	// 5. pkgFreeOfUnverifiedNativeWriteHazard fails closed without panic when idx.meta == nil.
	emptyBase := &tier2Base{idxByTypes: map[*types.Package]*pkgIndex{}}
	if emptyBase.pkgFreeOfUnverifiedNativeWriteHazard(&pkgIndex{meta: nil}) {
		t.Errorf("pkgFreeOfUnverifiedNativeWriteHazard admitted non-std pkgIndex with nil meta")
	}
}

