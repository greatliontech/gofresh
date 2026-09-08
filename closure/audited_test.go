package closure

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/auditset"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// The audited-pure widening: subjects reaching pure standard
// computation prove observable, while the two soundness exclusions -
// flag registration (covert Parse-time channel) and reflect (defeats
// reachability) - stay blocked
// (REQ-closure-observability-analysis's audited-set boundary).
func TestAuditedPureWideningAndExclusions(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
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
	h, err := NewAt(dir)
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
// (REQ-closure-observability-analysis's audited-set boundary).
func TestAuditedValueConstructorAndComparatorAdmissions(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	for _, sub := range []string{"values", "entropylocal", "entropyparam", "calendar", "stamp", "clock", "mirror", "span", "timer", "parsed", "unixzone"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, dir, "go.mod", "module example.com/audited\n\ngo 1.26\n")
	writeFile(t, dir, "values/values.go", `package values

import (
	"math/big"
	"reflect"
)

var answer = big.NewInt(42)

func Equal() bool {
	return reflect.DeepEqual(big.NewInt(42), answer)
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

// RandLocal draws entropy through math/rand's own constructor: the
// ambient entry is the caller's, refused at the caller, never inside
// the admitted package.
func RandLocal() string {
	return new(big.Int).Rand(rand.New(rand.NewSource(7)), big.NewInt(100)).String()
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
// body reaches no ambient constructor; whoever constructs the source
// carries the refusal.
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
	_ = RandParam(rand.New(rand.NewSource(7)))
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
	// (Time).UTC, Location, and AddDate share their names with ambient
	// declarations and are excluded whole; a fixed zone and Add say
	// the same things.
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
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{
		{Package: "example.com/audited/values", Symbol: "Equal"},
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
	})
	if err != nil {
		t.Fatal(err)
	}
	equal := proofs[Subject{Package: "example.com/audited/values", Symbol: "Equal"}]
	if !equal.Observable {
		t.Fatalf("Equal = %+v, want the constructor/comparator subject observable", equal)
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
}

// The admission sets are exactly the audited names: constructors and
// execution-free references in, every ambient or reflective neighbor
// out (REQ-closure-observability-analysis's audited-set boundary).
func TestAuditedPureStandardBounds(t *testing.T) {
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
	for _, tc := range []struct{ pkg, name string }{
		// flag's registration families (Bool, BoolVar, Var, Func, …) are
		// admitted program-wide as sinks by the registration-facts
		// judgment, never by this predicate: the rows below pin that no
		// flag operation is pure-admitted by name.
		{"flag", "Parse"}, {"flag", "Parsed"}, {"flag", "Lookup"}, {"flag", "Set"}, {"flag", "Args"}, {"flag", "NArg"},
		{"flag", "Name"}, {"flag", "UnquoteUsage"},
		{"flag", "Arg"}, {"flag", "NFlag"}, {"flag", "Visit"}, {"flag", "VisitAll"}, {"flag", "PrintDefaults"},
		{"flag", "Output"}, {"flag", "SetOutput"}, {"flag", "Init"}, {"flag", "Usage"}, {"flag", "Var"}, {"flag", "Func"},
		{"flag", "BoolFunc"}, {"flag", "TextVar"}, {"flag", "Bool"}, {"flag", "BoolVar"}, {"flag", "ErrHelp"},
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
		// time.UTC variable), AddDate (re-enters Date through it).
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
	if !auditedRuntimeTypeSymbol(true, "reflect", "DeepEqual") {
		t.Error("auditedRuntimeTypeSymbol(true, reflect, DeepEqual) = false, want the invoke-nothing comparator audited")
	}
	for _, name := range []string{"ValueOf", "Value", "New", "MakeFunc", "Indirect"} {
		if auditedRuntimeTypeSymbol(true, "reflect", name) {
			t.Errorf("auditedRuntimeTypeSymbol(true, reflect, %s) = true, want reflect closed beyond its invoke-nothing members", name)
		}
	}
	if classBPureStandard(true, "example.com/big", "NewInt") || auditedRuntimeTypeSymbol(true, "example.com/reflect", "DeepEqual") {
		t.Error("an admission leaked to a non-standard package path")
	}
}

// The harness failure/logging channel is exactly the output-only method
// list; the harness's ambient-input and mutation surfaces and its
// structural operations stay outside it
// (REQ-closure-observability-analysis's audited-set boundary).
func TestAuditedHarnessLoggingBounds(t *testing.T) {
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
	if testing.Short() {
		t.Skip("runs the engine over the fixture corpus")
	}
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/harnesslog"
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
	sibling, err := computeTier2Result(h, "github.com/greatliontech/gofresh/closure/fixtures/harnessclock", "TestLogAmbientClock")
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
// widening the admission (REQ-closure-observability-analysis).
func TestHarnessLoggingDeclarationInventory(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	// Source mode is load-bearing: export data materializes only the
	// exported surface, and the admission must refuse an audited-name
	// method on an unexported body-local type too.
	mode := packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedDeps | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo
	pkgs, err := packages.Load(&packages.Config{Mode: mode}, "testing")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Types == nil {
		t.Fatalf("loaded %d packages for testing, want one with types", len(pkgs))
	}
	if len(pkgs[0].Syntax) == 0 {
		t.Fatal("testing loaded without syntax — the inventory no longer type-checks from source and cannot see unexported declarations")
	}
	audited := map[string]bool{}
	for _, name := range []string{"Fatal", "Fatalf", "Error", "Errorf", "Log", "Logf", "Skip", "Skipf", "SkipNow", "Fail", "FailNow"} {
		audited[name] = true
	}
	scope := pkgs[0].Types.Scope()
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
// (REQ-closure-observability-analysis).
func TestHarnessSubtestDriverDeclarationInventory(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	mode := packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedDeps | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo
	pkgs, err := packages.Load(&packages.Config{Mode: mode}, "testing")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Types == nil {
		t.Fatalf("loaded %d packages for testing, want one with types", len(pkgs))
	}
	if len(pkgs[0].Syntax) == 0 {
		t.Fatal("testing loaded without syntax — the inventory no longer type-checks from source and cannot see unexported declarations")
	}
	allowedRun := map[string]bool{"T": true, "B": true, "M": true}
	scope := pkgs[0].Types.Scope()
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

// The toolchain-audit canary: a toolchain move fails HERE, as one named
// test naming the required walk, instead of surfacing as a scatter of
// fixture flips (the go1.27 drift arrived exactly that way). The
// audited sets claim properties of specific standard-library source;
// this test is the release listing's enforcement pointer.
func TestAuditedToolchainCoversRunningToolchain(t *testing.T) {
	if !auditedToolchainSource() {
		t.Fatalf("running toolchain %q (audit key %q) is not in auditedToolchainSelections: walk its standard-library delta against the audited admissions (the source-only set, class-B operations, sync/pool/reflect symbols, atomic transparency, harness channels, writer-sink family) and list the audit key in closure/toolchainaudit.go", runtime.Version(), toolchainKey(runtime.Version()))
	}
}

// A false audit verdict — an unlisted release or an unaudited build
// selection, computed once per analysis by AuditedToolchainSelection —
// keeps every toolchain-source admission's ordinary fail-closed
// classification: the direction that makes an unaudited stdlib refuse
// instead of silently inheriting a stale proof.
func TestUnauditedToolchainDropsAdmissions(t *testing.T) {
	if classBPureStandard(false, "fmt", "Sprint") {
		t.Error("classBPureStandard admits fmt.Sprint on an unaudited toolchain")
	}
	if isSourceOnlyStandardPackage(false, "strings") || isSourceOnlyStandardPackage(false, "math/big") {
		t.Error("isSourceOnlyStandardPackage admits strings or math/big on an unaudited toolchain")
	}
	if auditedSyncSymbol(false, "sync", "Lock") {
		t.Error("auditedSyncSymbol admits sync.Lock on an unaudited toolchain")
	}
	if auditedPoolSymbol(false, "sync", "Get") {
		t.Error("auditedPoolSymbol admits sync.Get on an unaudited toolchain")
	}
	if auditedRuntimeTypeSymbol(false, "reflect", "TypeOf") {
		t.Error("auditedRuntimeTypeSymbol admits reflect.TypeOf on an unaudited toolchain")
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
	if _, ok := AuditedAtomicPointerElem(false, inst.(*types.Named)); ok {
		t.Error("AuditedAtomicPointerElem admits sync/atomic.Pointer on an unaudited toolchain")
	}
	if driver := harnessSubtestDriverForTest(t); auditedHarnessSubtestDriver(false, driver) {
		t.Error("auditedHarnessSubtestDriver admits (*T).Run on an unaudited toolchain")
	}
}

// The drops test's probes are non-vacuous only if the fakes are
// admitted on the audited toolchain; this companion pins that half so
// the drop assertions cannot rot into always-false trivia.
func TestAuditedToolchainAdmitsTheDropFakes(t *testing.T) {
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
	if _, ok := AuditedAtomicPointerElem(true, inst.(*types.Named)); !ok {
		t.Error("the instantiated atomic.Pointer fake is not admitted on the audited toolchain")
	}
	if !auditedHarnessSubtestDriver(true, harnessSubtestDriverForTest(t)) {
		t.Error("the mini-SSA (*T).Run is not admitted on the audited toolchain")
	}
}

// harnessSubtestDriverForTest builds a minimal SSA (*T).Run in a
// package named and pathed "testing" — the smallest value the driver
// predicate's shape checks accept.
func harnessSubtestDriverForTest(t *testing.T) *ssa.Function {
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
// (REQ-closure-observability-analysis's audited-set boundary).
func TestNetURLAndFilepathAdmissions(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
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
	for _, sub := range []string{"urlhost", "urlvalues", "lexical", "absolute", "walking", "linking", "globbing", "walkfn", "badpattern", "viaglobal"} {
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
	// package's exported variables — io.EOF's shape.
	writeFile(t, dir, "viaglobal/viaglobal.go", `package viaglobal

import "io"

func Ended() bool { return io.EOF != nil }
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
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	// A refusal names its tier: the file fold's carries the "package
	// scan: " prefix, the walk's does not — so each tier's arm is
	// pinned on its own (REQ-closure-observability-analysis).
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
		{"viaglobal", "Ended", "reaches standard global io.EOF"},
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
// class (REQ-closure-observability-analysis's benchmark-pacing clause).
func TestBenchmarkPacingIsHarnessProtocol(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
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
	h, err := NewAt(dir)
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
	closures, err := h.ComputeMaximalBatch(pacingSubjects)
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
// (REQ-closure-observability-analysis's benchmark-pacing clause).
func TestBenchmarkPacingIsNotPurityEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine over the fixture corpus")
	}
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/benchpacing"
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
	if testingScanStrategy != "gofresh/testing-scan@4" {
		t.Fatalf("testing-scan strategy = %q, want @4 — the benchmark-pacing reads left the table", testingScanStrategy)
	}
}

// The pacing admission is sound only while the pacing names are declared
// exactly where the audit looked: Loop and the timer controls as methods
// of B alone, N as a field of B — BenchmarkResult and the fuzz result
// declare an N too, which the field arm's receiver check excludes — and
// none as a package-level function. A drifting toolchain fails here
// instead of silently widening (REQ-closure-observability-analysis).
func TestBenchmarkPacingDeclarationInventory(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	mode := packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedDeps | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo
	pkgs, err := packages.Load(&packages.Config{Mode: mode}, "testing")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Types == nil || len(pkgs[0].Syntax) == 0 {
		t.Fatalf("loaded %d packages for testing, want one with types and syntax", len(pkgs))
	}
	pacing := map[string]bool{"Loop": true, "ResetTimer": true, "StartTimer": true, "StopTimer": true}
	scope := pkgs[0].Types.Scope()
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
