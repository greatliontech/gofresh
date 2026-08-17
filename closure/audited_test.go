package closure

import (
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// The audited-pure widening: subjects reaching pure standard
// computation prove observable, while the two soundness exclusions -
// flag registration (covert Parse-time channel) and reflect (defeats
// reachability) - stay blocked
// (REQ-closure-observability-analysis's audited-set boundary).
func TestAuditedPureWideningAndExclusions(t *testing.T) {
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
	"fmt"
	"strings"
)

func Formats(x float64) string {
	r := bufio.NewReader(strings.NewReader(fmt.Sprintf("%.2f", x)))
	line, _ := r.ReadString('\n')
	return line
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
	dir := t.TempDir()
	for _, sub := range []string{"values", "calendar", "stamp", "clock", "mirror"} {
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
		{Package: "example.com/audited/calendar", Symbol: "Year"},
		{Package: "example.com/audited/stamp", Symbol: "Stamp"},
		{Package: "example.com/audited/clock", Symbol: "Now"},
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
	for _, tc := range []struct{ pkg, name string }{
		{"math/big", "NewInt"}, {"math/big", "NewFloat"}, {"math/big", "NewRat"},
		{"math/big", "Int"}, {"math/big", "Float"}, {"math/big", "Rat"},
		{"time", "Date"}, {"time", "Time"}, {"time", "Month"},
		{"time", "January"}, {"time", "February"}, {"time", "March"},
		{"time", "April"}, {"time", "May"}, {"time", "June"},
		{"time", "July"}, {"time", "August"}, {"time", "September"},
		{"time", "October"}, {"time", "November"}, {"time", "December"},
		{"fmt", "Stringer"}, {"fmt", "Sprint"},
	} {
		if !classBPureStandard(tc.pkg, tc.name) {
			t.Errorf("classBPureStandard(%s, %s) = false, want audited", tc.pkg, tc.name)
		}
	}
	for _, tc := range []struct{ pkg, name string }{
		{"time", "Now"}, {"time", "UTC"}, {"time", "Local"},
		{"time", "LoadLocation"}, {"time", "FixedZone"}, {"time", "Since"},
		{"math/big", "Rand"}, {"math/big", "ParseFloat"},
		{"fmt", "State"}, {"fmt", "Print"}, {"fmt", "Formatter"},
	} {
		if classBPureStandard(tc.pkg, tc.name) {
			t.Errorf("classBPureStandard(%s, %s) = true, want outside the audited set", tc.pkg, tc.name)
		}
	}
	if !auditedRuntimeTypeSymbol("reflect", "DeepEqual") {
		t.Error("auditedRuntimeTypeSymbol(reflect, DeepEqual) = false, want the invoke-nothing comparator audited")
	}
	for _, name := range []string{"ValueOf", "Value", "New", "MakeFunc", "Indirect"} {
		if auditedRuntimeTypeSymbol("reflect", name) {
			t.Errorf("auditedRuntimeTypeSymbol(reflect, %s) = true, want reflect closed beyond its invoke-nothing members", name)
		}
	}
	if classBPureStandard("example.com/big", "NewInt") || auditedRuntimeTypeSymbol("example.com/reflect", "DeepEqual") {
		t.Error("an admission leaked to a non-standard package path")
	}
}

// The harness failure/logging channel is exactly the output-only method
// list; the harness's ambient-input and mutation surfaces and its
// structural operations stay outside it
// (REQ-closure-observability-analysis's audited-set boundary).
func TestAuditedHarnessLoggingBounds(t *testing.T) {
	for _, name := range []string{"Fatal", "Fatalf", "Error", "Errorf", "Log", "Logf", "Skip", "Skipf", "SkipNow", "Fail", "FailNow"} {
		if !auditedHarnessLogging("testing", name) {
			t.Errorf("auditedHarnessLogging(testing, %s) = false, want audited", name)
		}
	}
	for _, name := range []string{"Setenv", "Chdir", "TempDir", "Run", "Cleanup", "Helper", "Short", "Deadline", "Context", "Parallel", "Name", "Failed", "Skipped"} {
		if auditedHarnessLogging("testing", name) {
			t.Errorf("auditedHarnessLogging(testing, %s) = true, want outside the audited set", name)
		}
	}
	if auditedHarnessLogging("os", "Fatal") || auditedHarnessLogging("log", "Fatal") {
		t.Error("auditedHarnessLogging admits a non-testing package")
	}
}

// A subject whose only reachable effect is the audited harness channel
// earns the observation proof yet stays unverifiable in the legacy
// projection: the admission is observation evidence, never purity
// evidence.
func TestHarnessLoggingIsNotPurityEvidence(t *testing.T) {
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
	} {
		if got := auditedLinknamesOnly(tc.text); got != tc.want {
			t.Errorf("%s: auditedLinknamesOnly = %v, want %v", name, got, tc.want)
		}
	}
}
