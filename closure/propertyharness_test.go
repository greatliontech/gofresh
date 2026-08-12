package closure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The version gate: audited releases pass, anything else keeps the
// package's ordinary classification - a silent registry upgrade must
// never extend the audit (local source is judged separately, by the
// module's Main/Replace facts).
func TestAuditedPropertyHarnessVersion(t *testing.T) {
	for version, want := range map[string]bool{
		"":       false,
		"v1.3.0": true,
		"v1.2.0": false,
		"v1.4.0": false,
		"v2.0.0": false,
	} {
		if auditedPropertyHarnessVersion(version) != want {
			t.Fatalf("auditedPropertyHarnessVersion(%q) = %v, want %v", version, auditedPropertyHarnessVersion(version), want)
		}
	}
}

// The property-harness audit: a distilled pgregory.net/rapid - the
// real v1.3.0 shape's blockers in miniature (computed property
// dispatch, clock reads, failure-artifact writes, flag-registered
// configuration, interface log calls, the concrete *testing.T entry
// boundary) - proves observable behind the package audit exactly when
// every value crossing the harness boundary passes the gate, and
// widens when one does not
// (REQ-closure-observability-analysis).
func TestPropertyHarnessAudit(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"rapid", "prop", "prop/propinit", "prop/propmain", "prop/propquiet"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, dir, "rapid/go.mod", "module pgregory.net/rapid\n\ngo 1.26\n")
	writeFile(t, dir, "rapid/rapid.go", `package rapid

import (
	"flag"
	"fmt"
	"os"
	"testing"
	"time"
)

var flags struct {
	checks   int
	seed     uint64
	failfile string
}

func init() {
	flag.IntVar(&flags.checks, "rapid.checks", 100, "number of checks")
	flag.Uint64Var(&flags.seed, "rapid.seed", 0, "PRNG seed")
	flag.StringVar(&flags.failfile, "rapid.failfile", "", "failure file")
}

type TB interface {
	Helper()
	Logf(format string, args ...any)
	Errorf(format string, args ...any)
	Name() string
}

type T struct {
	tb    TB
	state uint64
	fail  bool
}

func (t *T) Logf(format string, args ...any)   { t.tb.Logf(format, args...) }
func (t *T) Errorf(format string, args ...any) { t.fail = true }

type Generator struct {
	gen func(*T) int
}

func (g *Generator) Draw(t *T, label string) int {
	t.state = t.state*6364136223846793005 + 1442695040888963407
	return g.gen(t)
}

func Int() *Generator {
	return &Generator{gen: func(t *T) int { return int(t.state >> 33) }}
}

func Custom(fn func(*T) int) *Generator {
	return &Generator{gen: fn}
}

func Deriv(g *Generator) *Generator {
	return &Generator{gen: g.gen}
}

// The real v1.3.0 boundary: a concrete *testing.T entry, the TB
// interface only internal.
func Check(t *testing.T, prop func(*T)) {
	t.Helper()
	checkTB(t, prop)
}

func MakeCheck(prop func(*T)) func(*testing.T) {
	return func(t *testing.T) {
		checkTB(t, prop)
	}
}

// A named internal function dispatched through a package variable -
// the harness's own function-valued internals, whose sites must stay
// harness frames rather than subject content.
var failReporter = reportFailure

func reportFailure(tb TB, seed uint64) {
	tb.Errorf("[rapid] failed (seed=%d)", seed)
}

func checkTB(tb TB, prop func(*T)) {
	start := time.Now()
	t := &T{tb: tb, state: flags.seed}
	for i := 0; i < flags.checks && !t.fail; i++ {
		checkOnce(t, prop)
	}
	if t.fail {
		if flags.failfile != "" {
			_ = os.WriteFile(flags.failfile, []byte(fmt.Sprintf("seed=%d", t.state)), 0o644)
		}
		failReporter(tb, t.state)
		return
	}
	tb.Logf("[rapid] OK, passed %v tests (%v)", flags.checks, time.Since(start))
}

func checkOnce(t *T, prop func(*T)) {
	prop(t)
}
`)
	writeFile(t, dir, "prop/go.mod", `module example.com/prop

go 1.26

require pgregory.net/rapid v0.0.0

replace pgregory.net/rapid => ../rapid
`)
	writeFile(t, dir, "prop/prop.go", `package prop

import "pgregory.net/rapid"

func Add(a, b int) int { return a + b }

// Startup-flow generator composition: the inner call result crosses
// the boundary gate exactly as it would in subject flow.
var derived = rapid.Deriv(rapid.Int())

func Derived() *rapid.Generator { return derived }
`)
	writeFile(t, dir, "prop/prop_test.go", `package prop

import (
	"testing"

	"pgregory.net/rapid"
)

func TestCheckLiteral(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		n := rapid.Int().Draw(rt, "n")
		rt.Logf("n=%v", n)
		if Add(n, 0) != n {
			rt.Errorf("bad add")
		}
	})
}

// A property loaded from mutable state is not locally closed: the
// harness boundary refuses it.
var openProp func(*rapid.T)

func TestCheckOpen(t *testing.T) {
	rapid.Check(t, openProp)
}

func TestMakeCheck(t *testing.T) {
	t.Run("prop", rapid.MakeCheck(func(rt *rapid.T) {
		g := rapid.Custom(func(rt *rapid.T) int { return 42 })
		if Add(g.Draw(rt, "x"), 0) != 42 {
			rt.Errorf("bad custom")
		}
	}))
}

// The harness-wrapped callback is a closed value: a computed call of
// MakeCheck's result dispatches only the gate-judged property.
func TestMakeCheckComputed(t *testing.T) {
	f := rapid.MakeCheck(func(rt *rapid.T) {
		if Add(1, 1) != 2 {
			rt.Errorf("bad")
		}
	})
	f(t)
}

// A generator callback loaded from mutable state refuses at the
// boundary like the property itself.
var openGen func(*rapid.T) int

func TestCustomOpen(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		g := rapid.Custom(openGen)
		if g.Draw(rt, "x") < 0 {
			rt.Errorf("bad")
		}
	})
}

// A generator loaded from shared mutable state is a sibling's plant:
// the receiver refuses at the boundary - harness-owned TYPES confer
// no admission, only handle parameters and gated call results do.
var sharedGen *rapid.Generator

func TestDrawShared(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		if sharedGen.Draw(rt, "s") < 0 {
			rt.Errorf("bad")
		}
	})
}

// A generator laundered through a helper parameter refuses the same
// way: the parameter crossing judges the caller's argument.
func drawDirect(rt *rapid.T, g *rapid.Generator) int { return g.Draw(rt, "d") }

var sharedGen2 *rapid.Generator

func TestParamLaunder(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		if drawDirect(rt, sharedGen2) < 0 {
			rt.Errorf("bad")
		}
	})
}

// A harness function reached as a dynamic target keeps the
// conservative refusal: no static site exists to gate the crossing.
var flip bool

func altCheck(t *testing.T, prop func(*rapid.T)) {}

func TestDynamicDriver(t *testing.T) {
	f := rapid.Check
	if flip {
		f = altCheck
	}
	f(t, func(rt *rapid.T) {})
}
`)
	writeFile(t, dir, "prop/propquiet/propquiet.go", `package propquiet

import "fmt"

// The fmt import feeds only the audited Sprint family: an unbacked
// potential-external import fallback beside the harness fact, pinning
// that the backed fact wins the diagnostic.
func Ok() bool { return fmt.Sprintf("%d", 1) != "" }
`)
	writeFile(t, dir, "prop/propquiet/propquiet_test.go", `package propquiet

import (
	"testing"

	"pgregory.net/rapid"
)

// A test that touches neither the harness handle's classified surface
// nor any other effect-bearing selector: without the recorded harness
// fact this package would verify by hash alone.
func TestQuiet(t *testing.T) {
	if rapid.Int() == nil || !Ok() {
		panic("quiet fixture broke")
	}
}
`)
	writeFile(t, dir, "prop/propinit/propinit.go", `package propinit

import "pgregory.net/rapid"

// A harness value created in startup flow carries the gate there: the
// anonymous-target admission downstream rests on every flow judging
// what crosses the boundary.
var openInitProp func(*rapid.T)

var wrapped = rapid.MakeCheck(openInitProp)

func Prod() int {
	if wrapped == nil {
		return 0
	}
	return 7
}
`)
	writeFile(t, dir, "prop/propinit/propinit_test.go", `package propinit

import "testing"

func TestProd(t *testing.T) {
	if Prod() == 0 {
		t.Fatal()
	}
}
`)
	writeFile(t, dir, "prop/propmain/propmain.go", `package propmain

func Prod() int { return 7 }
`)
	writeFile(t, dir, "prop/propmain/propmain_test.go", `package propmain

import (
	"os"
	"testing"

	"pgregory.net/rapid"
)

// The boundary gate holds in test-main flow: an unclosed callable
// crossing into the harness there widens exactly as in subject flow.
var openMainProp func(*rapid.T)

func TestMain(m *testing.M) {
	_ = rapid.MakeCheck(openMainProp)
	os.Exit(m.Run())
}

func TestProd(t *testing.T) {
	if Prod() == 0 {
		t.Fatal()
	}
}
`)
	h, err := NewAt(filepath.Join(dir, "prop"))
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{
		{Package: "example.com/prop", Symbol: "TestCheckLiteral"},
		{Package: "example.com/prop", Symbol: "TestCheckOpen"},
		{Package: "example.com/prop", Symbol: "TestMakeCheck"},
		{Package: "example.com/prop", Symbol: "TestMakeCheckComputed"},
		{Package: "example.com/prop", Symbol: "TestCustomOpen"},
		{Package: "example.com/prop", Symbol: "TestDrawShared"},
		{Package: "example.com/prop", Symbol: "TestParamLaunder"},
		{Package: "example.com/prop", Symbol: "TestDynamicDriver"},
		{Package: "example.com/prop/propinit", Symbol: "TestProd"},
		{Package: "example.com/prop/propmain", Symbol: "TestProd"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		pkg, symbol string
		observable  bool
		reason      string
	}{
		{pkg: "example.com/prop", symbol: "TestCheckLiteral", observable: true},
		{pkg: "example.com/prop", symbol: "TestCheckOpen", reason: "property-harness argument is not locally closed"},
		{pkg: "example.com/prop", symbol: "TestMakeCheck", observable: true},
		{pkg: "example.com/prop", symbol: "TestMakeCheckComputed", observable: true},
		{pkg: "example.com/prop", symbol: "TestCustomOpen", reason: "property-harness argument is not locally closed"},
		{pkg: "example.com/prop", symbol: "TestDrawShared", reason: "property-harness argument is not locally closed"},
		{pkg: "example.com/prop", symbol: "TestParamLaunder", reason: "property-harness argument is not locally closed"},
		{pkg: "example.com/prop", symbol: "TestDynamicDriver", reason: "property harness reached as a dynamic target"},
		{pkg: "example.com/prop/propinit", symbol: "TestProd", reason: "property-harness argument is not locally closed in startup flow"},
		{pkg: "example.com/prop/propmain", symbol: "TestProd", reason: "property-harness argument is not locally closed"},
	} {
		got := proofs[Subject{Package: tc.pkg, Symbol: tc.symbol}]
		if got.Observable != tc.observable || tc.reason != "" && !strings.Contains(got.Reason, tc.reason) {
			t.Fatalf("%s = %+v, want observable=%v reason containing %q", tc.symbol, got, tc.observable, tc.reason)
		}
	}
	// The audit admits observation, never purity: a package reaching the
	// harness stays unverifiable at the closure tier, so validity is
	// proven through the observation path rather than the source hash.
	// propquiet pins the fact itself - nothing else in that package
	// records a maximal EFFECT (its fmt import feeds only an unbacked
	// fallback reason) - and the diagnostic must name the backed fact,
	// never the fallback.
	for _, pkg := range []string{"example.com/prop", "example.com/prop/propquiet"} {
		unverifiable, selected, err := h.maximalUnverifiable(pkg)
		if err != nil {
			t.Fatal(err)
		}
		if !unverifiable {
			t.Fatalf("%s verified by hash alone: the audit must admit observation, never purity", pkg)
		}
		if selected == "" {
			t.Fatalf("%s unverifiable with an empty diagnostic", pkg)
		}
		if pkg == "example.com/prop/propquiet" && !strings.Contains(selected, "pgregory.net/rapid") {
			t.Fatalf("propquiet diagnostic = %q, want the harness fact named", selected)
		}
	}
}
