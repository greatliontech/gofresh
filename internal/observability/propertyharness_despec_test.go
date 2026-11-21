package observability

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/propharness"
	"github.com/greatliontech/gofresh/internal/trace"
)

const despecPropcheckSrc = `package propcheck

import (
	"flag"
	"fmt"
	"hash/maphash"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

var cfg struct {
	runs     int
	seed     uint64
	failfile string
}

func init() {
	if v, ok := os.LookupEnv("PROPCHECK_FAILFILE"); ok && v != "" {
		cfg.failfile = v
	}
	flag.IntVar(&cfg.runs, "propcheck.runs", 50, "runs")
	flag.Uint64Var(&cfg.seed, "propcheck.seed", 0, "seed")
	flag.StringVar(&cfg.failfile, "propcheck.failfile", "", "failfile")
}

type Logger interface {
	Helper()
	Logf(format string, args ...any)
	Fatalf(format string, args ...any)
	Name() string
}

type Context struct {
	log   Logger
	state uint64
}

func (c *Context) Fatalf(format string, args ...any) {
	c.log.Fatalf(format, args...)
}

func (c *Context) Logf(format string, args ...any) {
	c.log.Logf(format, args...)
}

func (c *Context) next() uint64 {
	c.state = c.state*2862933555777941757 + 3037000493
	return c.state
}

type noopLogger struct{}

func (*noopLogger) Helper()                           {}
func (*noopLogger) Logf(format string, args ...any)   {}
func (*noopLogger) Fatalf(format string, args ...any) {}
func (*noopLogger) Name() string                      { return "sample" }

type Arb[V any] struct {
	draw func(*Context) V
}

func (a *Arb[V]) Take(c *Context) V {
	return a.draw(c)
}

func (a *Arb[V]) Sample(seed ...int) V {
	var s uint64
	if len(seed) > 0 {
		s = uint64(seed[0])
	} else {
		s = freshSeed()
	}
	return a.Take(&Context{log: &noopLogger{}, state: s})
}

func Int64() *Arb[int64] {
	return &Arb[int64]{draw: func(c *Context) int64 { return int64(c.next() >> 1) }}
}

func CustomArb[V any](fn func(*Context) V) *Arb[V] {
	return &Arb[V]{draw: fn}
}

func Synth[V any]() *Arb[V] {
	return &Arb[V]{draw: func(c *Context) V {
		rt := reflect.TypeOf((*V)(nil)).Elem()
		rv := reflect.New(rt).Elem()
		if rv.Kind() == reflect.Struct {
			for i := 0; i < rv.NumField(); i++ {
				f := rv.Field(i)
				if f.CanSet() && f.Kind() == reflect.Int {
					f.SetInt(int64(c.next() & 0xff))
				}
			}
		}
		return rv.Interface().(V)
	}}
}

func freshSeed() uint64 {
	if cfg.seed != 0 {
		return cfg.seed
	}
	var h maphash.Hash
	h.SetSeed(maphash.MakeSeed())
	return h.Sum64()
}

func failPath(name string) string {
	if cfg.failfile != "" {
		return cfg.failfile
	}
	return filepath.Join("testdata", "propcheck", name)
}

func persistFail(name string, seed uint64) {
	p := failPath(name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".propcheck-*")
	if err != nil {
		return
	}
	_, _ = f.WriteString(fmt.Sprintf("%d", seed))
	_ = f.Close()
	_ = os.Rename(f.Name(), p)
}

func runVerify(l Logger, fn func(*Context)) {
	l.Helper()
	start := time.Now()
	n := cfg.runs
	if ` + "testing." + `Short() {
		n /= 2
	}
	s := freshSeed()
	c := &Context{log: l, state: s}
	for i := 0; i < n; i++ {
		fn(c)
	}
	if s == 1 {
		persistFail(l.Name(), s)
	}
	l.Logf("[propcheck] ok (%v)", time.Since(start))
}

func Verify(l Logger, fn func(*Context)) {
	runVerify(l, fn)
}

type StateRunner interface {
	Check(*Context)
}

type StateComparator interface {
	Compare(*Context) int
}

func StateActions(sr StateRunner) map[string]func(*Context) {
	return map[string]func(*Context){"": sr.Check}
}

func (c *Context) Repeat(actions map[string]func(*Context)) {
	for _, act := range actions {
		act(c)
	}
}

func BuildVerify(fn func(*Context)) func(*testing.T) {
	return func(t *testing.T) { runVerify(t, fn) }
}
`

func TestPropcheckDeSpecializedEndToEnd(t *testing.T) {
	propharness.ResetPinnedMemoForTest()
	t.Cleanup(propharness.ResetPinnedMemoForTest)

	dir := t.TempDir()
	for _, sub := range []string{"propcheck", "util", "app"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	writeFile(t, dir, "propcheck/go.mod", "module example.com/propcheck\n\ngo 1.26\n")
	writeFile(t, dir, "propcheck/propcheck.go", despecPropcheckSrc)

	// Non-harness sibling dependency (does not import "testing"): Stage 0 must
	// reject it immediately without entering propharness.VerifyPackageWithIndex.
	writeFile(t, dir, "util/go.mod", "module example.com/util\n\ngo 1.26\n")
	writeFile(t, dir, "util/util.go", "package util\n\nfunc Double(x int64) int64 { return x * 2 }\n")

	writeFile(t, dir, "app/go.mod", `module example.com/app

go 1.26

require (
	example.com/propcheck v0.0.0
	example.com/util v0.0.0
)

replace (
	example.com/propcheck => ../propcheck
	example.com/util => ../util
)
`)
	writeFile(t, dir, "app/app.go", `package app

import (
	"slices"

	"example.com/propcheck"
	"example.com/util"
)

func SumScaled(a, b int64) int64 {
	return util.Double(a) + b
}

type ScalarPair struct {
	A int
	B int
}

type HookCarrier struct {
	Hook func() int
}

func NewClosedHookCarrier() HookCarrier {
	return HookCarrier{Hook: func() int { return 7 }}
}

// PureBuildVerifyNilHandle invokes BuildVerify's returned func(*testing.T)
// closure with nil in a non-test function: the anonymous-wrapper handle gate
// must refuse it.
func PureBuildVerifyNilHandle() int {
	f := propcheck.BuildVerify(func(c *propcheck.Context) {
		_ = propcheck.Int64().Take(c)
	})
	f(nil)
	return 1
}

// PureStdCallbackBypass invokes a callback taking *propcheck.Context via a
// higher-order stdlib function (slices.ContainsFunc) passing nil.
func PureStdCallbackBypass() int {
	cb := func(c *propcheck.Context) bool {
		_ = propcheck.Int64().Take(c)
		return true
	}
	fns := []func(*propcheck.Context) bool{cb}
	_ = slices.ContainsFunc([]*propcheck.Context{nil}, fns[0])
	return 1
}
`)
	writeFile(t, dir, "app/app_test.go", `package app

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"example.com/propcheck"
)

func TestVerifyClean(t *testing.T) {
	propcheck.Verify(t, func(c *propcheck.Context) {
		x := propcheck.Int64().Take(c)
		if SumScaled(x, 0) != x*2 {
			c.Fatalf("mismatch")
		}
	})
}

func TestBuildVerifySubtest(t *testing.T) {
	t.Run("prop", propcheck.BuildVerify(func(c *propcheck.Context) {
		g := propcheck.CustomArb(func(c *propcheck.Context) int64 { return 21 })
		if SumScaled(g.Take(c), 0) != 42 {
			c.Fatalf("bad custom")
		}
	}))
}

func TestBuildVerifyWithHandle(t *testing.T) {
	f := propcheck.BuildVerify(func(c *propcheck.Context) {
		if SumScaled(2, 3) != 7 {
			c.Fatalf("bad sum")
		}
	})
	f(t)
}

func TestBuildVerifyNilHandle(t *testing.T) {
	f := propcheck.BuildVerify(func(c *propcheck.Context) {
		_ = propcheck.Int64().Take(c)
	})
	f(nil)
}

func TestBuildVerifyNewLocalT(t *testing.T) {
	f := propcheck.BuildVerify(func(c *propcheck.Context) {
		_ = propcheck.Int64().Take(c)
	})
	f(new(testing.T))
}

func TestSampleSeeded(t *testing.T) {
	v := propcheck.Int64().Sample(42)
	if SumScaled(v, 1)-1 != v*2 {
		t.Fatal("bad sample")
	}
}

func TestSampleSeededNestedCleanTakeAndLogf(t *testing.T) {
	v := propcheck.CustomArb(func(c *propcheck.Context) int64 {
		x := propcheck.Int64().Take(c)
		c.Logf("x=%d", x)
		return x
	}).Sample(42)
	if SumScaled(v, 0) != v*2 {
		t.Fatal("bad nested sample")
	}
}

type sampleSpy struct {
	buf []int
}

func (s sampleSpy) String() string {
	if len(s.buf) > 0 {
		s.buf[0]++
	}
	return "spy"
}

func TestSampleSeededSpyStringer(t *testing.T) {
	v := propcheck.CustomArb(func(*propcheck.Context) sampleSpy {
		return sampleSpy{buf: make([]int, 1)}
	}).Sample(42)
	if v.buf[0] != 0 {
		t.Fatal("spy String invoked")
	}
}

func TestSampleSeededNestedTakeSpyStringer(t *testing.T) {
	n := propcheck.CustomArb(func(c *propcheck.Context) int64 {
		spyGen := propcheck.CustomArb(func(*propcheck.Context) sampleSpy {
			return sampleSpy{buf: make([]int, 1)}
		})
		v := spyGen.Take(c)
		return int64(v.buf[0])
	}).Sample(42)
	if n != 0 {
		t.Fatal("nested spy String invoked")
	}
}

func TestSampleSeededNestedLogfSpyStringer(t *testing.T) {
	n := propcheck.CustomArb(func(c *propcheck.Context) int64 {
		v := sampleSpy{buf: make([]int, 1)}
		c.Logf("%v", v)
		return int64(v.buf[0])
	}).Sample(42)
	if n != 0 {
		t.Fatal("nested Logf spy String invoked")
	}
}

type bufWriteSpy struct {
	b *bytes.Buffer
}

func (s bufWriteSpy) String() string {
	s.b.WriteString("on")
	return "spy"
}

func TestSampleSeededBufferWriteSpyStringer(t *testing.T) {
	var b bytes.Buffer
	_ = propcheck.CustomArb(func(*propcheck.Context) bufWriteSpy {
		return bufWriteSpy{b: &b}
	}).Sample(42)
	if b.Len() != 0 {
		t.Fatal("buffer spy String invoked")
	}
}

type utf8Spy struct {
	buf []byte
}

func (s utf8Spy) String() string {
	_ = utf8.EncodeRune(s.buf, 'Z')
	return "spy"
}

func TestSampleSeededUTF8EncodeSpyStringer(t *testing.T) {
	v := propcheck.CustomArb(func(*propcheck.Context) utf8Spy {
		return utf8Spy{buf: make([]byte, 4)}
	}).Sample(42)
	if v.buf[0] != 0 {
		t.Fatal("utf8 spy String invoked")
	}
}

type indexFuncSpy struct {
	buf []int
}

func (s indexFuncSpy) String() string {
	_ = strings.IndexFunc("x", func(rune) bool {
		s.buf[0] = 1
		return true
	})
	return "spy"
}

func TestSampleSeededIndexFuncSpyStringer(t *testing.T) {
	v := propcheck.CustomArb(func(*propcheck.Context) indexFuncSpy {
		return indexFuncSpy{buf: make([]int, 1)}
	}).Sample(42)
	if v.buf[0] != 0 {
		t.Fatal("indexFunc spy String invoked")
	}
}

var mutBasicGlobal int

type mutBasicInt int

func (mutBasicInt) String() string {
	mutBasicGlobal++
	return "mut"
}

type namedBasicFmtSpy struct{}

func (namedBasicFmtSpy) String() string {
	return fmt.Sprintf("%v", mutBasicInt(1))
}

func TestSampleSeededFmtNamedBasicSpyStringer(t *testing.T) {
	_ = propcheck.CustomArb(func(*propcheck.Context) namedBasicFmtSpy {
		return namedBasicFmtSpy{}
	}).Sample(42)
}

func TestSampleUnseeded(t *testing.T) {
	_ = propcheck.Int64().Sample()
}

func TestSynthScalarStruct(t *testing.T) {
	propcheck.Verify(t, func(c *propcheck.Context) {
		pair := propcheck.Synth[ScalarPair]().Take(c)
		if pair.A+pair.B != pair.B+pair.A {
			c.Fatalf("non-commutative")
		}
	})
}

func TestClosedHookCarrierWithoutSynth(t *testing.T) {
	hc := NewClosedHookCarrier()
	if hc.Hook() != 7 {
		t.Fatal("bad hook")
	}
}

func TestSynthPoisonsHookCarrier(t *testing.T) {
	// Synth[HookCarrier]() reflectively constructs HookCarrier via reflect.New,
	// poisoning HookCarrier's struct-field provenance across the binary; calling
	// Hook on a Synth-produced HookCarrier must not be treated as closed.
	propcheck.Verify(t, func(c *propcheck.Context) {
		hc := propcheck.Synth[HookCarrier]().Take(c)
		if hc.Hook != nil {
			_ = hc.Hook()
		}
	})
}

type silentUserLogger struct{}

func (silentUserLogger) Helper()                         {}
func (silentUserLogger) Logf(format string, args ...any) {}
func (silentUserLogger) Fatalf(format string, args ...any) {}
func (silentUserLogger) Name() string                    { return "silent" }

func TestVerifySilentLogger(t *testing.T) {
	_ = t
	propcheck.Verify(silentUserLogger{}, func(c *propcheck.Context) {
		_ = propcheck.Int64().Take(c)
	})
}

func TestVerifyNilHandle(t *testing.T) {
	_ = t
	propcheck.Verify((*testing.T)(nil), func(c *propcheck.Context) {
		_ = propcheck.Int64().Take(c)
	})
}

func runBuildVerifyViaHelper(t *testing.T) {
	propcheck.BuildVerify(func(c *propcheck.Context) {
		_ = propcheck.Int64().Take(c)
	})(t)
}

func TestAuthenticHandleViaHelper(t *testing.T) {
	runBuildVerifyViaHelper(t)
}

func TestLaunderedLocalHandleViaHelper(t *testing.T) {
	_ = t
	runBuildVerifyViaHelper(&testing.T{})
}

func TestDualCalledCallbackWithNilContext(t *testing.T) {
	cb := func(c *propcheck.Context) {
		_ = propcheck.Int64().Take(c)
	}
	propcheck.Verify(t, cb)
	cb(nil)
}

func Testlowercase(t *testing.T) {
	propcheck.Verify(t, func(c *propcheck.Context) {
		_ = propcheck.Int64().Take(c)
	})
}

func helperFakeContextRoot(c *propcheck.Context) {
	_ = propcheck.Int64().Take(c)
}

func TestCrossCalledTarget(t *testing.T) {
	propcheck.Verify(t, func(c *propcheck.Context) {
		_ = propcheck.Int64().Take(c)
	})
}

func TestCrossCallerNil(t *testing.T) {
	_ = t
	if false {
		go TestCrossCalledTarget(nil)
	}
	TestCrossCalledTarget(nil)
}

type cleanStateRunner struct {
	v int64
}

func (s *cleanStateRunner) Check(c *propcheck.Context) {
	if s.v < 0 {
		c.Fatalf("negative")
	}
}

func TestStateRunnerAlongsideUnrelated2ArgDynCall(t *testing.T) {
	fns := []func(int, int) int{func(a, b int) int { return a + b }}
	_ = fns[0](1, 2)
	propcheck.Verify(t, func(c *propcheck.Context) {
		c.Repeat(propcheck.StateActions(&cleanStateRunner{v: 1}))
	})
}

type localStateComparator interface {
	Compare(*propcheck.Context) int
}

type thunkBadStateRunner struct{}

func (s *thunkBadStateRunner) Compare(c *propcheck.Context) int {
	c.Fatalf("bad")
	return 0
}

func TestStateRunnerMethodThunkWithNilHandle(t *testing.T) {
	propcheck.Verify(t, func(c *propcheck.Context) {
		_ = c
		_, _ = slices.BinarySearchFunc(
			[]localStateComparator{&thunkBadStateRunner{}},
			(*propcheck.Context)(nil),
			localStateComparator.Compare,
		)
	})
}

type badHarnessThunkRunner struct{}

func (s *badHarnessThunkRunner) Check(c *propcheck.Context) {
	c.Fatalf("bad")
}

func TestHarnessIfaceMethodThunkWithNilHandle(t *testing.T) {
	propcheck.Verify(t, func(c *propcheck.Context) {
		_ = c
		(propcheck.StateRunner.Check)(&badHarnessThunkRunner{}, (*propcheck.Context)(nil))
	})
}

func TestHarnessIfaceDynSliceMethodThunkWithNilHandle(t *testing.T) {
	propcheck.Verify(t, func(c *propcheck.Context) {
		_ = c
		fns := []func(propcheck.StateRunner, *propcheck.Context){propcheck.StateRunner.Check}
		fns[0](&badHarnessThunkRunner{}, (*propcheck.Context)(nil))
	})
}

func TestHarnessIfaceStdDynamicMethodThunkWithNilHandle(t *testing.T) {
	propcheck.Verify(t, func(c *propcheck.Context) {
		_ = c
		_, _ = slices.BinarySearchFunc(
			[]propcheck.StateComparator{&thunkBadStateRunner{}},
			(*propcheck.Context)(nil),
			propcheck.StateComparator.Compare,
		)
	})
}
`)

	rec := trace.NewRecorder()
	ctx := trace.WithSink(t.Context(), rec)
	appDir := filepath.Join(dir, "app")
	h, err := NewAt(ctx, gotool.NewEnvReader(gotool.Runner{}, appDir, os.Environ()))
	if err != nil {
		t.Fatal(err)
	}
	markHasherEligible(h)

	subjects := []Subject{
		{Package: "example.com/app", Symbol: "TestVerifyClean"},
		{Package: "example.com/app", Symbol: "TestBuildVerifySubtest"},
		{Package: "example.com/app", Symbol: "TestBuildVerifyWithHandle"},
		{Package: "example.com/app", Symbol: "TestBuildVerifyNilHandle"},
		{Package: "example.com/app", Symbol: "TestBuildVerifyNewLocalT"},
		{Package: "example.com/app", Symbol: "PureBuildVerifyNilHandle"},
		{Package: "example.com/app", Symbol: "TestSampleSeeded"},
		{Package: "example.com/app", Symbol: "TestSampleSeededNestedCleanTakeAndLogf"},
		{Package: "example.com/app", Symbol: "TestSampleSeededSpyStringer"},
		{Package: "example.com/app", Symbol: "TestSampleSeededNestedTakeSpyStringer"},
		{Package: "example.com/app", Symbol: "TestSampleSeededNestedLogfSpyStringer"},
		{Package: "example.com/app", Symbol: "TestSampleSeededBufferWriteSpyStringer"},
		{Package: "example.com/app", Symbol: "TestSampleSeededUTF8EncodeSpyStringer"},
		{Package: "example.com/app", Symbol: "TestSampleSeededIndexFuncSpyStringer"},
		{Package: "example.com/app", Symbol: "TestSampleSeededFmtNamedBasicSpyStringer"},
		{Package: "example.com/app", Symbol: "TestSampleUnseeded"},
		{Package: "example.com/app", Symbol: "TestSynthScalarStruct"},
		{Package: "example.com/app", Symbol: "TestSynthPoisonsHookCarrier"},
		{Package: "example.com/app", Symbol: "TestVerifySilentLogger"},
		{Package: "example.com/app", Symbol: "TestVerifyNilHandle"},
		{Package: "example.com/app", Symbol: "TestAuthenticHandleViaHelper"},
		{Package: "example.com/app", Symbol: "TestLaunderedLocalHandleViaHelper"},
		{Package: "example.com/app", Symbol: "TestDualCalledCallbackWithNilContext"},
		{Package: "example.com/app", Symbol: "PureStdCallbackBypass"},
		{Package: "example.com/app", Symbol: "runBuildVerifyViaHelper"},
		{Package: "example.com/app", Symbol: "Testlowercase"},
		{Package: "example.com/app", Symbol: "helperFakeContextRoot"},
		{Package: "example.com/app", Symbol: "TestCrossCallerNil"},
		{Package: "example.com/app", Symbol: "TestCrossCalledTarget"},
		{Package: "example.com/app", Symbol: "TestStateRunnerAlongsideUnrelated2ArgDynCall"},
		{Package: "example.com/app", Symbol: "TestStateRunnerMethodThunkWithNilHandle"},
		{Package: "example.com/app", Symbol: "TestHarnessIfaceMethodThunkWithNilHandle"},
		{Package: "example.com/app", Symbol: "TestHarnessIfaceDynSliceMethodThunkWithNilHandle"},
		{Package: "example.com/app", Symbol: "TestHarnessIfaceStdDynamicMethodThunkWithNilHandle"},
	}

	maxFacts, _, err := h.ComputeMaximalFactsBatch([]Subject{{Package: "example.com/app", Symbol: "TestVerifyClean"}})
	if err != nil {
		t.Fatalf("ComputeMaximalFactsBatch: %v", err)
	}
	cleanFacts := maxFacts[Subject{Package: "example.com/app", Symbol: "TestVerifyClean"}]
	if !cleanFacts.Closure().Unverifiable {
		t.Fatalf("ComputeMaximalFactsBatch(TestVerifyClean).Closure() = %+v, want Unverifiable=true", cleanFacts.Closure())
	}
	sawHarnessFact := false
	for _, eff := range cleanFacts.Effects {
		if eff.Kind == BlockerTestRuntime && eff.Package == "example.com/propcheck" && eff.Symbol == "Verify" && eff.Observable &&
			eff.Reason == "reaches the audited property-testing harness example.com/propcheck" {
			sawHarnessFact = true
		}
		if eff.Package == "example.com/propcheck" && !eff.Observable {
			t.Fatalf("unexpected non-observable propcheck maximal blocker: %+v", eff)
		}
	}
	if !sawHarnessFact {
		t.Fatalf("missing audited propcheck harness fact in MaximalFacts.Effects: %+v", cleanFacts.Effects)
	}

	// Stage-0 fast pre-screen check: example.com/util must never reach propharness.verify.done.
	for _, ev := range rec.ByName("propharness.verify.done") {
		if ev.Target == "example.com/util" {
			t.Fatalf("Stage-0 pre-screen failed: non-harness dependency example.com/util entered full verification: %+v", ev)
		}
	}

	proofs, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatalf("ComputeObservabilityBatch: %v", err)
	}

	cases := []struct {
		symbol     string
		observable bool
		effectFree bool
		wantReason string
	}{
		{symbol: "TestVerifyClean", observable: true, effectFree: true},
		{symbol: "TestBuildVerifySubtest", observable: true, effectFree: true},
		{symbol: "TestBuildVerifyWithHandle", observable: true, effectFree: true},
		{symbol: "TestBuildVerifyNilHandle", observable: false, wantReason: "property harness reached as a dynamic target"},
		{symbol: "TestBuildVerifyNewLocalT", observable: false, wantReason: "property harness reached as a dynamic target"},
		{symbol: "PureBuildVerifyNilHandle", observable: false, wantReason: "property harness reached as a dynamic target"},
		{symbol: "TestSampleSeeded", observable: true, effectFree: true},
		{symbol: "TestSampleSeededNestedCleanTakeAndLogf", observable: true, effectFree: true},
		{symbol: "TestSampleSeededSpyStringer", observable: false, wantReason: "property-harness argument is not locally closed"},
		{symbol: "TestSampleSeededNestedTakeSpyStringer", observable: false, wantReason: "property-harness argument is not locally closed"},
		{symbol: "TestSampleSeededNestedLogfSpyStringer", observable: false, wantReason: "property-harness argument is not locally closed"},
		{symbol: "TestSampleSeededBufferWriteSpyStringer", observable: false, wantReason: "property-harness argument is not locally closed"},
		{symbol: "TestSampleSeededUTF8EncodeSpyStringer", observable: false, wantReason: "property-harness argument is not locally closed"},
		{symbol: "TestSampleSeededIndexFuncSpyStringer", observable: false, wantReason: "property-harness argument is not locally closed"},
		{symbol: "TestSampleSeededFmtNamedBasicSpyStringer", observable: false, wantReason: "property-harness argument is not locally closed"},
		{symbol: "TestSampleUnseeded", observable: false, wantReason: "reaches example.com/propcheck.Arb.Sample without an explicit seed (entropy)"},
		{symbol: "TestSynthScalarStruct", observable: true, effectFree: true},
		{symbol: "TestSynthPoisonsHookCarrier", observable: false},
		{symbol: "TestVerifySilentLogger", observable: false, wantReason: "property-harness argument is not locally closed"},
		{symbol: "TestVerifyNilHandle", observable: false, wantReason: "property-harness argument is not locally closed"},
		{symbol: "TestAuthenticHandleViaHelper", observable: true, effectFree: true},
		{symbol: "TestLaunderedLocalHandleViaHelper", observable: false, wantReason: "property harness reached as a dynamic target"},
		{symbol: "TestDualCalledCallbackWithNilContext", observable: false, wantReason: "property-harness argument is not locally closed"},
		{symbol: "PureStdCallbackBypass", observable: false, wantReason: "property-harness argument is not locally closed"},
		{symbol: "runBuildVerifyViaHelper", observable: false, wantReason: "property harness reached as a dynamic target"},
		{symbol: "Testlowercase", observable: false, wantReason: "property-harness argument is not locally closed"},
		{symbol: "helperFakeContextRoot", observable: false, wantReason: "property-harness argument is not locally closed"},
		{symbol: "TestCrossCallerNil", observable: false},
		{symbol: "TestCrossCalledTarget", observable: true, effectFree: true},
		{symbol: "TestStateRunnerAlongsideUnrelated2ArgDynCall", observable: true, effectFree: true},
		{symbol: "TestStateRunnerMethodThunkWithNilHandle", observable: false, wantReason: "property-harness argument is not locally closed"},
		{symbol: "TestHarnessIfaceMethodThunkWithNilHandle", observable: false, wantReason: "property-harness argument is not locally closed"},
		{symbol: "TestHarnessIfaceDynSliceMethodThunkWithNilHandle", observable: false, wantReason: "subject reachability is not closed"},
		{symbol: "TestHarnessIfaceStdDynamicMethodThunkWithNilHandle", observable: false, wantReason: "property harness reached as a dynamic target"},
	}
	for _, tc := range cases {
		got := proofs[Subject{Package: "example.com/app", Symbol: tc.symbol}]
		if got.Observable != tc.observable || got.EffectFree != tc.effectFree {
			t.Errorf("%s: got Observable=%v EffectFree=%v Reason=%q, want Observable=%v EffectFree=%v",
				tc.symbol, got.Observable, got.EffectFree, got.Reason, tc.observable, tc.effectFree)
		}
		if tc.wantReason != "" && !strings.Contains(got.Reason, tc.wantReason) {
			t.Errorf("%s: Reason = %q, want substring %q", tc.symbol, got.Reason, tc.wantReason)
		}
	}

	sawThunkGateReject := false
	for _, ev := range rec.ByName("closure.propharness.gate_reject") {
		if ev.Target != "TestStateRunnerMethodThunkWithNilHandle" {
			continue
		}
		var gotCallee, gotReason, gotDetail string
		for _, f := range ev.Fields {
			switch f.Key {
			case "callee":
				gotCallee = f.Str
			case "reason":
				gotReason = f.Str
			case "detail":
				gotDetail = f.Str
			}
		}
		if gotCallee == "(*example.com/propcheck.Context).Fatalf" &&
			gotReason == "unauthentic_handle_arg" &&
			strings.Contains(gotDetail, "harness_struct_param_dyncall:bad_invoke_caller:") &&
			strings.Contains(gotDetail, "nil:*example.com/propcheck.Context") {
			sawThunkGateReject = true
		}
	}
	if !sawThunkGateReject {
		t.Errorf("TestStateRunnerMethodThunkWithNilHandle: missing expected closure.propharness.gate_reject event; events=%+v",
			rec.ByName("closure.propharness.gate_reject"))
	}

	for _, sym := range []string{
		"TestSampleSeededSpyStringer",
		"TestSampleSeededNestedTakeSpyStringer",
		"TestSampleSeededNestedLogfSpyStringer",
		"TestSampleSeededBufferWriteSpyStringer",
		"TestSampleSeededUTF8EncodeSpyStringer",
		"TestSampleSeededIndexFuncSpyStringer",
		"TestSampleSeededFmtNamedBasicSpyStringer",
	} {
		sawHookReject := false
		for _, ev := range rec.ByName("closure.propharness.gate_reject") {
			if ev.Target == sym {
				for _, f := range ev.Fields {
					if f.Key == "reason" && f.Str == "seeded_sample_format_hook" {
						sawHookReject = true
					}
				}
			}
		}
		if !sawHookReject {
			t.Errorf("%s: missing closure.propharness.gate_reject with reason=seeded_sample_format_hook", sym)
		}
	}

	hSolo, err := NewAt(ctx, gotool.NewEnvReader(gotool.Runner{}, appDir, os.Environ()))
	if err != nil {
		t.Fatal(err)
	}
	markHasherEligible(hSolo)
	soloProofs, err := hSolo.ComputeObservabilityBatch([]Subject{{Package: "example.com/app", Symbol: "TestCrossCalledTarget"}})
	if err != nil {
		t.Fatalf("solo ComputeObservabilityBatch: %v", err)
	}
	if soloGot, batchGot := soloProofs[Subject{Package: "example.com/app", Symbol: "TestCrossCalledTarget"}], proofs[Subject{Package: "example.com/app", Symbol: "TestCrossCalledTarget"}]; soloGot != batchGot {
		t.Fatalf("batch-vs-solo mismatch on TestCrossCalledTarget: batch=%+v solo=%+v", batchGot, soloGot)
	}

	rooted, err := h.ComputeRootedFunctions(ctx, []Subject{{Package: "example.com/app", Symbol: "TestVerifyClean"}})
	if err != nil {
		t.Fatalf("ComputeRootedFunctions: %v", err)
	}
	rf := rooted[Subject{Package: "example.com/app", Symbol: "TestVerifyClean"}]
	if !rf.Complete {
		t.Fatalf("ComputeRootedFunctions(TestVerifyClean) incomplete: %+v", rf)
	}
	for fnKey := range rf.Fns {
		if strings.Contains(fnKey, "example.com/propcheck") {
			t.Errorf("harness frame leaked into rooted subject functions: %s", fnKey)
		}
	}
}
