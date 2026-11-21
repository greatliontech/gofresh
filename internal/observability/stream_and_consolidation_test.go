package observability

import (
	"context"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/trace"
	"pgregory.net/rapid"
)

func newTracedFullSyntaxHasherAt(t *testing.T, dir string, env []string, buildFlags ...string) (*Prover, *trace.Recorder) {
	t.Helper()
	snap, err := cachedHostSnapshotOnce()
	if err != nil {
		t.Fatal(err)
	}
	rec := trace.NewRecorder()
	ctx := trace.WithSink(t.Context(), rec)
	procEnv := os.Environ()
	if env != nil {
		procEnv = env
	}
	var h *Prover
	if env != nil {
		h, err = NewAt(ctx, gotool.NewEnvReader(gotool.Runner{}, dir, procEnv), buildFlags...)
	} else {
		h, err = NewAt(ctx, gotool.PrimedEnvReader(gotool.Runner{}, dir, procEnv, snap), buildFlags...)
	}
	if err != nil {
		t.Fatal(err)
	}
	return h, rec
}

func newTracedInMemoryHasherAt(t *testing.T, dir string, env []string, buildFlags ...string) (*Prover, *trace.Recorder) {
	t.Helper()
	h, rec := newTracedFullSyntaxHasherAt(t, dir, env, buildFlags...)
	markHasherEligible(h)
	primeHasherFromDir(t, h, dir)
	t.Cleanup(func() { unprimeHasher(h) })
	return h, rec
}

func hasTraceEventReason(rec *trace.Recorder, eventName, reasonSubstr string) bool {
	for _, ev := range rec.ByName(eventName) {
		for _, f := range ev.Fields {
			if f.Key == "reason" && strings.Contains(f.Str, reasonSubstr) {
				return true
			}
		}
	}
	return false
}

func TestGoLinknameBlockAndProseDirectives(t *testing.T) {
	t.Parallel()

	linePrefix := "//" + "go:linkname"
	lineStdPrefix := "//" + "go:linknamestd"
	blkPrefix := "/*" + "go:linkname"
	blkStdPrefix := "/*" + "go:linknamestd"

	cases := []struct {
		name        string
		text        string
		wantLocal   string
		wantTarget  string
		wantMatched bool
		wantValid   bool
	}{
		{
			name:        "line_two_arg",
			text:        linePrefix + " localNano runtime.nanotime",
			wantLocal:   "localNano",
			wantTarget:  "runtime.nanotime",
			wantMatched: true,
			wantValid:   true,
		},
		{
			name:        "line_one_arg",
			text:        linePrefix + " exportedLocal",
			wantLocal:   "exportedLocal",
			wantMatched: true,
			wantValid:   true,
		},
		{
			name:        "block_two_arg",
			text:        blkPrefix + " localNano runtime.nanotime*/",
			wantLocal:   "localNano",
			wantTarget:  "runtime.nanotime",
			wantMatched: true,
			wantValid:   true,
		},
		{
			name:        "block_std_two_arg",
			text:        blkStdPrefix + "\tlocalNano\truntime.nanotime */",
			wantLocal:   "localNano",
			wantTarget:  "runtime.nanotime",
			wantMatched: true,
			wantValid:   true,
		},
		{
			name:        "line_std_missing_dot",
			text:        lineStdPrefix + " localNano nodot",
			wantMatched: true,
			wantValid:   false,
		},
		{
			name:        "block_zero_args",
			text:        blkPrefix + "*/",
			wantMatched: true,
			wantValid:   false,
		},
		{
			name:        "block_three_args",
			text:        blkPrefix + " a b.c extra*/",
			wantMatched: true,
			wantValid:   false,
		},
		{
			name:        "prose_leading_space_line",
			text:        "// go:linkname is discussed in prose",
			wantMatched: false,
			wantValid:   false,
		},
		{
			name:        "prose_leading_space_block",
			text:        "/* go:linkname is discussed in prose */",
			wantMatched: false,
			wantValid:   false,
		},
		{
			name:        "unrelated_prefix_identifier",
			text:        linePrefix + "extra a b.c",
			wantMatched: false,
			wantValid:   false,
		},
		{
			name:        "block_same_line_split_bypass",
			text:        blkPrefix + " evil*//* runtime.getAuxv*/",
			wantMatched: true,
			wantValid:   false,
		},
		{
			name:        "non_identifier_local",
			text:        linePrefix + " 123bad runtime.getAuxv",
			wantMatched: true,
			wantValid:   false,
		},
	}

	for _, tc := range cases {
		local, target, matched, valid := parseGoLinknameDirectiveComment(tc.text)
		if matched != tc.wantMatched || valid != tc.wantValid || local != tc.wantLocal || target != tc.wantTarget {
			t.Errorf("%s: parseGoLinknameDirectiveComment(%q) = (%q, %q, matched=%v, valid=%v), want (%q, %q, matched=%v, valid=%v)",
				tc.name, tc.text, local, target, matched, valid, tc.wantLocal, tc.wantTarget, tc.wantMatched, tc.wantValid)
		}
	}

	// Raw string literal containing a block linkname directive must fail closed on the raw-text floor.
	rawLiteralSrc := "package p\nconst s = `" + blkPrefix + " bad runtime.nanotime*/`\n"
	if !hasRawGoLinkname(rawLiteralSrc) {
		t.Fatalf("hasRawGoLinkname(%q) = false, want true", rawLiteralSrc)
	}
	if auditedLinknamesOnly(true, rawLiteralSrc) {
		t.Fatalf("auditedLinknamesOnly(true, %q) = true, want false for unverified target in raw text", rawLiteralSrc)
	}

	// Audited target inside a block comment passes auditedLinknamesOnly; unverified target or split block fails closed.
	auditedBlockSrc := "package p\nimport _ \"unsafe\"\n" + blkPrefix + " auxv runtime.getAuxv*/\nfunc auxv() []uintptr\n"
	if !auditedLinknamesOnly(true, auditedBlockSrc) {
		t.Fatalf("auditedLinknamesOnly(true, audited block linkname) = false, want true")
	}
	unauditedBlockSrc := "package p\nimport _ \"unsafe\"\n" + blkPrefix + " nano runtime.nanotime*/\nfunc nano() int64\n"
	if auditedLinknamesOnly(true, unauditedBlockSrc) {
		t.Fatalf("auditedLinknamesOnly(true, unaudited block linkname) = true, want false")
	}
	splitBlockBypassSrc := "package p\nimport _ \"unsafe\"\n" + blkPrefix + " evil*//* runtime.getAuxv*/\nfunc evil()\n"
	if auditedLinknamesOnly(true, splitBlockBypassSrc) {
		t.Fatalf("auditedLinknamesOnly(true, split block linkname bypass) = true, want false")
	}
	sameLineSecondUnauditedSrc := "package p\nimport _ \"unsafe\"\n" + blkPrefix + " auxv runtime.getAuxv*/ " + linePrefix + " bad runtime.nanotime\n"
	if auditedLinknamesOnly(true, sameLineSecondUnauditedSrc) {
		t.Fatalf("auditedLinknamesOnly(true, same-line second unaudited linkname) = true, want false")
	}

	// End-to-end Tier 1 + Tier 2 refusal on block-comment /*go:linkname ...*/ to an unaudited target
	// and same-line 1-arg block-comment linkname followed by /* runtime.getAuxv*/,
	// contrasted with prose comment "// go:linkname ..." which is admitted.
	dir := writeTestVariantModule(t, map[string]string{
		"go.mod":                  "module example.com/blklink\n\ngo 1.24\n",
		"prose/prose_test.go":     "package prose\n\nimport \"testing\"\n\n// go:linkname mentioned in prose only\n/* go:linkname also prose */\nfunc TestProse(t *testing.T) {\n\tif 1+1 != 2 {\n\t\tt.Fatal(\"math\")\n\t}\n}\n",
		"badblk/badblk_test.go":   "package badblk\n\nimport (\n\t\"testing\"\n\t_ \"unsafe\"\n)\n\n" + blkPrefix + " badNano runtime.nanotime*/\nfunc badNano() int64\n\nfunc TestBlockLinkname(t *testing.T) {\n\t_ = t\n}\n",
		"splitblk/split_test.go":  "package splitblk\n\nimport (\n\t\"testing\"\n\t_ \"unsafe\"\n)\n\n" + blkPrefix + " ExportedLocal*//* runtime.getAuxv*/\nfunc ExportedLocal() int { return 1 }\n\nfunc TestSplitBlockLinkname(t *testing.T) {\n\t_ = ExportedLocal()\n}\n",
	})
	h, _ := newTracedInMemoryHasherAt(t, dir, nil)
	proseSubj := Subject{Package: "example.com/blklink/prose", Symbol: "TestProse"}
	badSubj := Subject{Package: "example.com/blklink/badblk", Symbol: "TestBlockLinkname"}
	splitSubj := Subject{Package: "example.com/blklink/splitblk", Symbol: "TestSplitBlockLinkname"}

	maxClosures, _, err := h.ComputeMaximalBatch([]Subject{proseSubj, badSubj, splitSubj})
	if err != nil {
		t.Fatal(err)
	}
	if maxClosures[proseSubj].Unverifiable {
		t.Fatalf("TestProse maximal unverifiable: %+v", maxClosures[proseSubj])
	}
	if !maxClosures[badSubj].Unverifiable || !strings.Contains(maxClosures[badSubj].Reason, "go:linkname") {
		t.Fatalf("TestBlockLinkname maximal = %+v, want go:linkname refusal", maxClosures[badSubj])
	}
	if !maxClosures[splitSubj].Unverifiable || !strings.Contains(maxClosures[splitSubj].Reason, "go:linkname") {
		t.Fatalf("TestSplitBlockLinkname maximal = %+v, want go:linkname refusal", maxClosures[splitSubj])
	}
	obs, err := h.ComputeObservabilityBatch([]Subject{proseSubj, badSubj, splitSubj})
	if err != nil {
		t.Fatal(err)
	}
	if !obs[proseSubj].Observable {
		t.Fatalf("TestProse observability = %+v, want Observable", obs[proseSubj])
	}
	if obs[badSubj].Observable || !strings.Contains(obs[badSubj].Reason, "go:linkname") {
		t.Fatalf("TestBlockLinkname observability = %+v, want go:linkname refusal", obs[badSubj])
	}
	if obs[splitSubj].Observable || !strings.Contains(obs[splitSubj].Reason, "go:linkname") {
		t.Fatalf("TestSplitBlockLinkname observability = %+v, want go:linkname refusal", obs[splitSubj])
	}
}

func TestRapidParserModeTraceFreeBitwiseOracle(t *testing.T) {
	t.Parallel()

	modeType := types.Typ[types.Uint]
	// Track 3-valued Kleene bit-vectors (mayOne, mayZero) across all 64 bits so
	// masking idioms such as `dynamic & 0` or `dynamic &^ parser.Trace` have an
	// exact semantic reference oracle.
	type modeExpr struct {
		val     ssa.Value
		mayOne  uint64
		mayZero uint64
		pureBit bool
	}
	var buildExpr func(rt *rapid.T, depth int) modeExpr
	buildExpr = func(rt *rapid.T, depth int) modeExpr {
		if depth <= 0 || rapid.Bool().Draw(rt, "leaf") {
			if rapid.IntRange(0, 4).Draw(rt, "dynamic") == 0 {
				var p ssa.Parameter
				return modeExpr{val: &p, mayOne: ^uint64(0), mayZero: ^uint64(0), pureBit: true}
			}
			c := rapid.SampledFrom([]uint64{
				0,
				uint64(parser.PackageClauseOnly),
				uint64(parser.ImportsOnly),
				uint64(parser.ParseComments),
				uint64(parser.Trace),
				uint64(parser.DeclarationErrors),
				uint64(parser.AllErrors),
				uint64(parser.SkipObjectResolution),
				uint64(parser.ParseComments | parser.AllErrors),
				uint64(parser.ParseComments | parser.Trace),
				0xff,
			}).Draw(rt, "const")
			sc := ssa.NewConst(constant.MakeUint64(c), modeType)
			return modeExpr{val: sc, mayOne: c, mayZero: ^c, pureBit: true}
		}
		left := buildExpr(rt, depth-1)
		right := buildExpr(rt, depth-1)
		op := rapid.SampledFrom([]token.Token{token.OR, token.AND, token.XOR, token.AND_NOT, token.ADD}).Draw(rt, "op")
		bin := &ssa.BinOp{Op: op, X: left.val, Y: right.val}
		switch op {
		case token.OR:
			return modeExpr{
				val:     bin,
				mayOne:  left.mayOne | right.mayOne,
				mayZero: left.mayZero & right.mayZero,
				pureBit: left.pureBit && right.pureBit,
			}
		case token.AND:
			return modeExpr{
				val:     bin,
				mayOne:  left.mayOne & right.mayOne,
				mayZero: left.mayZero | right.mayZero,
				pureBit: left.pureBit && right.pureBit,
			}
		case token.XOR:
			return modeExpr{
				val:     bin,
				mayOne:  (left.mayOne & right.mayZero) | (left.mayZero & right.mayOne),
				mayZero: (left.mayOne & right.mayOne) | (left.mayZero & right.mayZero),
				pureBit: left.pureBit && right.pureBit,
			}
		case token.AND_NOT:
			return modeExpr{
				val:     bin,
				mayOne:  left.mayOne & right.mayZero,
				mayZero: left.mayZero | right.mayOne,
				pureBit: left.pureBit && right.pureBit,
			}
		default:
			// ADD carries across bit positions; if both sides are exact constants, compute exact sum.
			if (left.mayOne^^left.mayZero) == 0 && (right.mayOne^^right.mayZero) == 0 {
				sum := left.mayOne + right.mayOne
				return modeExpr{val: bin, mayOne: sum, mayZero: ^sum, pureBit: false}
			}
			return modeExpr{val: bin, mayOne: ^uint64(0), mayZero: ^uint64(0), pureBit: false}
		}
	}

	rapid.Check(t, func(rt *rapid.T) {
		e := buildExpr(rt, 3)
		got := parserModeTraceFree(e.val, nil)
		traceMayBeSet := e.mayOne&uint64(parser.Trace) != 0
		if got && traceMayBeSet {
			rt.Fatalf("parserModeTraceFree admitted expression whose parser.Trace bit may be 1 (mayOne=%#x)", e.mayOne)
		}
		if e.pureBit && !traceMayBeSet {
			if _, isConst := e.val.(*ssa.Const); isConst && !got {
				rt.Fatalf("parserModeTraceFree rejected trace-free constant %#x", e.mayOne)
			}
		}
	})
}

func TestProgramGlobalsConsolidationAndLiveBlocks(t *testing.T) {
	t.Parallel()

	dir := writeTestVariantModule(t, map[string]string{
		"go.mod": "module example.com/globcons\n\ngo 1.24\n",
		"glob_test.go": `package globcons

import (
	"os"
	"testing"
)

var selfCycle *uintptr
var zeroFlag bool

func init() {
	var raw uintptr
	selfCycle = &raw
}

var selfAddr any

func init() {
	selfAddr = &selfAddr
}

func deadNegatedShortCircuit() string {
	const a = true
	const b = true
	if !(a && b) {
		return os.Getenv("DEAD_BRANCH")
	}
	return "ok"
}

func tupleConfinedHelper(bad func() string) (string, func() string) {
	type box struct {
		fn func() string
	}
	b := box{fn: bad}
	return "clean", b.fn
}

func TestLiveCalleeAndTupleConfinement(t *testing.T) {
	if deadNegatedShortCircuit() != "ok" {
		t.Fatal("unexpected")
	}
	s, _ := tupleConfinedHelper(func() string { return os.Getenv("UNUSED_SLOT") })
	if s != "clean" {
		t.Fatal(s)
	}
	if zeroFlag {
		_ = os.Getenv("ZERO_GLOBAL_PRUNED")
	}
}

func TestSelfRefGlobalIsMutated(t *testing.T) {
	if selfAddr == nil || selfCycle == nil {
		t.Fatal("nil")
	}
}
`,
	})

	h, _ := newTracedInMemoryHasherAt(t, dir, nil)
	subj1 := Subject{Package: "example.com/globcons", Symbol: "TestLiveCalleeAndTupleConfinement"}
	subj2 := Subject{Package: "example.com/globcons", Symbol: "TestSelfRefGlobalIsMutated"}
	obs, err := h.ComputeObservabilityBatch([]Subject{subj1, subj2})
	if err != nil {
		t.Fatal(err)
	}
	if !obs[subj1].Observable {
		t.Fatalf("TestLiveCalleeAndTupleConfinement = %+v, want Observable", obs[subj1])
	}
	if !obs[subj2].Observable {
		t.Fatalf("TestSelfRefGlobalIsMutated = %+v, want Observable", obs[subj2])
	}

	prog, err := h.loadCached("example.com/globcons")
	if err != nil {
		t.Fatal(err)
	}
	summary := enumerateCallerReferencesForProgram(prog, true, nil, userModulePaths(prog.Pkgs), nil)
	if summary == nil {
		t.Fatal("missing callerReferenceSummary on program")
	}
	if !summary.wholeProgram {
		t.Fatal("expected summary.wholeProgram == true")
	}
	if summary.errorNewSentinelGlobals == nil {
		t.Fatal("expected non-nil summary.errorNewSentinelGlobals even with 0 errors.New sentinels")
	}
	if summary.nonReadOnlyGlobals == nil {
		t.Fatal("expected non-nil summary.nonReadOnlyGlobals on summary")
	}
	var sawSelfAddrMutated bool
	for g := range summary.mutatedGlobals {
		if g != nil && g.Name() == "selfAddr" {
			sawSelfAddrMutated = true
		}
	}
	if !sawSelfAddrMutated {
		t.Fatal("expected selfAddr = &selfAddr global to be classified as mutated")
	}
}

func TestLocalMakeClosureInlineArgsAndFreshParams(t *testing.T) {
	t.Parallel()

	dir := writeTestVariantModule(t, map[string]string{
		"go.mod": "module example.com/localclosures\n\ngo 1.24\n",
		"closures_test.go": `package localclosures

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func withClosure(fn func() int) int {
	return fn()
}

func runWithDir(dir string, fn func(string)) {
	fn(dir)
}

func runWithWriter(w io.Writer, fn func(io.Writer)) {
	fn(w)
}

var escapedDirHook func(string)

func writeSharedDir(d string) {
	_ = os.WriteFile(filepath.Join(d, "shared.txt"), []byte("x"), 0o600)
}

func TestInlineClosureArgPure(t *testing.T) {
	base := 40
	got := withClosure(func() int {
		return base + 2
	})
	if got != 42 {
		t.Fatal(got)
	}
}

func TestFreshDirAcrossCapturingLocalClosure(t *testing.T) {
	sink := 0
	runWithDir(t.TempDir(), func(d string) {
		p := filepath.Join(d, "nested.txt")
		if err := os.WriteFile(p, []byte("payload"), 0o600); err != nil {
			sink++
			t.Fatal("write failed")
		}
	})
	_ = sink
}

func TestFreshDirDirectCapturingClosureCall(t *testing.T) {
	sink := 0
	writeOne := func(d string) {
		if err := os.WriteFile(filepath.Join(d, "one.txt"), []byte("ok"), 0o600); err != nil {
			sink++
			t.Fatal("write failed")
		}
	}
	writeOne(t.TempDir())
	_ = sink
}

func TestStreamAcrossCapturingLocalClosure(t *testing.T) {
	var buf bytes.Buffer
	tag := "ok"
	runWithWriter(&buf, func(w io.Writer) {
		fmt.Fprintf(w, "tag=%s", tag)
	})
	if buf.String() != "tag=ok" {
		t.Fatal(buf.String())
	}
}

func TestEscapedGlobalClosureRefusesFreshParam(t *testing.T) {
	salt := "x"
	escapedDirHook = func(d string) {
		_ = os.WriteFile(filepath.Join(d, salt), []byte("bad"), 0o600)
	}
	escapedDirHook(t.TempDir())
}

func TestEscapedSliceFuncRefusesFreshParam(t *testing.T) {
	hooks := []func(string){writeSharedDir}
	writeSharedDir(t.TempDir())
	hooks[0]("/tmp/non-fresh-escape-target")
}

func runFrameLocalHelper(cb func() int) int {
	step := 1
	local := func(fn func() int) int {
		return fn() + step
	}
	return local(cb)
}

var initHelperVal = runFrameLocalHelper(func() int { return 9 })

func TestSharedHelperCalledInInitAndSubject(t *testing.T) {
	base := initHelperVal
	if got := runFrameLocalHelper(func() int { return base + 1 }); got != 12 {
		t.Fatal(got)
	}
}
`,
		"structsmuggle/smuggle_test.go": `package structsmuggle

import (
	"os"
	"testing"
)

type structClosureHolder struct {
	set func(cb func())
	run func()
}

func makeHolder() *structClosureHolder {
	var savedCB func()
	return &structClosureHolder{
		set: func(cb func()) { savedCB = cb },
		run: func() {
			if savedCB != nil {
				savedCB()
			}
		},
	}
}

var sharedHolder = makeHolder()

func smuggledWritePayload() {
	_ = os.WriteFile("/tmp/smuggled-struct-closure", []byte("1"), 0o600)
}

func TestPlantStructStoredClosure(t *testing.T) {
	sharedHolder.set(smuggledWritePayload)
}

func TestVictimStructStoredClosure(t *testing.T) {
	sharedHolder.run()
	sharedHolder.set(func() {})
}
`,
		"cellsmuggle/cell.go": `package cellsmuggle

import "os"

type Holder struct {
	set func(cb func())
	run func()
}

func makeHolder() *Holder {
	var savedCB func()
	return &Holder{
		set: func(cb func()) { savedCB = cb },
		run: func() {
			if savedCB != nil {
				savedCB()
			}
		},
	}
}

func smuggledWritePayload() {
	_ = os.WriteFile("/tmp/smuggled-cell-closure", []byte("1"), 0o600)
}

func PlantAndCall() {
	h := makeHolder()
	h.set(smuggledWritePayload)
	h.Victim()
}

func (h *Holder) Victim() {
	h.run()
	h.set(func() {})
}
`,
		"cellsmuggle/cell_test.go": `package cellsmuggle

import "testing"

func TestCallPlant(t *testing.T) {
	PlantAndCall()
}
`,
	})

	h, _ := newTracedInMemoryHasherAt(t, dir, nil)
	cases := []struct {
		pkg        string
		symbol     string
		observable bool
	}{
		{"example.com/localclosures", "TestInlineClosureArgPure", true},
		{"example.com/localclosures", "TestFreshDirAcrossCapturingLocalClosure", true},
		{"example.com/localclosures", "TestFreshDirDirectCapturingClosureCall", true},
		{"example.com/localclosures", "TestStreamAcrossCapturingLocalClosure", true},
		{"example.com/localclosures", "TestSharedHelperCalledInInitAndSubject", true},
		{"example.com/localclosures", "TestEscapedGlobalClosureRefusesFreshParam", false},
		{"example.com/localclosures", "TestEscapedSliceFuncRefusesFreshParam", false},
		{"example.com/localclosures/structsmuggle", "TestVictimStructStoredClosure", false},
		{"example.com/localclosures/cellsmuggle", "Holder.Victim", false},
	}
	subjects := make([]Subject, len(cases))
	for i, tc := range cases {
		subjects[i] = Subject{Package: tc.pkg, Symbol: tc.symbol}
	}
	obs, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		got := obs[Subject{Package: tc.pkg, Symbol: tc.symbol}]
		if got.Observable != tc.observable {
			t.Errorf("%s.%s: Observable = %v (reason=%q), want %v", tc.pkg, tc.symbol, got.Observable, got.Reason, tc.observable)
		}
	}
}

func TestInMemoryStreamWritersAndReadersWithCausalTraces(t *testing.T) {
	t.Parallel()

	dir := writeTestVariantModule(t, map[string]string{
		"go.mod": "module example.com/streamsinks\n\ngo 1.24\n",
		"positive/pos_test.go": `package positive

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"hash/crc32"
	"hash/fnv"
	"io"
	"strings"
	"testing"
	"text/tabwriter"
)

func TestPureHashAndDiscardWriters(t *testing.T) {
	fmt.Fprintln(io.Discard, "discarded")
	h256 := sha256.New()
	fmt.Fprintf(h256, "alpha:%d", 1)
	hfnv := fnv.New64a()
	fmt.Fprint(hfnv, "beta")
	hcrc := crc32.NewIEEE()
	fmt.Fprintf(hcrc, "gamma")
	mac := hmac.New(sha256.New, []byte("secret-key"))
	fmt.Fprintf(mac, "authenticated:%x", h256.Sum(nil))
	if len(mac.Sum(nil)) == 0 || hfnv.Sum64() == 0 || hcrc.Sum32() == 0 {
		t.Fatal("unexpected empty digest")
	}
}

func TestConfinedBufioAndTabwriterWriters(t *testing.T) {
	var b1, b2 bytes.Buffer
	bw := bufio.NewWriterSize(&b1, 64)
	fmt.Fprintf(bw, "hello %s", "world")
	_, _ = bw.ReadFrom(strings.NewReader("!"))
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	bw.Reset(&b2)
	fmt.Fprintln(bw, "second")
	_ = bw.Flush()

	tw := tabwriter.NewWriter(&b2, 0, 4, 1, ' ', 0)
	fmt.Fprintln(tw, "a\tb")
	_ = tw.Flush()

	var tw2 tabwriter.Writer
	tw2.Init(&b1, 0, 2, 1, ' ', 0)
	fmt.Fprintln(&tw2, "c\td")
	_ = tw2.Flush()

	expr, err := parser.ParseExpr("1 + 2")
	if err != nil || expr.Pos() == token.NoPos {
		t.Fatal(err)
	}
	id := ast.NewIdent("v")
	if id.String() != "v" || ast.Var.String() != "var" {
		t.Fatal("ident/objkind string")
	}
	scanner.PrintError(&b1, scanner.ErrorList{})

	if b1.Len() == 0 || b2.Len() == 0 {
		t.Fatal("empty")
	}
}

func TestInMemoryReadersAndSscan(t *testing.T) {
	var a, b, c, d, e int
	if _, err := fmt.Fscan(strings.NewReader("11"), &a); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fscanf(bytes.NewReader([]byte("v=22")), "v=%d", &b); err != nil {
		t.Fatal(err)
	}
	buf := bytes.NewBufferString("33\n")
	if _, err := fmt.Fscanln(buf, &c); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(strings.NewReader("44"))
	if _, err := fmt.Fscan(br, &d); err != nil {
		t.Fatal(err)
	}
	br.Reset(bytes.NewReader([]byte("55")))
	if _, err := fmt.Fscan(br, &e); err != nil {
		t.Fatal(err)
	}
	var s int
	if _, err := fmt.Sscanf("66", "%d", &s); err != nil {
		t.Fatal(err)
	}
	if a+b+c+d+e+s != 11+22+33+44+55+66 {
		t.Fatalf("unexpected sum: %d", a+b+c+d+e+s)
	}
}
`,
		"negative/neg_test.go": `package negative

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"fmt"
	"hash"
	"hash/maphash"
	"io"
	"strings"
	"testing"
)

type customWriter struct{}

func (*customWriter) Write(p []byte) (int, error) { return len(p), nil }

type customReader struct{}

func (*customReader) Read(p []byte) (int, error) { return 0, io.EOF }

type customHash struct{ maphash.Hash }

func newImpureHash() hash.Hash { return &customHash{} }

func retargetViaTypeAssert(w io.Writer) {
	if bw, ok := w.(*bufio.Writer); ok {
		bw.Reset(&customWriter{})
	}
}

func TestBufioInterfaceEscapeTypeAssertReset(t *testing.T) {
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	retargetViaTypeAssert(bw)
	fmt.Fprintf(bw, "escaped %d", 1)
	_ = bw.Flush()
}

func TestBufioWriterOverCustomSink(t *testing.T) {
	bw := bufio.NewWriter(&customWriter{})
	fmt.Fprintf(bw, "bad %d", 1)
}

func TestMaphashWriterRejected(t *testing.T) {
	var mh maphash.Hash
	fmt.Fprintf(&mh, "seeded %d", 1)
}

func TestHMACImpureFactoryRejected(t *testing.T) {
	mac := hmac.New(newImpureHash, []byte("k"))
	fmt.Fprintf(mac, "bad %d", 1)
}

func TestBufioReaderResetCustomRejected(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("10"))
	br.Reset(&customReader{})
	var v int
	_, _ = fmt.Fscan(br, &v)
}

func TestBufioReaderWriteToCustomRejected(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("10"))
	_, _ = br.WriteTo(&customWriter{})
	var v int
	_, _ = fmt.Fscan(br, &v)
}

func TestBufioReaderPassThroughNestedResetRejected(t *testing.T) {
	br1 := bufio.NewReader(strings.NewReader("10"))
	br2 := bufio.NewReader(br1)
	br2.Reset(&customReader{})
	var v int
	_, _ = fmt.Fscan(br1, &v)
}

func TestBufioReaderViaUnconfinedReadFromRejected(t *testing.T) {
	br1 := bufio.NewReader(strings.NewReader("10"))
	otherBW := bufio.NewWriter(&customWriter{})
	_, _ = otherBW.ReadFrom(br1)
	var v int
	_, _ = fmt.Fscan(br1, &v)
}

func makeBufioPair(buf *bytes.Buffer) (*bufio.Writer, *bufio.Writer) {
	bw := bufio.NewWriter(buf)
	return bw, bw
}

func TestTupleReturningHelperSiblingResetRejected(t *testing.T) {
	var buf bytes.Buffer
	bw1, bw2 := makeBufioPair(&buf)
	bw2.Reset(&customWriter{})
	fmt.Fprintln(bw1, "x")
}

func reentrantMakeWriter(buf *bytes.Buffer, step int, carry *bufio.Writer) *bufio.Writer {
	if step == 1 {
		return carry
	}
	bw := bufio.NewWriter(buf)
	leaked := reentrantMakeWriter(buf, 1, bw)
	leaked.Reset(&customWriter{})
	return bw
}

func TestReentrantHelperReturnResetRejected(t *testing.T) {
	var buf bytes.Buffer
	bw := reentrantMakeWriter(&buf, 0, bufio.NewWriter(&buf))
	fmt.Fprintln(bw, "x")
}

func TestLoopWrappedBufioWriterRejected(t *testing.T) {
	var buf bytes.Buffer
	var w io.Writer = &buf
	for range 2 {
		w = bufio.NewWriter(w)
	}
	fmt.Fprintln(w, "hi")
}

func recursiveHMACFactory() hash.Hash {
	return hmac.New(recursiveHMACFactory, []byte("k"))
}

func TestRecursiveHMACFactoryRejected(t *testing.T) {
	fmt.Fprintln(hmac.New(recursiveHMACFactory, []byte("k")), "hi")
}

func makeWriterFrom(w io.Writer) *bufio.Writer {
	return bufio.NewWriter(w)
}

func TestPhiSameHelperTwoBufioArgsRejected(t *testing.T) {
	var buf bytes.Buffer
	var w *bufio.Writer
	if len("a") == 1 {
		w = makeWriterFrom(&buf)
	} else {
		w = makeWriterFrom(&customWriter{})
	}
	fmt.Fprintln(w, "x")
}
`,
	})

	h, rec := newTracedFullSyntaxHasherAt(t, dir, nil)

	posSyms := []string{
		"TestPureHashAndDiscardWriters",
		"TestConfinedBufioAndTabwriterWriters",
		"TestInMemoryReadersAndSscan",
	}
	var posSubjs []Subject
	for _, s := range posSyms {
		posSubjs = append(posSubjs, Subject{Package: "example.com/streamsinks/positive", Symbol: s})
	}
	posObs, err := h.ComputeObservabilityBatch(posSubjs)
	if err != nil {
		t.Fatal(err)
	}
	for _, subj := range posSubjs {
		if !posObs[subj].Observable {
			t.Errorf("%s: got %+v, want Observable=true", subj.Symbol, posObs[subj])
		}
	}

	negCases := []struct {
		symbol     string
		wantReason string
	}{
		{"TestBufioInterfaceEscapeTypeAssertReset", "unsupported_concrete_type:*example.com/streamsinks/negative.customWriter"},
		{"TestBufioWriterOverCustomSink", "unsupported_concrete_type"},
		{"TestMaphashWriterRejected", "unsupported_concrete_type"},
		{"TestHMACImpureFactoryRejected", "hmac_factory_return"},
		{"TestBufioReaderResetCustomRejected", "unsupported_concrete_type"},
		{"TestBufioReaderWriteToCustomRejected", "unsupported_concrete_type"},
		{"TestBufioReaderPassThroughNestedResetRejected", "unsupported_concrete_type:*example.com/streamsinks/negative.customReader"},
		{"TestBufioReaderViaUnconfinedReadFromRejected", "wrapper_iface_std_escape"},
		{"TestTupleReturningHelperSiblingResetRejected", "wrapper_escaped_return"},
		{"TestReentrantHelperReturnResetRejected", "wrapper_unconfined_call"},
		{"TestLoopWrappedBufioWriterRejected", "nil_or_depth_exceeded"},
		{"TestRecursiveHMACFactoryRejected", "nil_or_depth_exceeded"},
		{"TestPhiSameHelperTwoBufioArgsRejected", "unsupported_concrete_type:*example.com/streamsinks/negative.customWriter"},
	}
	var negSubjs []Subject
	for _, tc := range negCases {
		negSubjs = append(negSubjs, Subject{Package: "example.com/streamsinks/negative", Symbol: tc.symbol})
	}
	negObs, err := h.ComputeObservabilityBatch(negSubjs)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range negCases {
		subj := Subject{Package: "example.com/streamsinks/negative", Symbol: tc.symbol}
		got := negObs[subj]
		if got.Observable {
			t.Errorf("%s: unexpectedly Observable=true", tc.symbol)
		}
		if !hasTraceEventReason(rec, "closure.stream.reject", tc.wantReason) {
			t.Errorf("%s: missing closure.stream.reject trace containing %q; events=%+v", tc.symbol, tc.wantReason, rec.ByName("closure.stream.reject"))
		}
	}
}

func TestGoParserAndSealedGoASTNodeDispatch(t *testing.T) {
	t.Parallel()

	dir := writeTestVariantModule(t, map[string]string{
		"go.mod": "module example.com/astparse\n\ngo 1.24\n",
		"sealed/sealed_test.go": `package sealed

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"strings"
	"testing"
)

func TestParseFileAndInspectSealedNodes(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "mem.go", "package p\n\nvar X = 1 + 2\n", parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Decls) == 0 || !f.Decls[0].Pos().IsValid() {
		t.Fatal("invalid decl pos")
	}
	if gd, ok := f.Decls[0].(*ast.GenDecl); !ok || !gd.Pos().IsValid() {
		t.Fatal("expected concrete GenDecl assertion to remain observable")
	}
	count := 0
	ast.Inspect(f, func(n ast.Node) bool {
		if n != nil && n.Pos().IsValid() {
			count++
		}
		return true
	})
	expr, err := parser.ParseExprFrom(fset, "expr.go", strings.NewReader("3 * 4"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !expr.End().IsValid() || count == 0 {
		t.Fatal("invalid")
	}
	_, badErr := parser.ParseFile(fset, "bad.go", []byte("package"), 0)
	if badErr == nil || badErr.Error() == "" {
		t.Fatal("expected syntax error")
	}
}

func TestParseFileTraceModeRejected(t *testing.T) {
	fset := token.NewFileSet()
	_, _ = parser.ParseFile(fset, "mem.go", "package p\n", parser.Trace)
}

func TestParseFileNilSrcRejected(t *testing.T) {
	fset := token.NewFileSet()
	_, _ = parser.ParseFile(fset, "nonexistent.go", nil, 0)
}

func TestParseFileNilableReaderWidenedToAnyRejected(t *testing.T) {
	fset := token.NewFileSet()
	var r io.Reader
	_, _ = parser.ParseFile(fset, "nonexistent.go", r, 0)
}

func TestASTFprintAndScopeStringRejected(t *testing.T) {
	var buf strings.Builder
	expr, _ := parser.ParseExpr("1")
	_ = ast.Fprint(&buf, token.NewFileSet(), expr, nil)
	_ = ast.NewScope(nil).String()
}

func TestFmtSprintASTScopeRejected(t *testing.T) {
	s := ast.NewScope(nil)
	s.Insert(ast.NewObj(ast.Var, "a"))
	_ = fmt.Sprint(s)
}

func TestFmtSprintCompositeASTScopeRejected(t *testing.T) {
	s := ast.NewScope(nil)
	_ = fmt.Sprint([1]*ast.Scope{s})
}

func TestTLogASTCommentMapRejected(t *testing.T) {
	fset := token.NewFileSet()
	f, _ := parser.ParseFile(fset, "mem.go", "package p\n", 0)
	cm := ast.NewCommentMap(fset, f, nil)
	t.Log(cm)
}

func TestFmtSprintWidenedASTNodeToAnyRejected(t *testing.T) {
	fset := token.NewFileSet()
	f, _ := parser.ParseFile(fset, "mem.go", "package p\nvar X = 1\n", 0)
	var n ast.Node = f
	_ = fmt.Sprint(n)
}

type scopeVisitor struct {
	S *ast.Scope
}

func (v scopeVisitor) Visit(ast.Node) ast.Visitor { return v }

func TestFmtSprintWidenedASTVisitorRejected(t *testing.T) {
	sc := ast.NewScope(nil)
	sc.Insert(ast.NewObj(ast.Var, "a"))
	var v ast.Visitor = scopeVisitor{S: sc}
	_ = fmt.Sprint(v)
}

func TestFmtSprintTypeAssertedASTNodeRejected(t *testing.T) {
	fset := token.NewFileSet()
	f, _ := parser.ParseFile(fset, "mem.go", "package p\nvar a, b = 1, 2\n", 0)
	var n ast.Node = f
	if x, ok := n.(any); ok {
		_ = fmt.Sprint(x)
	}
}
`,
		"initscope/initscope_test.go": `package initscope

import (
	"fmt"
	"go/ast"
	"testing"
)

var initFormattedScope = fmt.Sprint(ast.NewScope(nil))

func TestAfterInitScopeFormat(t *testing.T) {
	_ = initFormattedScope
}
`,
		"reflectevil/reflectevil_test.go": `package reflectevil

import (
	"go/ast"
	"go/token"
	"os"
	"reflect"
	"testing"
)

type EvilNode struct {
	ast.Expr
}

func (EvilNode) Pos() token.Pos {
	if os.Getenv("EVIL_REFLECT_AST_POS") != "" {
		return 2
	}
	return 1
}

var globalNode ast.Node

func TestPlantViaReflectComposite(t *testing.T) {
	arrType := reflect.TypeOf([1]EvilNode{}).Elem()
	v := reflect.New(arrType).Elem()
	v.Field(0).Set(reflect.ValueOf(&ast.Ident{Name: "x"}))
	globalNode = v.Interface().(ast.Node)
}

func TestVictimOpenGlobalNodePos(t *testing.T) {
	if globalNode != nil {
		_ = globalNode.Pos()
	}
}
`,
		"unsealed/unsealed_test.go": `package unsealed

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"
)

type EvilDecl struct {
	ast.Decl
}

func (EvilDecl) Pos() token.Pos {
	if os.Getenv("EVIL_AST_OVERRIDE") != "" {
		return 2
	}
	return 1
}

var sinkDecl ast.Decl = EvilDecl{}

func TestUnsealedASTInvokeRejectedWhenEvilNodeExists(t *testing.T) {
	_ = sinkDecl
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "mem.go", "package p\nvar X = 1\n", 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Decls[0].Pos()
}
`,
	})

	h, rec := newTracedFullSyntaxHasherAt(t, dir, nil)

	sealedSubjs := []Subject{
		{Package: "example.com/astparse/sealed", Symbol: "TestParseFileAndInspectSealedNodes"},
		{Package: "example.com/astparse/sealed", Symbol: "TestParseFileTraceModeRejected"},
		{Package: "example.com/astparse/sealed", Symbol: "TestParseFileNilSrcRejected"},
		{Package: "example.com/astparse/sealed", Symbol: "TestParseFileNilableReaderWidenedToAnyRejected"},
		{Package: "example.com/astparse/sealed", Symbol: "TestASTFprintAndScopeStringRejected"},
		{Package: "example.com/astparse/sealed", Symbol: "TestFmtSprintASTScopeRejected"},
		{Package: "example.com/astparse/sealed", Symbol: "TestFmtSprintCompositeASTScopeRejected"},
		{Package: "example.com/astparse/sealed", Symbol: "TestTLogASTCommentMapRejected"},
		{Package: "example.com/astparse/sealed", Symbol: "TestFmtSprintWidenedASTNodeToAnyRejected"},
		{Package: "example.com/astparse/sealed", Symbol: "TestFmtSprintWidenedASTVisitorRejected"},
		{Package: "example.com/astparse/sealed", Symbol: "TestFmtSprintTypeAssertedASTNodeRejected"},
		{Package: "example.com/astparse/initscope", Symbol: "TestAfterInitScopeFormat"},
		{Package: "example.com/astparse/reflectevil", Symbol: "TestVictimOpenGlobalNodePos"},
		{Package: "example.com/astparse/unsealed", Symbol: "TestUnsealedASTInvokeRejectedWhenEvilNodeExists"},
	}
	obs, err := h.ComputeObservabilityBatch(sealedSubjs)
	if err != nil {
		t.Fatal(err)
	}
	if !obs[sealedSubjs[0]].Observable {
		t.Fatalf("TestParseFileAndInspectSealedNodes = %+v, want Observable=true", obs[sealedSubjs[0]])
	}
	for _, neg := range sealedSubjs[1:] {
		if obs[neg].Observable {
			t.Errorf("%s: unexpectedly Observable=true (%+v)", neg.Symbol, obs[neg])
		}
	}
	for _, wantReason := range []string{"mode_may_enable_trace", "src_nil_const", "src_nilable_change_interface"} {
		if !hasTraceEventReason(rec, "closure.parser.reject", wantReason) {
			t.Errorf("missing closure.parser.reject with reason containing %q; events=%+v", wantReason, rec.ByName("closure.parser.reject"))
		}
	}
	for _, wantUnsealed := range []string{"EvilNode", "EvilDecl"} {
		if !hasTraceEventReason(rec, "closure.ast_sealed.reject", wantUnsealed) {
			t.Errorf("missing closure.ast_sealed.reject with reason containing %q; events=%+v", wantUnsealed, rec.ByName("closure.ast_sealed.reject"))
		}
	}
}

func setReadBuildInfoDelegate(h *Prover, verified bool) {
	cloned := maps.Clone(h.PureDelegates())
	if cloned == nil {
		cloned = make(map[string]bool)
	}
	if verified {
		cloned["runtime/debug:ReadBuildInfo"] = true
	} else {
		delete(cloned, "runtime/debug:ReadBuildInfo")
	}
	h.SetSelectionForTest(h.Selection().WithPureDelegatesForTest(cloned))
}

func TestRuntimeDebugReadBuildInfoBuildVCSAndGoModFold(t *testing.T) {
	t.Parallel()

	baseFiles := map[string]string{
		"go.mod": "module example.com/binfo\n\ngo 1.24\n",
		"plain/plain.go": `package plain

func Add(a, b int) int { return a + b }
`,
		"cmd/app/main.go": `package main

import "runtime/debug"

func Banner() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return "none"
	}
	_, _ = debug.ParseBuildInfo(info.String())
	return info.Main.Path
}

func main() {
	_ = Banner()
}
`,
		"lib/lib.go": `package lib

import "runtime/debug"

var initMainPath string

func init() {
	if info, ok := debug.ReadBuildInfo(); ok && info != nil {
		initMainPath = info.String()
	}
}

func ModString() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return initMainPath
	}
	parsed, err := debug.ParseBuildInfo(info.String())
	if err != nil || parsed == nil {
		return ""
	}
	return parsed.String()
}
`,
		"lib/lib_test.go": `package lib

import (
	"os"
	"runtime/debug"
	"testing"
)

func TestMain(m *testing.M) {
	_, _ = debug.ReadBuildInfo()
	os.Exit(m.Run())
}

func TestReadBuildInfo(t *testing.T) {
	_ = ModString()
}
`,
	}
	dir := writeTestVariantModule(t, baseFiles)

	plainSubj := Subject{Package: "example.com/binfo/plain", Symbol: "Add"}
	mainSubj := Subject{Package: "example.com/binfo/cmd/app", Symbol: "Banner"}
	libSubj := Subject{Package: "example.com/binfo/lib", Symbol: "TestReadBuildInfo"}

	evalUnder := func(env []string, verifiedDelegate bool, buildFlags ...string) (map[Subject]Closure, map[Subject][]string, Observability) {
		h, _ := newTracedInMemoryHasherAt(t, dir, env, buildFlags...)
		setReadBuildInfoDelegate(h, verifiedDelegate)
		cl, srcs, err := h.ComputeMaximalBatch([]Subject{plainSubj, mainSubj, libSubj})
		if err != nil {
			t.Fatal(err)
		}
		obs, err := h.ComputeObservabilityBatch([]Subject{libSubj})
		if err != nil {
			t.Fatal(err)
		}
		return cl, srcs, obs[libSubj]
	}

	// 1. Default (-buildvcs=auto):
	// - plain does NOT fold go.mod into SourceFiles.
	// - cmd/app (Tier 1) and lib (Tier 1) remain unverifiable on MaximalClosure because go build embeds VCS stamps under auto.
	// - lib TestReadBuildInfo IS Observable on Tier 2 because go test forces buildvcs=false under auto!
	clAuto, srcsAuto, obsAuto := evalUnder(nil, true)
	goModPath := filepath.Clean(filepath.Join(dir, "go.mod"))
	if slices.Contains(srcsAuto[plainSubj], goModPath) {
		t.Fatalf("plain package (not importing runtime/debug) unexpectedly folded go.mod into SourceFiles: %v", srcsAuto[plainSubj])
	}
	if !slices.Contains(srcsAuto[mainSubj], goModPath) || !slices.Contains(srcsAuto[libSubj], goModPath) {
		t.Fatalf("runtime/debug importers missing go.mod in SourceFiles: main=%v lib=%v", srcsAuto[mainSubj], srcsAuto[libSubj])
	}
	if !clAuto[mainSubj].Unverifiable {
		t.Fatalf("cmd/app MaximalClosure under -buildvcs=auto = %+v, want Unverifiable=true", clAuto[mainSubj])
	}
	if !clAuto[libSubj].Unverifiable {
		t.Fatalf("lib MaximalClosure under -buildvcs=auto = %+v, want Unverifiable=true", clAuto[libSubj])
	}
	if !obsAuto.Observable {
		t.Fatalf("lib TestReadBuildInfo under -buildvcs=auto = %+v, want Observable=true", obsAuto)
	}

	// 2. Explicit -buildvcs=false:
	// - cmd/app (package main) IS admitted at Tier 1 (Unverifiable == false)!
	// - lib (library package) remains Unverifiable == true at Tier 1, and Observable == true at Tier 2!
	clFalse, _, obsFalse := evalUnder(nil, true, "-buildvcs=false")
	if clFalse[mainSubj].Unverifiable {
		t.Fatalf("cmd/app MaximalClosure under -buildvcs=false = %+v, want Unverifiable=false", clFalse[mainSubj])
	}
	if !clFalse[libSubj].Unverifiable {
		t.Fatalf("lib MaximalClosure under -buildvcs=false = %+v, want Unverifiable=true (library may link into VCS-stamped binary)", clFalse[libSubj])
	}
	if !obsFalse.Observable {
		t.Fatalf("lib TestReadBuildInfo under -buildvcs=false = %+v, want Observable=true", obsFalse)
	}

	// 3. Explicit -buildvcs=true, invalid -buildvcs=bogus, GOFLAGS=-buildvcs=true, and override:
	_, _, obsTrue := evalUnder(nil, true, "-buildvcs=true")
	if obsTrue.Observable {
		t.Fatalf("lib TestReadBuildInfo under -buildvcs=true unexpectedly Observable=true")
	}
	_, _, obsInvalid := evalUnder(nil, true, "-buildvcs=bogus")
	if obsInvalid.Observable {
		t.Fatalf("lib TestReadBuildInfo under -buildvcs=bogus unexpectedly Observable=true")
	}
	_, _, obsGoflagsTrue := evalUnder(listingEnv("-buildvcs=true", "off"), true)
	if obsGoflagsTrue.Observable {
		t.Fatalf("lib TestReadBuildInfo under GOFLAGS=-buildvcs=true unexpectedly Observable=true")
	}
	_, _, obsGoflagsOverridden := evalUnder(listingEnv("-buildvcs=true", "off"), true, "-buildvcs=false")
	if !obsGoflagsOverridden.Observable {
		t.Fatalf("lib TestReadBuildInfo under GOFLAGS=-buildvcs=true + explicit -buildvcs=false = %+v, want Observable=true", obsGoflagsOverridden)
	}

	// 4. Unverified runtime/debug:ReadBuildInfo delegate negative control:
	clUnverified, _, obsUnverified := evalUnder(nil, false, "-buildvcs=false")
	if !clUnverified[mainSubj].Unverifiable {
		t.Fatalf("cmd/app MaximalClosure with unverified ReadBuildInfo delegate unexpectedly verifiable")
	}
	if obsUnverified.Observable {
		t.Fatalf("lib TestReadBuildInfo with unverified ReadBuildInfo delegate unexpectedly Observable=true")
	}

	// 5. Editing go.mod and adding/editing go.sum moves MaximalClosure ONLY for runtime/debug importers!
	writeFile(t, dir, "go.mod", "module example.com/binfo\n\ngo 1.24.0\n")
	clAfterGoMod, _, _ := evalUnder(nil, true, "-buildvcs=false")
	if clAfterGoMod[plainSubj].Hash != clFalse[plainSubj].Hash {
		t.Fatalf("editing go.mod moved plain package MaximalClosure (%s -> %s)", clFalse[plainSubj].Hash, clAfterGoMod[plainSubj].Hash)
	}
	if clAfterGoMod[mainSubj].Hash == clFalse[mainSubj].Hash || clAfterGoMod[libSubj].Hash == clFalse[libSubj].Hash {
		t.Fatalf("editing go.mod failed to move runtime/debug importer MaximalClosure: main=%s lib=%s", clAfterGoMod[mainSubj].Hash, clAfterGoMod[libSubj].Hash)
	}

	writeFile(t, dir, "go.sum", "example.com/dep v1.0.0 h1:deadbeef=\n")
	clAfterGoSum, srcsAfterGoSum, _ := evalUnder(nil, true, "-buildvcs=false")
	goSumPath := filepath.Clean(filepath.Join(dir, "go.sum"))
	if !slices.Contains(srcsAfterGoSum[mainSubj], goSumPath) {
		t.Fatalf("go.sum missing from runtime/debug importer SourceFiles: %v", srcsAfterGoSum[mainSubj])
	}
	if clAfterGoSum[mainSubj].Hash == clAfterGoMod[mainSubj].Hash {
		t.Fatalf("adding go.sum failed to move runtime/debug importer MaximalClosure")
	}

	// 6. Active GOWORK folds go.work + go.work.sum and moves on edit while staying relocation-keyed by basename:
	workPath := filepath.Join(dir, "go.work")
	writeFile(t, dir, "go.work", "go 1.24\n\nuse .\n")
	clWork1, srcsWork1, _ := evalUnder(listingEnv("", workPath), true, "-buildvcs=false")
	if !slices.Contains(srcsWork1[mainSubj], filepath.Clean(workPath)) {
		t.Fatalf("go.work missing from runtime/debug importer SourceFiles under GOWORK: %v", srcsWork1[mainSubj])
	}
	writeFile(t, dir, "go.work", "go 1.24.0\n\nuse .\n")
	clWork2, _, _ := evalUnder(listingEnv("", workPath), true, "-buildvcs=false")
	if clWork2[mainSubj].Hash == clWork1[mainSubj].Hash {
		t.Fatalf("editing go.work under GOWORK failed to move runtime/debug importer MaximalClosure")
	}

	// 7. vendor/modules.txt folds into SourceFiles and moves MaximalClosure on creation and edit:
	vendorManifest := filepath.Clean(filepath.Join(dir, "vendor", "modules.txt"))
	writeFile(t, dir, filepath.Join("vendor", "modules.txt"), "# example.com/dep v1.0.0\n## explicit\n")
	clVendor1, srcsVendor1, _ := evalUnder(nil, true, "-buildvcs=false")
	if !slices.Contains(srcsVendor1[mainSubj], vendorManifest) {
		t.Fatalf("vendor/modules.txt missing from runtime/debug importer SourceFiles: %v", srcsVendor1[mainSubj])
	}
	if clVendor1[mainSubj].Hash == clAfterGoSum[mainSubj].Hash {
		t.Fatalf("creating vendor/modules.txt failed to move runtime/debug importer MaximalClosure")
	}
	writeFile(t, dir, filepath.Join("vendor", "modules.txt"), "# example.com/dep v1.0.0 => ../dep\n## explicit\n")
	clVendor2, _, _ := evalUnder(nil, true, "-buildvcs=false")
	if clVendor2[mainSubj].Hash == clVendor1[mainSubj].Hash {
		t.Fatalf("editing vendor/modules.txt failed to move runtime/debug importer MaximalClosure")
	}
	clWorkVendor, srcsWorkVendor, _ := evalUnder(listingEnv("", workPath), true, "-buildvcs=false")
	if !slices.Contains(srcsWorkVendor[mainSubj], vendorManifest) {
		t.Fatalf("workspace vendor/modules.txt missing from SourceFiles under GOWORK: %v", srcsWorkVendor[mainSubj])
	}
	if clWorkVendor[mainSubj].Hash == clWork2[mainSubj].Hash {
		t.Fatalf("workspace vendor/modules.txt failed to move runtime/debug importer MaximalClosure under GOWORK")
	}
	_ = context.Background()
}

func TestSubjectEnumerationRebindableStdWrapperRefused(t *testing.T) {
	t.Parallel()

	dir := writeTestVariantModule(t, map[string]string{
		"go.mod": "module example.com/enumrebind\n\ngo 1.24\n",
		"rebind.go": `package enumrebind

import (
	"bufio"
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
)

type envWriter struct{}

func (envWriter) Write(p []byte) (int, error) {
	if os.Getenv("HIDDEN_ENUM_ENV") != "" {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

type envReader struct{}

func (envReader) Read(p []byte) (int, error) {
	if os.Getenv("HIDDEN_ENUM_ENV") != "" {
		return 0, io.ErrUnexpectedEOF
	}
	return 0, io.EOF
}

type envReaderAt struct{}

func (envReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if os.Getenv("HIDDEN_READERAT_ENV") != "" {
		return 0, io.ErrUnexpectedEOF
	}
	return 0, io.EOF
}

type envStringer struct{}

func (envStringer) String() string { return os.Getenv("HIDDEN_LIST_ENV") }

type envErr struct{}

func (envErr) Error() string { return os.Getenv("HIDDEN_PIPE_ENV") }

type Report struct {
	tw *tabwriter.Writer
}

func (r *Report) EmitMethod() error {
	_, _ = r.tw.Write([]byte("a\tb\n"))
	return r.tw.Flush()
}

func EmitTabwriter(tw *tabwriter.Writer) error {
	_, _ = tw.Write([]byte("a\tb\n"))
	return tw.Flush()
}

func EmitBufioWriter(bw *bufio.Writer) error {
	_, _ = bw.WriteString("x")
	return bw.Flush()
}

func EmitLimitedReader(lr *io.LimitedReader) (int, error) {
	var buf [4]byte
	return lr.Read(buf[:])
}

func FormatListFront(l *list.List) string {
	return fmt.Sprint(l.Front().Value)
}

func FormatPipeErr(pr *io.PipeReader) string {
	var buf [1]byte
	_, err := pr.Read(buf[:])
	return fmt.Sprint(err)
}

func FormatJoinedErr(err error) string {
	return err.Error()
}

func EmitSectionReaderOverwrite(sr *io.SectionReader) (int, error) {
	var buf [3]byte
	return sr.Read(buf[:])
}

func EmitNopCloser(rc io.ReadCloser) (int, error) {
	var buf [3]byte
	return rc.Read(buf[:])
}

func FormatMultiWrappedErr(err error) string {
	return fmt.Sprint(errors.Is(err, envErr{}))
}

func FormatValueCtxErr(ctx context.Context) error {
	return ctx.Err()
}

func FormatCancelCause(ctx context.Context) string {
	return fmt.Sprint(context.Cause(ctx))
}

func FormatCleanWithCancel(ctx context.Context) string {
	return fmt.Sprint(ctx.Err())
}

func RunAll() {
	tw := tabwriter.NewWriter(io.Discard, 0, 4, 1, ' ', 0)
	tw.Init(envWriter{}, 0, 4, 1, ' ', 0)
	_ = EmitTabwriter(tw)
	rep := &Report{tw: tw}
	_ = rep.EmitMethod()

	bw := bufio.NewWriter(io.Discard)
	bw.Reset(envWriter{})
	_ = EmitBufioWriter(bw)

	lr := io.LimitReader(strings.NewReader("abc"), 2).(*io.LimitedReader)
	lr.R = envReader{}
	_, _ = EmitLimitedReader(lr)

	l := list.New()
	l.PushBack(envStringer{})
	_ = FormatListFront(l)

	pr, pw := io.Pipe()
	_ = pw.CloseWithError(envErr{})
	_ = FormatPipeErr(pr)

	jErr := errors.Join(io.EOF)
	jErr.(interface{ Unwrap() []error }).Unwrap()[0] = envErr{}
	_ = FormatJoinedErr(jErr)

	mErr := fmt.Errorf("multi: %w %w", io.EOF, io.ErrUnexpectedEOF)
	mErr.(interface{ Unwrap() []error }).Unwrap()[0] = envErr{}
	_ = FormatMultiWrappedErr(mErr)

	sr := io.NewSectionReader(strings.NewReader("abc"), 0, 3)
	*sr = *io.NewSectionReader(envReaderAt{}, 0, 3)
	_, _ = EmitSectionReaderOverwrite(sr)

	ccCtx, cancelCause := context.WithCancelCause(context.Background())
	cancelCause(envErr{})
	_ = FormatCancelCause(ccCtx)

	nc := io.NopCloser(strings.NewReader("abc"))
	_, _ = EmitNopCloser(nc)

	vCtx := context.WithValue(context.Background(), "k", "v")
	_ = FormatValueCtxErr(vCtx)

	cleanCtx, cleanCancel := context.WithCancel(context.Background())
	cleanCancel()
	_ = FormatCleanWithCancel(cleanCtx)
}
`,
		"rebind_test.go": `package enumrebind

import "testing"

func TestExerciseRunAll(t *testing.T) {
	RunAll()
}
`,
	})

	h, rec := newTracedInMemoryHasherAt(t, dir, nil)
	pkg := "example.com/enumrebind"
	refused := []Subject{
		{Package: pkg, Symbol: "EmitTabwriter"},
		{Package: pkg, Symbol: "Report.EmitMethod"},
		{Package: pkg, Symbol: "EmitBufioWriter"},
		{Package: pkg, Symbol: "EmitLimitedReader"},
		{Package: pkg, Symbol: "FormatListFront"},
		{Package: pkg, Symbol: "FormatPipeErr"},
		{Package: pkg, Symbol: "FormatJoinedErr"},
		{Package: pkg, Symbol: "FormatMultiWrappedErr"},
		{Package: pkg, Symbol: "EmitSectionReaderOverwrite"},
		{Package: pkg, Symbol: "FormatCancelCause"},
	}
	admitted := []Subject{
		{Package: pkg, Symbol: "EmitNopCloser"},
		{Package: pkg, Symbol: "FormatValueCtxErr"},
		{Package: pkg, Symbol: "FormatCleanWithCancel"},
	}
	all := append(slices.Clone(refused), admitted...)

	obs, err := h.ComputeObservabilityBatch(all)
	if err != nil {
		t.Fatal(err)
	}
	rooted, err := h.ComputeRootedFunctions(t.Context(), all)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range refused {
		if obs[s].Observable {
			t.Errorf("%s: unexpectedly Observable=true (%+v)", s.Symbol, obs[s])
		}
		if rooted[s].Complete && !rooted[s].Fns[pkg+"\x00envWriter.Write"] && !rooted[s].Fns[pkg+"\x00envReader.Read"] && !rooted[s].Fns[pkg+"\x00envReaderAt.ReadAt"] && !rooted[s].Fns[pkg+"\x00envStringer.String"] && !rooted[s].Fns[pkg+"\x00envErr.Error"] {
			t.Errorf("%s: Complete=true without rebind target in Fns: %+v", s.Symbol, rooted[s])
		}
	}
	if len(rec.ByName("closure.std_alloc.mutable")) == 0 {
		t.Fatalf("expected closure.std_alloc.mutable trace events on rebindable stdlib carriers")
	}
	foundSiblingMutator := false
	for _, ev := range rec.ByName("closure.callee.reject") {
		if ev.StringField("gate") == "sibling_tuple_mutator" {
			foundSiblingMutator = true
			break
		}
	}
	if !foundSiblingMutator {
		t.Fatalf("expected closure.callee.reject with gate=sibling_tuple_mutator; events=%+v", rec.ByName("closure.callee.reject"))
	}
	for _, s := range admitted {
		if !obs[s].Observable {
			t.Errorf("%s: got %+v, want Observable=true", s.Symbol, obs[s])
		}
		if !rooted[s].Complete {
			t.Errorf("%s: got Complete=false (%+v), want Complete=true", s.Symbol, rooted[s])
		}
	}

	// Verify mutated context.Canceled in an unreached caller refuses both
	// context.WithCancel and testing.T.Context() enumeration closures.
	dirMut := writeTestVariantModule(t, map[string]string{
		"go.mod": "module example.com/mutcanceled\n\ngo 1.24\n",
		"mut.go": `package mutcanceled

import (
	"context"
	"fmt"
	"os"
)

type envErr struct{}

func (envErr) Error() string { return os.Getenv("GOFRESH_CANCELED_SECRET") }

func FormatMutatedCanceled(ctx context.Context) string {
	return fmt.Sprint(ctx.Err())
}

func FormatMutatedTestingCtx(ctx context.Context) string {
	return fmt.Sprint(ctx.Err())
}

func MutateAndRun() string {
	context.Canceled = envErr{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return FormatMutatedCanceled(ctx)
}
`,
		"mut_test.go": `package mutcanceled

import "testing"

func TestMutateTestingCtx(t *testing.T) {
	_ = MutateAndRun()
	_ = FormatMutatedTestingCtx(t.Context())
}
`,
	})
	hMut, recMut := newTracedInMemoryHasherAt(t, dirMut, nil)
	mutPkg := "example.com/mutcanceled"
	mutSubjs := []Subject{
		{Package: mutPkg, Symbol: "FormatMutatedCanceled"},
		{Package: mutPkg, Symbol: "FormatMutatedTestingCtx"},
	}
	obsMut, err := hMut.ComputeObservabilityBatch(mutSubjs)
	if err != nil {
		t.Fatal(err)
	}
	rootedMut, err := hMut.ComputeRootedFunctions(t.Context(), mutSubjs)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range mutSubjs {
		if obsMut[s].Observable {
			t.Errorf("%s: unexpectedly Observable=true under mutated context.Canceled (%+v)", s.Symbol, obsMut[s])
		}
		if rootedMut[s].Complete && !rootedMut[s].Fns[mutPkg+"\x00envErr.Error"] {
			t.Errorf("%s: Complete=true without envErr.Error under mutated context.Canceled: %+v", s.Symbol, rootedMut[s])
		}
	}
	foundMutatedGlobal := false
	for _, ev := range recMut.ByName("closure.callee.reject") {
		if ev.StringField("gate") == "sibling_closure_global_mutated" {
			foundMutatedGlobal = true
			break
		}
	}
	if !foundMutatedGlobal {
		t.Fatalf("expected closure.callee.reject with gate=sibling_closure_global_mutated; events=%+v", recMut.ByName("closure.callee.reject"))
	}
}

func TestIsMutableStdCarrierAllocTypeStructuralMatrix(t *testing.T) {
	t.Parallel()

	anyType := types.Universe.Lookup("any").Type()
	errType := types.Universe.Lookup("error").Type()
	pkg := types.NewPackage("example/stdsim", "stdsim")

	// 1. Boxed unexported struct + exported Store(v any) method -> mutable (method param clause alone).
	methodOnlyObj := types.NewTypeName(token.NoPos, pkg, "methodStore", nil)
	methodOnlyStruct := types.NewStruct([]*types.Var{types.NewField(token.NoPos, pkg, "hidden", anyType, false)}, nil)
	methodOnlyNamed := types.NewNamed(methodOnlyObj, methodOnlyStruct, nil)
	recv := types.NewVar(token.NoPos, pkg, "m", types.NewPointer(methodOnlyNamed))
	storeParams := types.NewTuple(types.NewVar(token.NoPos, pkg, "v", anyType))
	methodOnlyNamed.AddMethod(types.NewFunc(token.NoPos, pkg, "Store", types.NewSignatureType(recv, nil, nil, storeParams, nil, false)))
	if !isMutableStdCarrierAllocType(true, types.NewPointer(methodOnlyNamed), false) {
		t.Fatal("expected boxed unexported struct with exported Store(any) method to be classified mutable")
	}

	// 2. Boxed unexported struct + exported Unwrap() []error (like errors.joinError / fmt.wrapErrors) -> mutable.
	joinObj := types.NewTypeName(token.NoPos, pkg, "joinErrSim", nil)
	joinNamed := types.NewNamed(joinObj, types.NewStruct([]*types.Var{types.NewField(token.NoPos, pkg, "errs", types.NewSlice(errType), false)}, nil), nil)
	joinRecv := types.NewVar(token.NoPos, pkg, "e", types.NewPointer(joinNamed))
	unwrapSliceRes := types.NewTuple(types.NewVar(token.NoPos, pkg, "", types.NewSlice(errType)))
	joinNamed.AddMethod(types.NewFunc(token.NoPos, pkg, "Unwrap", types.NewSignatureType(joinRecv, nil, nil, nil, unwrapSliceRes, false)))
	if !isMutableStdCarrierAllocType(true, types.NewPointer(joinNamed), false) {
		t.Fatal("expected boxed unexported struct with exported Unwrap() []error to be classified mutable")
	}

	// 3. Boxed exported carrier struct with only unexported fields -> mutable (type-assertable *p = *p2 overwrite).
	expCarrierObj := types.NewTypeName(token.NoPos, pkg, "ExportedCarrier", nil)
	expCarrierNamed := types.NewNamed(expCarrierObj, types.NewStruct([]*types.Var{types.NewField(token.NoPos, pkg, "r", errType, false)}, nil), nil)
	if !isMutableStdCarrierAllocType(true, types.NewPointer(expCarrierNamed), false) {
		t.Fatal("expected boxed addressable exported carrier struct to be classified mutable")
	}

	// 4. Directly held (concrete=true) unexported carrier pointer -> mutable (*a = *New(...) overwrite).
	directHiddenObj := types.NewTypeName(token.NoPos, pkg, "directHiddenCarrier", nil)
	directHiddenNamed := types.NewNamed(directHiddenObj, types.NewStruct([]*types.Var{types.NewField(token.NoPos, pkg, "r", errType, false)}, nil), nil)
	if !isMutableStdCarrierAllocType(true, types.NewPointer(directHiddenNamed), true) {
		t.Fatal("expected concrete-returned unexported carrier pointer to be classified mutable")
	}
	if isMutableStdCarrierAllocType(true, types.NewPointer(directHiddenNamed), false) {
		t.Fatal("expected boxed unexported carrier pointer without mutating methods or exported alias to remain immutable")
	}

	// 5. Boxed unexported carrier pointer with an exported type alias in package scope -> mutable via i.(*pkg.ExportedAlias).
	aliasedHiddenObj := types.NewTypeName(token.NoPos, pkg, "aliasedHidden", nil)
	aliasedHiddenNamed := types.NewNamed(aliasedHiddenObj, types.NewStruct([]*types.Var{types.NewField(token.NoPos, pkg, "r", errType, false)}, nil), nil)
	aliasObj := types.NewTypeName(token.NoPos, pkg, "ExportedAlias", nil)
	_ = types.NewAlias(aliasObj, aliasedHiddenNamed)
	pkg.Scope().Insert(aliasObj)
	if !isMutableStdCarrierAllocType(true, types.NewPointer(aliasedHiddenNamed), false) {
		t.Fatal("expected boxed unexported carrier with exported package alias to be classified mutable")
	}

	// 6. Concrete value struct embedding unexported struct with exported []error field -> mutable via promoted field.
	innerSliceObj := types.NewTypeName(token.NoPos, pkg, "innerSliceHolder", nil)
	innerSliceNamed := types.NewNamed(innerSliceObj, types.NewStruct([]*types.Var{types.NewField(token.NoPos, pkg, "S", types.NewSlice(errType), false)}, nil), nil)
	outerValObj := types.NewTypeName(token.NoPos, pkg, "OuterVal", nil)
	outerValNamed := types.NewNamed(outerValObj, types.NewStruct([]*types.Var{types.NewField(token.NoPos, pkg, "innerSliceHolder", innerSliceNamed, true)}, nil), nil)
	if !isMutableStdCarrierAllocType(true, outerValNamed, false) {
		t.Fatal("expected exported value struct with promoted []error field to be classified mutable")
	}

	// 7. Boxed unexported struct encapsulating unexported mutable field + embedded interface + single-value Unwrap() error + WriteTo -> immutable.
	encapObj := types.NewTypeName(token.NoPos, pkg, "wrapErrSim", nil)
	encapNamed := types.NewNamed(encapObj, types.NewStruct([]*types.Var{
		types.NewField(token.NoPos, pkg, "error", errType, true),
		types.NewField(token.NoPos, pkg, "done", methodOnlyNamed, false),
	}, nil), nil)
	encapRecv := types.NewVar(token.NoPos, pkg, "w", types.NewPointer(encapNamed))
	unwrapOneRes := types.NewTuple(types.NewVar(token.NoPos, pkg, "", errType))
	encapNamed.AddMethod(types.NewFunc(token.NoPos, pkg, "Unwrap", types.NewSignatureType(encapRecv, nil, nil, nil, unwrapOneRes, false)))
	encapNamed.AddMethod(types.NewFunc(token.NoPos, pkg, "WriteTo", types.NewSignatureType(encapRecv, nil, nil, storeParams, nil, false)))
	if isMutableStdCarrierAllocType(true, types.NewPointer(encapNamed), false) {
		t.Fatal("expected boxed unexported struct with single-value Unwrap() error and WriteTo to remain immutable")
	}

	// 8. Signature types: CancelCauseFunc (func(error)) -> mutable when concrete; CancelFunc (func()) -> immutable.
	causeSig := types.NewSignatureType(nil, nil, nil, types.NewTuple(types.NewVar(token.NoPos, pkg, "cause", errType)), nil, false)
	cancelCauseObj := types.NewTypeName(token.NoPos, pkg, "CancelCauseFuncSim", nil)
	cancelCauseNamed := types.NewNamed(cancelCauseObj, causeSig, nil)
	if !isMutableStdCarrierAllocType(true, cancelCauseNamed, true) {
		t.Fatal("expected func(error) signature to be classified mutable")
	}
	plainCancelSig := types.NewSignatureType(nil, nil, nil, nil, nil, false)
	plainCancelObj := types.NewTypeName(token.NoPos, pkg, "CancelFuncSim", nil)
	plainCancelNamed := types.NewNamed(plainCancelObj, plainCancelSig, nil)
	if isMutableStdCarrierAllocType(true, plainCancelNamed, true) {
		t.Fatal("expected func() signature to remain immutable")
	}

	// 9. Unnamed / aliased interface with Set(error) -> mutable; context.Context Value(any) any -> immutable.
	setMethod := types.NewFunc(token.NoPos, pkg, "Set", types.NewSignatureType(nil, nil, nil, types.NewTuple(types.NewVar(token.NoPos, pkg, "e", errType)), nil, false))
	setterIface := types.NewInterfaceType([]*types.Func{setMethod}, nil).Complete()
	setterAliasObj := types.NewTypeName(token.NoPos, pkg, "AliasSetter", nil)
	setterAlias := types.NewAlias(setterAliasObj, setterIface)
	if !isMutableStdCarrierAllocType(true, setterAlias, true) {
		t.Fatal("expected aliased unnamed interface { Set(error) } to be classified mutable")
	}
	ctxPkg := types.NewPackage("context", "context")
	ctxValMethod := types.NewFunc(token.NoPos, ctxPkg, "Value", types.NewSignatureType(nil, nil, nil, storeParams, storeParams, false))
	ctxIface := types.NewInterfaceType([]*types.Func{ctxValMethod}, nil).Complete()
	if isMutableStdCarrierAllocType(true, ctxIface, true) {
		t.Fatal("expected context.Context Value(any) any underlying interface to remain immutable")
	}
}

func TestRapidIsMutableStdCarrierAllocTypeProperties(t *testing.T) {
	t.Parallel()

	anyType := types.Universe.Lookup("any").Type()
	errType := types.Universe.Lookup("error").Type()
	intType := types.Typ[types.Int]
	strType := types.Typ[types.String]

	rapid.Check(t, func(rt *rapid.T) {
		pkg := types.NewPackage("example/rsim", "rsim")
		exportedStruct := rapid.Bool().Draw(rt, "exportedStruct")
		addAlias := rapid.Bool().Draw(rt, "addAlias")
		ptrAlloc := rapid.Bool().Draw(rt, "ptrAlloc")
		fieldKind := rapid.IntRange(0, 4).Draw(rt, "fieldKind")
		fieldExported := rapid.Bool().Draw(rt, "fieldExported")
		embedMid := rapid.Bool().Draw(rt, "embedMid")
		methodKind := rapid.IntRange(0, 7).Draw(rt, "methodKind")

		var fType types.Type
		switch fieldKind {
		case 0:
			fType = intType
		case 1:
			fType = errType
		case 2:
			fType = types.NewSlice(errType)
		case 3:
			fType = types.NewChan(types.RecvOnly, intType)
		case 4:
			fType = types.NewMap(strType, anyType)
		}
		fName := "f"
		if fieldExported {
			fName = "F"
		}
		leafField := types.NewField(token.NoPos, pkg, fName, fType, false)
		var fields []*types.Var
		if embedMid {
			midObj := types.NewTypeName(token.NoPos, pkg, "mid", nil)
			midNamed := types.NewNamed(midObj, types.NewStruct([]*types.Var{leafField}, nil), nil)
			fields = []*types.Var{types.NewField(token.NoPos, pkg, "mid", midNamed, true)}
		} else {
			fields = []*types.Var{leafField}
		}

		tName := "carrier"
		if exportedStruct {
			tName = "Carrier"
		}
		obj := types.NewTypeName(token.NoPos, pkg, tName, nil)
		named := types.NewNamed(obj, types.NewStruct(fields, nil), nil)
		recv := types.NewVar(token.NoPos, pkg, "r", types.NewPointer(named))
		switch methodKind {
		case 1:
			p := types.NewTuple(types.NewVar(token.NoPos, pkg, "x", anyType))
			named.AddMethod(types.NewFunc(token.NoPos, pkg, "Mutate", types.NewSignatureType(recv, nil, nil, p, nil, false)))
		case 2:
			p := types.NewTuple(types.NewVar(token.NoPos, pkg, "w", anyType))
			named.AddMethod(types.NewFunc(token.NoPos, pkg, "WriteTo", types.NewSignatureType(recv, nil, nil, p, nil, false)))
		case 3:
			r := types.NewTuple(types.NewVar(token.NoPos, pkg, "", errType))
			named.AddMethod(types.NewFunc(token.NoPos, pkg, "Unwrap", types.NewSignatureType(recv, nil, nil, nil, r, false)))
		case 4:
			r := types.NewTuple(types.NewVar(token.NoPos, pkg, "", types.NewSlice(errType)))
			named.AddMethod(types.NewFunc(token.NoPos, pkg, "Unwrap", types.NewSignatureType(recv, nil, nil, nil, r, false)))
		case 5:
			r := types.NewTuple(types.NewVar(token.NoPos, pkg, "", types.NewChan(types.SendRecv, errType)))
			named.AddMethod(types.NewFunc(token.NoPos, pkg, "Ch", types.NewSignatureType(recv, nil, nil, nil, r, false)))
		case 6:
			sigRes := types.NewSignatureType(nil, nil, nil, types.NewTuple(types.NewVar(token.NoPos, pkg, "c", errType)), nil, false)
			r := types.NewTuple(types.NewVar(token.NoPos, pkg, "", sigRes))
			named.AddMethod(types.NewFunc(token.NoPos, pkg, "CancelFn", types.NewSignatureType(recv, nil, nil, nil, r, false)))
		case 7:
			setM := types.NewFunc(token.NoPos, pkg, "Set", types.NewSignatureType(nil, nil, nil, types.NewTuple(types.NewVar(token.NoPos, pkg, "e", errType)), nil, false))
			ifaceRes := types.NewInterfaceType([]*types.Func{setM}, nil).Complete()
			r := types.NewTuple(types.NewVar(token.NoPos, pkg, "", ifaceRes))
			named.AddMethod(types.NewFunc(token.NoPos, pkg, "Setter", types.NewSignatureType(recv, nil, nil, nil, r, false)))
		}

		var subject types.Type = named
		if ptrAlloc {
			subject = types.NewPointer(named)
		}

		boxedBeforeAlias := isMutableStdCarrierAllocType(true, subject, false)
		concreteBeforeAlias := isMutableStdCarrierAllocType(true, subject, true)

		// Monotonicity: concrete access strictly dominates stdlib-boxed access.
		if boxedBeforeAlias && !concreteBeforeAlias {
			rt.Fatalf("monotonicity violated: boxed=true but concrete=false for %v", subject)
		}

		// Reference oracle for boxed vs concrete on our generated type.
		carriesDyn := fieldKind == 1 || fieldKind == 2 || fieldKind == 4
		fieldIsRefSharing := fieldKind == 2 || fieldKind == 4
		methodMutates := ptrAlloc && (methodKind == 1 || methodKind == 4 || methodKind == 5 || methodKind == 6 || methodKind == 7)
		wantConcrete := methodMutates || (ptrAlloc && carriesDyn) || (fieldExported && ((ptrAlloc && carriesDyn) || fieldIsRefSharing))
		wantBoxed := methodMutates || (exportedStruct && wantConcrete)
		if concreteBeforeAlias != wantConcrete {
			rt.Fatalf("concrete mismatch: got %v, want %v (ptr=%v exp=%v fk=%d fe=%v emb=%v mk=%d)",
				concreteBeforeAlias, wantConcrete, ptrAlloc, exportedStruct, fieldKind, fieldExported, embedMid, methodKind)
		}
		if boxedBeforeAlias != wantBoxed {
			rt.Fatalf("boxed mismatch: got %v, want %v (ptr=%v exp=%v fk=%d fe=%v emb=%v mk=%d)",
				boxedBeforeAlias, wantBoxed, ptrAlloc, exportedStruct, fieldKind, fieldExported, embedMid, methodKind)
		}

		if addAlias && !exportedStruct {
			aliasObj := types.NewTypeName(token.NoPos, pkg, "ExportedAlias", nil)
			_ = types.NewAlias(aliasObj, named)
			pkg.Scope().Insert(aliasObj)
			boxedAfterAlias := isMutableStdCarrierAllocType(true, subject, false)
			if boxedAfterAlias != wantConcrete {
				rt.Fatalf("exported alias equivalence violated: got %v, want %v", boxedAfterAlias, wantConcrete)
			}
		}
	})
}
