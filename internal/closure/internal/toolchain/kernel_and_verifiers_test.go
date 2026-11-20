package toolchain

import (
	"archive/zip"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/auditset"
	"pgregory.net/rapid"
)

func buildValidSyntheticMathGoSrc(extraBody string) string {
	var b strings.Builder
	b.WriteString("package math\n\nimport (\n\t\"internal/cpu\"\n\t\"math/bits\"\n\t\"unsafe\"\n)\n\nconst (\n")
	for i, c := range auditset.MathConstants() {
		fmt.Fprintf(&b, "\t%s = %d\n", c, i+1)
	}
	b.WriteString("\thaveArchPure = true\n\thaveArchDead = false\n)\n\n")
	b.WriteString("var pow10tab = [...]float64{1.0, 10.0, 100.0}\n")
	b.WriteString("var p0R8 = [2]float64{1.0, 2.0}\n")
	b.WriteString("var useFMA = cpu.X86.HasAVX && cpu.X86.HasFMA\n")
	b.WriteString("var hasVX = cpu.S390X.HasVX\n\n")
	b.WriteString("//go:linkname Float32bits\n")
	b.WriteString("func Float32bits(f float32) uint32 { return *(*uint32)(unsafe.Pointer(&f)) }\n")
	b.WriteString("func Float32frombits(b uint32) float32 { return *(*float32)(unsafe.Pointer(&b)) }\n")
	b.WriteString("func Float64bits(f float64) uint64 { return *(*uint64)(unsafe.Pointer(&f)) }\n")
	b.WriteString("func Float64frombits(b uint64) float64 { return *(*float64)(unsafe.Pointer(&b)) }\n")
	for _, fn := range auditset.MathPureFuncs() {
		switch fn {
		case "Float32bits", "Float32frombits", "Float64bits", "Float64frombits":
			continue
		}
		fmt.Fprintf(&b, "func %s(x float64) float64 { return x + pow10tab[0] + float64(bits.LeadingZeros64(1)) }\n", fn)
	}
	b.WriteString(`
func archSin(x float64) float64
func archExp(x float64) float64
func archCos(x float64) float64
func deadStub(x float64) float64 { panic("not implemented") }

func Sin(x float64) float64 {
	if haveArchDead {
		return deadStub(x)
	}
	if haveArchPure {
		return archSin(x)
	}
	return x
}

func J0(x float64) float64 {
	var p *[2]float64
	p = &p0R8
	return p[0] + Sin(x)
}

func Exp(x float64) float64 {
	return archExp(x)
}

func Cosh(x float64) float64 {
	return Exp(x)
}

func Cos(x float64) float64 {
	return archCos(x)
}

func FMA(x, y, z float64) float64 {
	return x*y + z
}
`)
	b.WriteString(extraBody)
	return b.String()
}

const validSyntheticMathAsm = `#include "textflag.h"

#define PURE_KERNEL(NAME) \
TEXT NAME(SB),NOSPLIT,$0; \
	MOVQ sinrodata<>+0(SB), AX; \
	FRNDINT; \
	F64Floor; \
	MOVQ AX, ret+8(FP); \
	RET

GLOBL sinrodata<>+0(SB), RODATA, $8
DATA sinrodata<>+0(SB)/8, $1.0

PURE_KERNEL(·archSin)

TEXT ·archExp(SB),NOSPLIT,$0
	CMPB ·useFMA(SB), $1
	RET

TEXT ·archCos(SB),NOSPLIT,$0
	MOVQ ·cosvectorfacility+0x00(SB), AX
	RET

TEXT ·cosTrampoline(SB),NOSPLIT,$0
	MOVB ·hasVX(SB), AX
	MOVQ $·cosvectorfacility+0x00(SB), BX
	MOVQ $·archCos(SB), CX
	MOVQ CX, 0(BX)
	RET

GLOBL ·cosvectorfacility+0x00(SB), NOPTR, $8
DATA ·cosvectorfacility+0x00(SB)/8, $·cosTrampoline(SB)
`

const validRuntimeDebugModSrc = `package debug

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

func modinfo() string

func ReadBuildInfo() (info *BuildInfo, ok bool) {
	data := modinfo()
	if len(data) < 32 {
		return nil, false
	}
	data = data[16 : len(data)-16]
	bi, err := ParseBuildInfo(data)
	if err != nil {
		return nil, false
	}
	bi.GoVersion = runtime.Version()
	return bi, true
}

type BuildInfo struct {
	GoVersion string
	Path      string
	Main      Module
	Deps      []*Module
	Settings  []BuildSetting
}

type Module struct {
	Path    string
	Version string
	Sum     string
	Replace *Module
}

type BuildSetting struct {
	Key   string
	Value string
}

func quoteKey(key string) bool {
	return len(key) == 0 || strings.ContainsAny(key, "= \t\r\n\"` + "`" + `")
}

func quoteValue(value string) bool {
	return strings.ContainsAny(value, " \t\r\n\"` + "`" + `")
}

func (bi *BuildInfo) String() string {
	buf := new(strings.Builder)
	if bi.GoVersion != "" {
		fmt.Fprintf(buf, "go\t%s\n", bi.GoVersion)
	}
	if bi.Main != (Module{}) {
		_ = Module{Path: bi.Main.Path}
	}
	for _, s := range bi.Settings {
		k := s.Key
		if quoteKey(k) {
			k = strconv.Quote(k)
		}
		v := s.Value
		if quoteValue(v) {
			v = strconv.Quote(v)
		}
		fmt.Fprintf(buf, "build\t%s=%s\n", k, v)
	}
	return buf.String()
}

func ParseBuildInfo(data string) (bi *BuildInfo, err error) {
	bi = new(BuildInfo)
	for len(data) > 0 {
		var line string
		var ok bool
		line, data, ok = strings.Cut(data, "\n")
		if !ok {
			break
		}
		if strings.HasPrefix(line, "path\t") {
			bi.Path = line[5:]
		} else if strings.HasPrefix(line, "mod\t") {
			parts := strings.Split(line[4:], "\t")
			if len(parts) >= 2 {
				bi.Main = Module{Path: parts[0], Version: parts[1]}
			}
		} else if strings.HasPrefix(line, "build\t") {
			k, v, ok := strings.Cut(line[6:], "=")
			if !ok {
				return nil, fmt.Errorf("missing =")
			}
			if len(k) > 0 && k[0] == '"' {
				raw, qErr := strconv.QuotedPrefix(k)
				if qErr != nil {
					return nil, qErr
				}
				k, _ = strconv.Unquote(raw)
			}
			bi.Settings = append(bi.Settings, BuildSetting{Key: k, Value: v})
		}
	}
	return bi, nil
}
`

const validRuntimeModinfoSrc = `package runtime

import _ "unsafe"

var modinfo string

//go:linkname debug_modinfo runtime/debug.modinfo
func debug_modinfo() string {
	return modinfo
}

func clearSentinel() {
	if len(modinfo) == 1 {
		modinfo = ""
	}
}
`

func TestVerifyMathPackageMatrix(t *testing.T) {
	ctx := context.Background()
	baseGo := buildValidSyntheticMathGoSrc("")
	baseFiles := mustParseTestFiles(t, baseGo)

	pureFuncs, err := VerifyMathPackage(ctx, baseFiles, []string{baseGo}, map[string]string{"kernels.s": validSyntheticMathAsm}, nil)
	if err != nil {
		t.Fatalf("VerifyMathPackage(valid): %v", err)
	}
	for _, tier1 := range auditset.MathPureFuncs() {
		if !slices.Contains(pureFuncs, tier1) {
			t.Fatalf("missing Tier-1 function %s in pureFuncs=%v", tier1, pureFuncs)
		}
	}
	for _, wantAdmitted := range []string{"Sin", "J0"} {
		if !slices.Contains(pureFuncs, wantAdmitted) {
			t.Fatalf("expected CPU-free %s in pureFuncs=%v", wantAdmitted, pureFuncs)
		}
	}
	for _, wantRefused := range []string{"Exp", "Cosh", "Cos", "FMA"} {
		if slices.Contains(pureFuncs, wantRefused) {
			t.Fatalf("expected tainted/intrinsic %s to be excluded from pureFuncs=%v", wantRefused, pureFuncs)
		}
	}

	rejectCases := []struct {
		name   string
		goSrc  string
		asmSrc string
	}{
		{
			name:   "missing_tier1_const",
			goSrc:  strings.Replace(baseGo, "\tPi = ", "\t_missingPi = ", 1),
			asmSrc: validSyntheticMathAsm,
		},
		{
			name:   "missing_tier1_func",
			goSrc:  strings.Replace(baseGo, "func Abs(", "func hiddenAbs(", 1),
			asmSrc: validSyntheticMathAsm,
		},
		{
			name:   "tier1_func_reaches_cpu_var",
			goSrc:  strings.Replace(baseGo, "func Sqrt(x float64) float64 {", "func Sqrt(x float64) float64 {\n\tif useFMA { return x }\n", 1),
			asmSrc: validSyntheticMathAsm,
		},
		{
			name:   "two_arg_linkname",
			goSrc:  baseGo + "\n//go:linkname sneaky runtime.nanotime\nfunc sneaky() int64\n",
			asmSrc: validSyntheticMathAsm,
		},
		{
			name:   "single_arg_linkname_on_var",
			goSrc:  "//go:linkname pow10tab\n" + baseGo,
			asmSrc: validSyntheticMathAsm,
		},
		{
			name:   "init_func_forbidden",
			goSrc:  baseGo + "\nfunc init() {}\n",
			asmSrc: validSyntheticMathAsm,
		},
		{
			name:   "exported_var_forbidden",
			goSrc:  baseGo + "\nvar ExportedTable = [1]float64{1.0}\n",
			asmSrc: validSyntheticMathAsm,
		},
		{
			name:   "mutate_table_via_local_ptr",
			goSrc:  strings.Replace(baseGo, "return p[0] + Sin(x)", "p[0] = 9.0\n\treturn p[0] + Sin(x)", 1),
			asmSrc: validSyntheticMathAsm,
		},
		{
			name:   "escape_table_addr",
			goSrc:  baseGo + "\nfunc badPtr(x float64) float64 { _ = &pow10tab; return x }\n",
			asmSrc: validSyntheticMathAsm,
		},
		{
			name:   "unsafe_on_mutated_param",
			goSrc:  strings.Replace(baseGo, "func Float64bits(f float64) uint64 { return *(*uint64)(unsafe.Pointer(&f)) }", "func Float64bits(f float64) uint64 { f = 0; return *(*uint64)(unsafe.Pointer(&f)) }", 1),
			asmSrc: validSyntheticMathAsm,
		},
		{
			name:   "unsafe_width_mismatch",
			goSrc:  strings.Replace(baseGo, "func Float32bits(f float32) uint32 { return *(*uint32)(unsafe.Pointer(&f)) }", "func Float32bits(f float32) uint32 { return uint32(*(*uint64)(unsafe.Pointer(&f))) }", 1),
			asmSrc: validSyntheticMathAsm,
		},
		{
			name:   "asm_syscall_forbidden",
			goSrc:  baseGo,
			asmSrc: validSyntheticMathAsm + "\nTEXT ·badSys(SB),NOSPLIT,$0\n\tSYSCALL\n\tRET\n",
		},
		{
			name:   "asm_rdtsc_forbidden",
			goSrc:  baseGo,
			asmSrc: validSyntheticMathAsm + "\nTEXT ·badClock(SB),NOSPLIT,$0\n\tRDTSC\n\tRET\n",
		},
		{
			name:   "asm_direct_sb_store_forbidden",
			goSrc:  baseGo,
			asmSrc: strings.Replace(validSyntheticMathAsm, "MOVQ sinrodata<>+0(SB), AX;", "MOVQ AX, ·pow10tab+0(SB);", 1),
		},
		{
			name:   "asm_indirect_store_after_rodata_addr",
			goSrc:  baseGo,
			asmSrc: validSyntheticMathAsm + "\nTEXT ·badClobber(SB),NOSPLIT,$0\n\tMOVQ $sinrodata<>+0(SB), BX\n\tMOVQ AX, 0(BX)\n\tRET\n",
		},
	}

	for _, tc := range rejectCases {
		t.Run(tc.name, func(t *testing.T) {
			files := mustParseTestFiles(t, tc.goSrc)
			if _, err := VerifyMathPackage(ctx, files, []string{tc.goSrc}, map[string]string{"kernels.s": tc.asmSrc}, nil); err == nil {
				t.Fatalf("expected VerifyMathPackage to reject %s", tc.name)
			}
		})
	}
}

func TestVerifyRuntimeDebugAndModinfoMatrix(t *testing.T) {
	ctx := context.Background()
	dbgFiles := mustParseTestFiles(t, validRuntimeDebugModSrc)
	const emptyDebugS = "// marker assembly file\n"
	if err := VerifyRuntimeDebugPackage(ctx, dbgFiles, []string{validRuntimeDebugModSrc}, map[string]string{"debug.s": emptyDebugS}, nil); err != nil {
		t.Fatalf("VerifyRuntimeDebugPackage(valid): %v", err)
	}
	rtFiles := mustParseTestFiles(t, validRuntimeModinfoSrc)
	if err := VerifyRuntimeModinfoAST(rtFiles, []string{validRuntimeModinfoSrc}, nil); err != nil {
		t.Fatalf("VerifyRuntimeModinfoAST(valid): %v", err)
	}

	dbgRejects := []struct {
		name string
		src  string
		asm  string
	}{
		{"nonempty_debug_s", validRuntimeDebugModSrc, "TEXT ·modinfo(SB),$0\n\tRET\n"},
		{"linkname_on_readbuildinfo", "//go:linkname ReadBuildInfo runtime.bad\n" + validRuntimeDebugModSrc, emptyDebugS},
		{"pkg_var_forbidden", validRuntimeDebugModSrc + "\nvar cached *BuildInfo\n", emptyDebugS},
		{"extra_struct_field", strings.Replace(validRuntimeDebugModSrc, "Path      string", "Path string\n\tExtra int", 1), emptyDebugS},
		{"missing_sentinel_len_guard", strings.Replace(validRuntimeDebugModSrc, "if len(data) < 32 {\n\t\treturn nil, false\n\t}\n\t", "", 1), emptyDebugS},
		{"wrong_sentinel_slice", strings.Replace(validRuntimeDebugModSrc, "data[16 : len(data)-16]", "data[8 : len(data)-8]", 1), emptyDebugS},
		{"missing_runtime_version", strings.Replace(validRuntimeDebugModSrc, "bi.GoVersion = runtime.Version()", `bi.GoVersion = "fake"`, 1), emptyDebugS},
		{"pointer_verb_in_fprintf", strings.Replace(validRuntimeDebugModSrc, `"go\t%s\n"`, `"go\t%p\n"`, 1), emptyDebugS},
		{"extra_method_on_buildinfo", validRuntimeDebugModSrc + "\nfunc (bi *BuildInfo) Write(p []byte) (int, error) { return len(p), nil }\n", emptyDebugS},
		{"shadowed_receiver_as_builder", strings.Replace(validRuntimeDebugModSrc, "func (bi *BuildInfo) String() string {\n\tbuf := new(strings.Builder)", "func (buf *BuildInfo) String() string {\n\t{ buf := new(strings.Builder); _ = buf }\n\tbi := buf", 1), emptyDebugS},
	}
	for _, tc := range dbgRejects {
		t.Run(tc.name, func(t *testing.T) {
			files := mustParseTestFiles(t, tc.src)
			if err := VerifyRuntimeDebugPackage(ctx, files, []string{tc.src}, map[string]string{"debug.s": tc.asm}, nil); err == nil {
				t.Fatalf("expected VerifyRuntimeDebugPackage to reject %s", tc.name)
			}
		})
	}

	for _, modCase := range []struct {
		name  string
		src   string
		nonGo map[string]bool
	}{
		{"missing_linkname", strings.Replace(validRuntimeModinfoSrc, "//go:linkname debug_modinfo runtime/debug.modinfo\n", "", 1), nil},
		{"non_empty_assign", strings.Replace(validRuntimeModinfoSrc, `modinfo = ""`, `modinfo = "mutated"`, 1), nil},
		{"unguarded_empty_assign", validRuntimeModinfoSrc + "\nfunc clobber(cond bool) { if cond { modinfo = \"\" } }\n", nil},
		{"async_goroutine_empty_assign", validRuntimeModinfoSrc + "\nfunc asyncClobber() { go func() { if len(modinfo) == 1 { modinfo = \"\" } }() }\n", nil},
		{"nongo_modinfo_ref", validRuntimeModinfoSrc, map[string]bool{"modinfo": true}},
		{"addr_taken", validRuntimeModinfoSrc + "\nfunc leak() *string { return &modinfo }\n", nil},
	} {
		t.Run("modinfo_"+modCase.name, func(t *testing.T) {
			files := mustParseTestFiles(t, modCase.src)
			if err := VerifyRuntimeModinfoAST(files, []string{modCase.src}, modCase.nonGo); err == nil {
				t.Fatalf("expected VerifyRuntimeModinfoAST to reject %s", modCase.name)
			}
		})
	}
}

func TestRuntimeBubbleGatesLineWritersAndOutOfLineTestdeps(t *testing.T) {
	rtSrc := `package runtime

import (
	"internal/runtime/atomic"
	_ "unsafe"
)

type synctestBubble struct{ id int }

var (
	simFlag   atomic.Bool
	simBubble *synctestBubble
)

func simEnable() {
	simFlag.Store(true)
	simBubble = &synctestBubble{id: 1}
}

func simActive() bool {
	return simFlag.Load()
}

func getg() *g
type g struct{ bubble *synctestBubble }

//go:linkname inBubble runtime.inBubble
func inBubble() bool {
	gp := getg()
	return gp.bubble != nil && gp.bubble == simBubble
}

func write1(fd uintptr, p unsafe.Pointer, n int32) int32
func add(p unsafe.Pointer, x uintptr) unsafe.Pointer
func noescape(p unsafe.Pointer) unsafe.Pointer

const (
	_EINTR  = 4
	_EAGAIN = 11
	_ENOMEM = 12
)

//go:linkname writeLogLine
func writeLogLine(fd int, op, name string) int32 {
	total := len(op) + 1 + len(name) + 1
	if total <= 512 {
		var stackBuf [512]byte
		n := copy(stackBuf[:], op)
		stackBuf[n] = ' '
		n++
		n += copy(stackBuf[n:], name)
		stackBuf[n] = '\n'
		n++
		return writeLogAll(uintptr(fd), noescape(unsafe.Pointer(&stackBuf[0])), n)
	}
	alloc := alignUp(uintptr(total), 4096)
	if alloc == 0 || alloc < uintptr(total) {
		return _ENOMEM
	}
	p := sysAllocOS(alloc, "testlog line")
	if p == nil {
		return _ENOMEM
	}
	buf := unsafe.Slice((*byte)(p), total)
	n := copy(buf, op)
	buf[n] = ' '
	n++
	n += copy(buf[n:], name)
	buf[n] = '\n'
	errno := writeLogAll(uintptr(fd), p, total)
	sysFreeOS(p, alloc)
	return errno
}

func writeLogAll(fd uintptr, p unsafe.Pointer, rem int) int32 {
	const errEIO = 5
	for rem > 0 {
		chunk := rem
		if chunk > 0x7fffffff {
			chunk = 0x7fffffff
		}
		r := write1(fd, p, int32(chunk))
		if r > 0 {
			p = add(p, uintptr(r))
			rem -= int(r)
			continue
		}
		errno := -r
		if errno == _EINTR || errno == _EAGAIN {
			continue
		}
		if errno <= 0 {
			return errEIO
		}
		return errno
	}
	return 0
}
`
	rtSrcValid := strings.Replace(rtSrc, `_ "unsafe"`, `"unsafe"`, 1)
	rtFiles := mustParseTestFiles(t, rtSrcValid)
	gates := DiscoverRuntimeInactiveGates(rtFiles, []string{rtSrcValid}, nil)
	if _, ok := gates["runtime.inBubble"]; !ok {
		t.Fatalf("expected runtime.inBubble in inactive gates, got %v", gates)
	}
	writers := DiscoverVerifiedRuntimeLineWriters(rtFiles, []string{rtSrcValid})
	if !slices.Contains(writers, "runtime.writeLogLine") {
		t.Fatalf("expected runtime.writeLogLine in verified line writers, got %v", writers)
	}

	// Mutating writeLogLine to omit trailing '\n' or writeLogAll to ignore negative write errors must disqualify it.
	noNewline := strings.Replace(rtSrcValid, "stackBuf[n] = '\\n'", "stackBuf[n] = 'x'", 1)
	if got := DiscoverVerifiedRuntimeLineWriters(mustParseTestFiles(t, noNewline), []string{noNewline}); len(got) != 0 {
		t.Fatalf("expected writer missing newline to be disqualified, got %v", got)
	}
	swallowErr := strings.Replace(rtSrcValid, "return errno", "return 0", 1)
	if got := DiscoverVerifiedRuntimeLineWriters(mustParseTestFiles(t, swallowErr), []string{swallowErr}); len(got) != 0 {
		t.Fatalf("expected writer swallowing write error to be disqualified, got %v", got)
	}

	// A sibling runtime file with `import _ "unsafe"` (such as badlinkname.go) must not block
	// DiscoverVerifiedRuntimeLineWriters, whereas an aliased `import u "unsafe"` in the writer file must fail.
	siblingBlankUnsafe := "package runtime\nimport _ \"unsafe\"\n"
	if got := DiscoverVerifiedRuntimeLineWriters(mustParseTestFiles(t, siblingBlankUnsafe, rtSrcValid), []string{siblingBlankUnsafe, rtSrcValid}); !slices.Contains(got, "runtime.writeLogLine") {
		t.Fatalf("expected runtime.writeLogLine admitted alongside sibling blank unsafe import, got %v", got)
	}
	aliasedWriter := strings.Replace(rtSrcValid, "\t\"unsafe\"", "\tu \"unsafe\"", 1)
	aliasedWriter = strings.ReplaceAll(aliasedWriter, "unsafe.", "u.")
	if got := DiscoverVerifiedRuntimeLineWriters(mustParseTestFiles(t, siblingBlankUnsafe, aliasedWriter), []string{siblingBlankUnsafe, aliasedWriter}); len(got) != 0 {
		t.Fatalf("expected aliased unsafe in writer file to fail verification, got %v", got)
	}

	// Shadowing outer `total` inside fastIf.Body without final `total++` must be rejected (prevents dropping '\n').
	shadowTotalWriter := strings.Replace(rtSrcValid,
		"n := copy(stackBuf[:], op)\n\t\tstackBuf[n] = ' '\n\t\tn++\n\t\tn += copy(stackBuf[n:], name)\n\t\tstackBuf[n] = '\\n'\n\t\tn++\n\t\treturn writeLogAll(uintptr(fd), noescape(unsafe.Pointer(&stackBuf[0])), n)",
		"total := copy(stackBuf[:], op)\n\t\tstackBuf[total] = ' '\n\t\ttotal++\n\t\ttotal += copy(stackBuf[total:], name)\n\t\tstackBuf[total] = '\\n'\n\t\treturn writeLogAll(uintptr(fd), noescape(unsafe.Pointer(&stackBuf[0])), total)",
		1,
	)
	if got := DiscoverVerifiedRuntimeLineWriters(mustParseTestFiles(t, shadowTotalWriter), []string{shadowTotalWriter}); len(got) != 0 {
		t.Fatalf("expected writer shadowing total in fast path to be disqualified, got %v", got)
	}

	// Mutating zero-init pointer global `simBubble` alongside an inner shadowed local or GenDecl alias must disqualify `runtime.inBubble`.
	for _, ptrBypass := range []string{
		rtSrcValid + "\nfunc init() { simBubble = &synctestBubble{id: 1}; { var simBubble *synctestBubble; _ = simBubble } }\n",
		rtSrcValid + "\nfunc sneakySet() { simBubble = &synctestBubble{id: 1}; { var simBubble *synctestBubble; _ = simBubble } }\n",
		rtSrcValid + "\nvar bubbleAlias = &simBubble\n",
	} {
		if g := DiscoverRuntimeInactiveGates(mustParseTestFiles(t, ptrBypass), []string{ptrBypass}, nil); g["runtime.inBubble"] != nil {
			t.Fatalf("expected mutated/aliased simBubble to disqualify runtime.inBubble, got %v", g)
		}
	}
}

func TestKernelPruneDeadTailScopingAndLinknameContracts(t *testing.T) {
	// 1. Folded proven-true and proven-false-else early-return branches trim unreachable tails and record pruned nodes.
	pruneFixture := `package p

const flagTrue = true

//go:linkname inactiveGate runtime.inactiveGate
func inactiveGate() bool

var fnGate = inactiveGate

func TrueReturnTrimsTail(x int) int {
	if !fnGate() {
		return x + 1
	}
	return sideEffectBubble(x)
}

func FalseElseReturnTrimsTail(x int) int {
	if fnGate() {
		return sideEffectBubble(x)
	} else {
		return x + 2
	}
	return sideEffectBubble(x)
}

func UnguardedDeadTail(x int) int {
	return x
	return x + 1
}

func LabeledTailNotTrimmed(x int) int {
	if flagTrue {
		return x
	}
target:
	return x + 1
}

func LabeledElseNotFolded(x int) int {
	if flagTrue {
		x = x + 1
	} else {
	target:
		x = x + 2
	}
	return x
}

func BlockScopedShortDeclPreserved(x int) int {
	if flagTrue {
		x := 99
		_ = x
	}
	return x
}

func MethodExitIsNotAbort(cond bool, h interface{ Exit() }) error {
	if cond {
		h.Exit()
	}
	return nil
}

func OSExitVsMethodExit(h interface{ Exit() }) {
	h.Exit()
	os.Exit(1)
}
`
	files := mustParseTestFiles(t, pruneFixture)
	idx, errIdx := indexPackageAST("p", files, nil, nil)
	if errIdx != nil {
		t.Fatalf("indexPackageAST failed on pruneFixture: %v", errIdx)
	}
	k := NewPackageInactiveKernel(idx, files, map[string]string{"inactiveGate": "runtime.inactiveGate"}, map[string]bool{"inactiveGate": true})

	for _, fnName := range []string{"TrueReturnTrimsTail", "FalseElseReturnTrimsTail"} {
		fn := idx.topFuncs[fnName]
		reqGates := map[string]bool{}
		var pruned []ast.Node
		stmts, mod := k.PruneBlockStmts(fn.Body.List, fn, map[string]bool{"x": true}, reqGates, &pruned)
		if !mod || len(stmts) != 1 || !reqGates["runtime.inactiveGate"] || len(pruned) == 0 {
			t.Fatalf("%s: mod=%v len(stmts)=%d gates=%v len(pruned)=%d", fnName, mod, len(stmts), reqGates, len(pruned))
		}
		if _, okCFG := BuildStmtCFG(stmts); !okCFG {
			t.Fatalf("%s: BuildStmtCFG rejected pruned statements", fnName)
		}
	}

	// Unguarded dead statements in original source must still fail BuildStmtCFG.
	unguardedFn := idx.topFuncs["UnguardedDeadTail"]
	unguardedStmts, unguardedMod := k.PruneBlockStmts(unguardedFn.Body.List, unguardedFn, nil, nil, nil)
	if unguardedMod || len(unguardedStmts) != 2 {
		t.Fatalf("UnguardedDeadTail should not be modified by PruneBlockStmts: mod=%v len=%d", unguardedMod, len(unguardedStmts))
	}
	if _, okCFG := BuildStmtCFG(unguardedStmts); okCFG {
		t.Fatal("UnguardedDeadTail: expected BuildStmtCFG to reject unguarded unreachable statement")
	}

	// Labeled statements in tail or in else must prevent pruning jump targets.
	lblTailFn := idx.topFuncs["LabeledTailNotTrimmed"]
	lblTailStmts, _ := k.PruneBlockStmts(lblTailFn.Body.List, lblTailFn, nil, nil, nil)
	if len(lblTailStmts) != 2 {
		t.Fatalf("LabeledTailNotTrimmed: expected labeled tail preserved (len 2), got %d", len(lblTailStmts))
	}
	lblElseFn := idx.topFuncs["LabeledElseNotFolded"]
	lblElseStmts, lblElseMod := k.PruneBlockStmts(lblElseFn.Body.List, lblElseFn, nil, nil, nil)
	if lblElseMod || len(lblElseStmts) != 2 {
		t.Fatalf("LabeledElseNotFolded: expected else with label not folded, mod=%v len=%d", lblElseMod, len(lblElseStmts))
	}

	// Folded true branch containing `x := 99` followed by `return x` keeps a *ast.BlockStmt so inner `x` stays scoped.
	scopedFn := idx.topFuncs["BlockScopedShortDeclPreserved"]
	scopedStmts, scopedMod := k.PruneBlockStmts(scopedFn.Body.List, scopedFn, nil, nil, nil)
	if !scopedMod || len(scopedStmts) != 2 {
		t.Fatalf("BlockScopedShortDeclPreserved: mod=%v len=%d", scopedMod, len(scopedStmts))
	}
	if _, isBlk := scopedStmts[0].(*ast.BlockStmt); !isBlk {
		t.Fatalf("BlockScopedShortDeclPreserved: expected *ast.BlockStmt wrapper for inner short decl, got %T", scopedStmts[0])
	}

	// Arbitrary method `.Exit()` is NOT treated as an unconditional abort in BuildStmtCFG or stmtAlwaysTerminates.
	exitFn := idx.topFuncs["MethodExitIsNotAbort"]
	cfg, okCFG := BuildStmtCFG(exitFn.Body.List)
	if !okCFG {
		t.Fatal("MethodExitIsNotAbort: BuildStmtCFG failed")
	}
	for _, blk := range cfg.Blocks {
		if blk.Aborts {
			t.Fatalf("MethodExitIsNotAbort: non-os h.Exit() falsely marked Aborts=true on block %d", blk.ID)
		}
	}
	osVsMethodFn := idx.topFuncs["OSExitVsMethodExit"]
	if stmtAlwaysTerminates(osVsMethodFn.Body.List[0]) {
		t.Fatal("stmtAlwaysTerminates falsely returned true on h.Exit()")
	}
	if !stmtAlwaysTerminates(osVsMethodFn.Body.List[1]) {
		t.Fatal("stmtAlwaysTerminates failed to recognize os.Exit(1)")
	}

	// 2. Import alias shadowing check in NewPackageInactiveKernel: unshadowed alias admits PureIntReadFuncs, local shadow rejects.
	aliasCleanSrc := `package os

import (
	rtatomic "internal/runtime/atomic"
	"unsafe"
)

type File struct {
	file *file
}
type file struct {
	sysfd uintptr
}

func readSysfd(f *File) uintptr {
	return rtatomic.Loaduintptr((*uintptr)(unsafe.Pointer(&f.file.sysfd)))
}

func readSysfdShadowed(f *File) uintptr {
	rtatomic := f
	_ = rtatomic
	return 0
}
`
	aliasFiles := mustParseTestFiles(t, aliasCleanSrc)
	aliasIdx, errAIdx := indexPackageAST("os", aliasFiles, nil, nil)
	if errAIdx != nil {
		t.Fatalf("indexPackageAST failed on aliasCleanSrc: %v", errAIdx)
	}
	aliasKernel := NewPackageInactiveKernel(aliasIdx, aliasFiles, nil, nil)
	if !aliasKernel.PureIntReadFuncs["readSysfd"] {
		t.Fatalf("expected unshadowed import-alias readSysfd in PureIntReadFuncs, got %v", aliasKernel.PureIntReadFuncs)
	}
	if aliasKernel.PureIntReadFuncs["readSysfdShadowed"] {
		t.Fatalf("expected shadowed readSysfdShadowed excluded from PureIntReadFuncs")
	}

	// 3. testing checkParallel self-push linkname vs forbidden runtime pull or side-effecting body.
	selfPushTesting := validTestingChdirSetenvCleanupSrc + "\n//go:linkname checkParallel testing.checkParallel\nfunc checkParallel(t *T) {\n\tt.checkParallel()\n}\n"
	spFiles := mustParseTestFiles(t, selfPushTesting)
	pulled := map[string]bool{}
	selfPush := map[string]bool{}
	if err := VerifyHarnessFileDirectives("testing", selfPushTesting, pulled, selfPush, nil, nil); err != nil || len(pulled) != 0 || !selfPush["checkParallel"] {
		t.Fatalf("expected self-push testing.checkParallel directive accepted with zero runtime pulls, got err=%v pulled=%v selfPush=%v", err, pulled, selfPush)
	}
	if err := VerifyTestingChdirAST(spFiles); err != nil {
		t.Fatalf("expected delegating checkParallel(t *T) accepted by VerifyTestingChdirAST: %v", err)
	}
	badPullTesting := validTestingChdirSetenvCleanupSrc + "\n//go:linkname checkParallel runtime.evilHook\nfunc checkParallel(t *T)\n"
	if err := VerifyHarnessFileDirectives("testing", badPullTesting, map[string]bool{}, map[string]bool{}, nil, nil); err == nil {
		t.Fatal("expected runtime pull on checkParallel to be rejected by VerifyHarnessFileDirectives")
	}
	badBodyTesting := validTestingChdirSetenvCleanupSrc + "\nvar leaked int\n//go:linkname checkParallel testing.checkParallel\nfunc checkParallel(t *T) {\n\tleaked = 1\n\tt.checkParallel()\n}\n"
	if err := VerifyTestingChdirAST(mustParseTestFiles(t, badBodyTesting)); err == nil {
		t.Fatal("expected side-effecting checkParallel(t *T) to be rejected by VerifyTestingChdirAST")
	}

	// 4. Raw WORD/BYTE in math assembly taints only that TEXT at Tier 2, while failing VerifyMathPackage if reached by Tier 1.
	mathWithTan := buildValidSyntheticMathGoSrc("\nfunc archTan(x float64) float64\nfunc Tan(x float64) float64 { return archTan(x) }\n")
	asmWordTan := validSyntheticMathAsm + "\nTEXT ·archTan(SB),$0\n\tWORD $0xe7000000\n\tRET\n"
	pureWithWordTan, err := VerifyMathPackage(context.Background(), mustParseTestFiles(t, mathWithTan), []string{mathWithTan}, map[string]string{"k.s": asmWordTan}, nil)
	if err != nil {
		t.Fatalf("expected WORD in Tier-2 archTan to taint Tan without failing package, got err=%v", err)
	}
	if slices.Contains(pureWithWordTan, "Tan") || !slices.Contains(pureWithWordTan, "Sin") {
		t.Fatalf("expected Tan tainted and Sin pure, got %v", pureWithWordTan)
	}
	mathTier1CallsWord := strings.Replace(mathWithTan, "func Floor(x float64) float64 { return x + pow10tab[0] + float64(bits.LeadingZeros64(1)) }", "func Floor(x float64) float64 { return archTan(x) }", 1)
	if _, err := VerifyMathPackage(context.Background(), mustParseTestFiles(t, mathTier1CallsWord), []string{mathTier1CallsWord}, map[string]string{"k.s": asmWordTan}, nil); err == nil {
		t.Fatal("expected Tier-1 Floor reaching raw WORD assembly to fail VerifyMathPackage")
	}

	// 5. Math assembly RMW/atomic/bit-mutate ops on (SB) and forward-jump indirect stores after table address load must fail VerifyMathPackage.
	for _, badMathAsm := range []struct {
		name string
		asm  string
	}{
		{"one_op_rmw_incq", validSyntheticMathAsm + "\nTEXT ·archTan(SB),$0\n\tINCQ ·pow10tab+0(SB)\n\tRET\n"},
		{"bit_test_set_btsq", validSyntheticMathAsm + "\nTEXT ·archTan(SB),$0\n\tBTSQ $0, ·pow10tab+0(SB)\n\tRET\n"},
		{"cmpxchg_sb", validSyntheticMathAsm + "\nTEXT ·archTan(SB),$0\n\tCMPXCHGQ CX, ·pow10tab+0(SB)\n\tRET\n"},
		{"xchg_first_operand_sb", validSyntheticMathAsm + "\nTEXT ·archTan(SB),$0\n\tXCHGQ ·pow10tab+0(SB), AX\n\tRET\n"},
		{"arm64_stxr_mid_operand_sb", validSyntheticMathAsm + "\nTEXT ·archTan(SB),$0\n\tSTXR R0, ·pow10tab+0(SB), R1\n\tRET\n"},
		{"arm64_vst1_mid_operand_sb", validSyntheticMathAsm + "\nTEXT ·archTan(SB),$0\n\tVST1.P [V0.D2], ·pow10tab+0(SB), R1\n\tRET\n"},
		{"zero_operand_stosq_after_lea", validSyntheticMathAsm + "\nTEXT ·archTan(SB),$0\n\tLEAQ ·pow10tab+0(SB), DI\n\tSTOSQ\n\tRET\n"},
		{"zero_operand_movsq", validSyntheticMathAsm + "\nTEXT ·archTan(SB),$0\n\tMOVSQ\n\tRET\n"},
		{"forward_jmp_indirect_table_store", validSyntheticMathAsm + "\nTEXT ·archTan(SB),$0\n\tJMP take_addr\nstore_it:\n\tMOVQ AX, (R8)\n\tRET\ntake_addr:\n\tLEAQ ·pow10tab+0(SB), R8\n\tJMP store_it\n"},
	} {
		t.Run("math_asm_"+badMathAsm.name, func(t *testing.T) {
			if _, err := VerifyMathPackage(context.Background(), mustParseTestFiles(t, mathWithTan), []string{mathWithTan}, map[string]string{"k.s": badMathAsm.asm}, nil); err == nil {
				t.Fatalf("expected VerifyMathPackage to reject %s", badMathAsm.name)
			}
		})
	}

	for _, badMathGo := range []struct {
		name string
		src  string
	}{
		{"range_lhs_table_write", strings.Replace(mathWithTan, "func Sqrt(x float64) float64 { return x + pow10tab[0] + float64(bits.LeadingZeros64(1)) }", "func Sqrt(x float64) float64 { for _, pow10tab[0] = range [1]float64{x} {}; return pow10tab[0] }", 1)},
		{"shadowed_param_unsafe_bitcast", strings.Replace(mathWithTan, "func Float64bits(f float64) uint64 { return *(*uint64)(unsafe.Pointer(&f)) }", "func Float64bits(f float64) uint64 { var f uint8; return *(*uint64)(unsafe.Pointer(&f)) }", 1)},
	} {
		t.Run("math_go_"+badMathGo.name, func(t *testing.T) {
			if _, err := VerifyMathPackage(context.Background(), mustParseTestFiles(t, badMathGo.src), []string{badMathGo.src}, map[string]string{"k.s": validSyntheticMathAsm}, nil); err == nil {
				t.Fatalf("expected VerifyMathPackage to reject %s", badMathGo.name)
			}
		})
	}
}

func TestPropertyToolchainMathConstantPruningAndTaintOracle(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		const nConsts = 4
		const nFuncs = 5
		constVals := make([]bool, nConsts)
		for i := range constVals {
			constVals[i] = rapid.Bool().Draw(rt, fmt.Sprintf("c%d", i))
		}
		cpuDirect := make([]bool, nFuncs)
		condIdx := make([]int, nFuncs)
		thenCallee := make([]int, nFuncs)
		elseCallee := make([]int, nFuncs)
		injectDeadCPU := make([]bool, nFuncs)
		for i := range nFuncs {
			cpuDirect[i] = rapid.Bool().Draw(rt, fmt.Sprintf("cpu%d", i))
			condIdx[i] = rapid.IntRange(0, nConsts-1).Draw(rt, fmt.Sprintf("cond%d", i))
			if i+1 < nFuncs {
				thenCallee[i] = rapid.IntRange(i+1, nFuncs-1).Draw(rt, fmt.Sprintf("then%d", i))
				elseCallee[i] = rapid.IntRange(i+1, nFuncs-1).Draw(rt, fmt.Sprintf("else%d", i))
			} else {
				thenCallee[i] = -1
				elseCallee[i] = -1
			}
			injectDeadCPU[i] = rapid.Bool().Draw(rt, fmt.Sprintf("dead%d", i))
		}

		// Independent semantic reachability oracle over evaluated boolean constants.
		wantTainted := make([]bool, nFuncs)
		for i := nFuncs - 1; i >= 0; i-- {
			taint := cpuDirect[i]
			target := elseCallee[i]
			if constVals[condIdx[i]] {
				target = thenCallee[i]
			}
			if target >= 0 && wantTainted[target] {
				taint = true
			}
			wantTainted[i] = taint
		}

		var extra strings.Builder
		extra.WriteString("\nconst (\n\talwaysFalseGate = false\n")
		for i, v := range constVals {
			fmt.Fprintf(&extra, "\tswConst%d = %v\n", i, v)
		}
		extra.WriteString(")\n")
		for i := range nFuncs {
			fmt.Fprintf(&extra, "func GenFn%d(v%d float64) float64 {\n", i, i)
			if injectDeadCPU[i] {
				extra.WriteString("\tif alwaysFalseGate {\n\t\tif useFMA { return 1 }\n\t}\n")
			}
			if cpuDirect[i] {
				fmt.Fprintf(&extra, "\tif useFMA { return v%d }\n", i)
			}
			if thenCallee[i] >= 0 {
				fmt.Fprintf(&extra, "\tif swConst%d {\n\t\treturn GenFn%d(v%d)\n\t}\n\treturn GenFn%d(v%d)\n",
					condIdx[i], thenCallee[i], i, elseCallee[i], i)
			} else {
				fmt.Fprintf(&extra, "\treturn v%d\n", i)
			}
			extra.WriteString("}\n")
		}

		src := buildValidSyntheticMathGoSrc(extra.String())
		files := mustParseTestFiles(t, src)
		gotPure, err := VerifyMathPackage(context.Background(), files, []string{src}, map[string]string{"kernels.s": validSyntheticMathAsm}, nil)
		if err != nil {
			rt.Fatalf("VerifyMathPackage failed: %v", err)
		}
		for i := range nFuncs {
			name := fmt.Sprintf("GenFn%d", i)
			admitted := slices.Contains(gotPure, name)
			if admitted == wantTainted[i] {
				rt.Fatalf("%s: admitted=%v, wantTainted=%v", name, admitted, wantTainted[i])
			}
		}
	})
}

func FuzzToolchainMathDebugAndKernelVerifiers(f *testing.F) {
	f.Add(buildValidSyntheticMathGoSrc(""), validSyntheticMathAsm)
	f.Add(validRuntimeDebugModSrc, "// empty\n")
	f.Add(validRuntimeModinfoSrc, "")
	f.Add("package math\nfunc Sin(x float64) float64 { return x }\n", "TEXT ·Sin(SB),$0\n\tCPUID\n\tRET\n")
	f.Add("package scannerhooks\nimport \"go/token\"\nvar StringEnd func(scanner any) token.Pos\n", "")
	f.Add("package scanner\nimport (\"fmt\"; \"go/internal/scannerhooks\"; \"go/token\"; \"io\")\ntype Scanner struct { stringEnd token.Pos }\nfunc init() { scannerhooks.StringEnd = func(s any) token.Pos { return s.(*Scanner).stringEnd } }\nfunc PrintError(w io.Writer, err error) { fmt.Fprintf(w, \"%v\", err) }\n", "")

	f.Fuzz(func(t *testing.T, goSrc, asmSrc string) {
		ctx := context.Background()
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, "fuzz.go", goSrc, 0)
		if err != nil {
			return
		}
		files := []*ast.File{parsed}
		srcs := []string{goSrc}
		asms := map[string]string{"fuzz.s": asmSrc}

		res1, err1 := VerifyMathPackage(ctx, files, srcs, asms, nil)
		res2, err2 := VerifyMathPackage(ctx, files, srcs, asms, nil)
		if (err1 == nil) != (err2 == nil) || !slices.Equal(res1, res2) {
			t.Fatalf("non-deterministic VerifyMathPackage: (%v, %v) vs (%v, %v)", res1, err1, res2, err2)
		}
		if slices.Contains(res1, "FMA") {
			t.Fatalf("VerifyMathPackage must never admit FMA: %v", res1)
		}

		dErr1 := VerifyRuntimeDebugPackage(ctx, files, srcs, asms, nil)
		dErr2 := VerifyRuntimeDebugPackage(ctx, files, srcs, asms, nil)
		if (dErr1 == nil) != (dErr2 == nil) {
			t.Fatalf("non-deterministic VerifyRuntimeDebugPackage: %v vs %v", dErr1, dErr2)
		}
		_ = VerifyRuntimeModinfoAST(files, srcs, nil)
		_ = DiscoverRuntimeInactiveGates(files, srcs, nil)
		_ = DiscoverVerifiedRuntimeLineWriters(files, srcs)
		_ = VerifyTestingChdirAST(files)
		if (VerifyTabwriterPackageAST(files) == nil) != (VerifyTabwriterPackageAST(files) == nil) {
			t.Fatalf("non-deterministic VerifyTabwriterPackageAST")
		}
		if (VerifyGoTokenPackageAST(files) == nil) != (VerifyGoTokenPackageAST(files) == nil) {
			t.Fatalf("non-deterministic VerifyGoTokenPackageAST")
		}
		if (VerifyGoScannerHooksPackageAST(files) == nil) != (VerifyGoScannerHooksPackageAST(files) == nil) {
			t.Fatalf("non-deterministic VerifyGoScannerHooksPackageAST")
		}
		if (VerifyGoScannerPackageAST(files) == nil) != (VerifyGoScannerPackageAST(files) == nil) {
			t.Fatalf("non-deterministic VerifyGoScannerPackageAST")
		}
		if (VerifyGoASTPackageAST(files) == nil) != (VerifyGoASTPackageAST(files) == nil) {
			t.Fatalf("non-deterministic VerifyGoASTPackageAST")
		}
		if (VerifyGoParserPackageAST(files) == nil) != (VerifyGoParserPackageAST(files) == nil) {
			t.Fatalf("non-deterministic VerifyGoParserPackageAST")
		}
		_ = VerifyNoForeignDirectives("text/tabwriter", goSrc)
		for _, decl := range parsed.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				_, _ = BuildStmtCFG(fn.Body.List)
			}
		}
	})
}

func loadGOROOTPkgAST(t *testing.T, pkgPath string) ([]*ast.File, []string) {
	t.Helper()
	dir := filepath.Join(runtime.GOROOT(), "src", filepath.FromSlash(pkgPath))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	var srcs []string
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", name, err)
		}
		src := string(raw)
		f, err := parser.ParseFile(fset, name, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", name, err)
		}
		files = append(files, f)
		srcs = append(srcs, src)
	}
	if len(files) == 0 {
		t.Fatalf("no Go files loaded for %s", pkgPath)
	}
	return files, srcs
}

func TestGOROOTTabwriterAndSyntaxPackageVerifiers(t *testing.T) {
	cases := []struct {
		pkgPath string
		verify  func([]*ast.File) error
	}{
		{"text/tabwriter", VerifyTabwriterPackageAST},
		{"go/token", VerifyGoTokenPackageAST},
		{"go/scanner", VerifyGoScannerPackageAST},
		{"go/ast", VerifyGoASTPackageAST},
		{"go/parser", VerifyGoParserPackageAST},
	}
	if _, err := os.Stat(filepath.Join(runtime.GOROOT(), "src", "go", "internal", "scannerhooks")); err == nil {
		cases = append(cases, struct {
			pkgPath string
			verify  func([]*ast.File) error
		}{"go/internal/scannerhooks", VerifyGoScannerHooksPackageAST})
	}
	for _, tc := range cases {
		t.Run(tc.pkgPath, func(t *testing.T) {
			files, srcs := loadGOROOTPkgAST(t, tc.pkgPath)
			for _, src := range srcs {
				if err := VerifyNoForeignDirectives(tc.pkgPath, src); err != nil {
					t.Fatalf("VerifyNoForeignDirectives(%s) failed: %v", tc.pkgPath, err)
				}
			}
			if err := tc.verify(files); err != nil {
				t.Fatalf("verifier failed on active GOROOT %s: %v", tc.pkgPath, err)
			}
		})
	}

	constraintFiles, constraintSrcs := loadGOROOTPkgAST(t, "go/build/constraint")
	for _, src := range constraintSrcs {
		if err := VerifyFileLinknameDirectives("go/build/constraint", src); err != nil {
			t.Fatalf("VerifyFileLinknameDirectives(go/build/constraint) failed: %v", err)
		}
	}
	if err := VerifyPurePackageAST("go/build/constraint", constraintFiles); err != nil {
		t.Fatalf("VerifyPurePackageAST(go/build/constraint) failed: %v", err)
	}
}

const validTabwriterSyntheticSrc = `package tabwriter

import (
	"fmt"
	"io"
	"unicode/utf8"
)

var newline = []byte{'\n'}

type cell struct {
	size  int
	width int
}

type Writer struct {
	output io.Writer
	minwidth int
	tabwidth int
	padding int
	padbytes [8]byte
	flags uint
	buf []byte
	pos int
	cell cell
	lines [][]cell
}

func NewWriter(output io.Writer, minwidth, tabwidth, padding int, padchar byte, flags uint) *Writer {
	return new(Writer).Init(output, minwidth, tabwidth, padding, padchar, flags)
}

func (b *Writer) Init(output io.Writer, minwidth, tabwidth, padding int, padchar byte, flags uint) *Writer {
	b.output = output
	b.minwidth = minwidth + utf8.RuneSelf
	_ = fmt.Sprintf("%d", padding)
	return b
}

func (b *Writer) dump() {
	print("debug")
}

func (b *Writer) Write(buf []byte) (n int, err error) {
	return len(buf), nil
}

func (b *Writer) Flush() error {
	_, err := b.output.Write(newline)
	return err
}
`

func TestVerifyTabwriterPackageASTMutations(t *testing.T) {
	if err := VerifyTabwriterPackageAST(mustParseTestFiles(t, validTabwriterSyntheticSrc)); err != nil {
		t.Fatalf("valid synthetic tabwriter rejected: %v", err)
	}

	negCases := []struct {
		name    string
		mutate  func(string) string
		wantSub string
	}{
		{
			name:    "unapproved_import",
			mutate:  func(s string) string { return strings.Replace(s, "\"io\"", "\"io\"\n\t\"os\"", 1) },
			wantSub: "unapproved import \"os\"",
		},
		{
			name:    "init_func",
			mutate:  func(s string) string { return s + "\nfunc init() {}\n" },
			wantSub: "unexpected init function",
		},
		{
			name: "mutable_pkg_var",
			mutate: func(s string) string {
				return strings.Replace(s, "return len(buf), nil", "newline[0] = 'x'\n\treturn len(buf), nil", 1)
			},
			wantSub: "forbidden mutation or address-of package var newline",
		},
		{
			name:    "func_field_on_writer",
			mutate:  func(s string) string { return strings.Replace(s, "pos int", "pos int\n\thook func()", 1) },
			wantSub: "forbidden field hook type on Writer",
		},
		{
			name: "call_to_dump",
			mutate: func(s string) string {
				return strings.Replace(s, "return len(buf), nil", "b.dump()\n\treturn len(buf), nil", 1)
			},
			wantSub: "forbidden selector reference .dump",
		},
		{
			name: "builtin_print_outside_dump",
			mutate: func(s string) string {
				return strings.Replace(s, "return len(buf), nil", "println(len(buf))\n\treturn len(buf), nil", 1)
			},
			wantSub: "forbidden builtin println in Write",
		},
	}
	for _, tc := range negCases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyTabwriterPackageAST(mustParseTestFiles(t, tc.mutate(validTabwriterSyntheticSrc)))
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("got err=%v, want substring %q", err, tc.wantSub)
			}
		})
	}
}

func TestVerifyGo126ScannerHooksScannerAndParserAST(t *testing.T) {
	const validHooksSrc = `package scannerhooks

import "go/token"

var StringEnd func(scanner any) token.Pos
`
	if err := VerifyGoScannerHooksPackageAST(mustParseTestFiles(t, validHooksSrc)); err != nil {
		t.Fatalf("validHooksSrc rejected: %v", err)
	}
	for _, neg := range []struct {
		name string
		src  string
	}{
		{"initialized_var", "package scannerhooks\nimport \"go/token\"\nvar StringEnd = func(any) token.Pos { return 0 }\n"},
		{"blank_var_side_effect", validHooksSrc + "\nvar _ = func() int { StringEnd = func(any) token.Pos { return 1 }; return 0 }()\n"},
		{"extra_const", validHooksSrc + "\nconst Extra = 1\n"},
		{"extra_var", validHooksSrc + "\nvar Extra int\n"},
		{"extra_func", validHooksSrc + "\nfunc Helper() {}\n"},
		{"wrong_sig", "package scannerhooks\nimport \"go/token\"\nvar StringEnd func(int) token.Pos\n"},
		{"bad_import", "package scannerhooks\nimport (\"go/token\"; \"os\")\nvar _ = os.ErrInvalid\nvar StringEnd func(any) token.Pos\n"},
	} {
		t.Run("hooks_"+neg.name, func(t *testing.T) {
			if err := VerifyGoScannerHooksPackageAST(mustParseTestFiles(t, neg.src)); err == nil {
				t.Fatalf("expected %s to fail VerifyGoScannerHooksPackageAST", neg.name)
			}
		})
	}
	if err := VerifyGoScannerHooksPackageAST(mustParseTestFiles(t,
		"package scannerhooks\nimport \"go/token\"\n",
		"package scannerhooks\nvar StringEnd func(any) token.Pos\n",
	)); err == nil {
		t.Fatal("expected split scannerhooks without go/token import in decl file to fail")
	}

	const validGo126ScannerSrc = `package scanner

import (
	"fmt"
	"go/internal/scannerhooks"
	"go/token"
	"io"
)

type Error struct{}

var _ error = (*Error)(nil)

type Scanner struct {
	stringEnd token.Pos
}

func init() {
	scannerhooks.StringEnd = func(scanner any) token.Pos {
		return scanner.(*Scanner).stringEnd
	}
}

func PrintError(w io.Writer, err error) {
	fmt.Fprintf(w, "%v", err)
}
`
	if err := VerifyGoScannerPackageAST(mustParseTestFiles(t, validGo126ScannerSrc)); err != nil {
		t.Fatalf("validGo126ScannerSrc rejected: %v", err)
	}
	for _, neg := range []struct {
		name   string
		mutate func(string) string
	}{
		{"dup_init", func(s string) string { return s + "\nfunc init() {}\n" }},
		{"wrong_lhs", func(s string) string {
			return strings.Replace(s, "scannerhooks.StringEnd =", "scannerhooks.Other =", 1)
		}},
		{"wrong_assert_type", func(s string) string { return strings.Replace(s, "(*Scanner)", "(*token.File)", 1) }},
		{"non_init_ref", func(s string) string {
			return s + "\nfunc leak(s *Scanner) token.Pos { return scannerhooks.StringEnd(s) }\n"
		}},
		{"type_decl_scannerhooks_ref", func(s string) string {
			return s + "\ntype hidden scannerhooks.Hook\n"
		}},
		{"const_decl_scannerhooks_ref", func(s string) string {
			return s + "\nconst hidden = scannerhooks.Const\n"
		}},
		{"blank_var_hook_write", func(s string) string {
			sNoInit := strings.Replace(s, "func init() {\n\tscannerhooks.StringEnd = func(scanner any) token.Pos {\n\t\treturn scanner.(*Scanner).stringEnd\n\t}\n}\n", "", 1)
			return sNoInit + "\nvar _ = func() int { scannerhooks.StringEnd = func(any) token.Pos { return 7 }; return 0 }()\n"
		}},
		{"multi_return_blank_var", func(s string) string {
			return s + "\nvar _, _ = fmt.Printf(\"x\")\n"
		}},
	} {
		t.Run("scanner_"+neg.name, func(t *testing.T) {
			if err := VerifyGoScannerPackageAST(mustParseTestFiles(t, neg.mutate(validGo126ScannerSrc))); err == nil {
				t.Fatalf("expected %s to fail VerifyGoScannerPackageAST", neg.name)
			}
		})
	}

	const validGo126ParserAddon = `package parser

import (
	"go/internal/scannerhooks"
	"go/scanner"
	"go/token"
)

func stringEndOf(s *scanner.Scanner) token.Pos {
	return scannerhooks.StringEnd(s)
}
`
	const parserMainFor126 = `package parser

import (
	"fmt"
	"go/ast"
	"go/scanner"
	"go/token"
	"io"
	"io/fs"
	"os"
)

type Mode uint

const (
	PackageClauseOnly Mode = 1 << iota
	ImportsOnly
	ParseComments
	Trace
)

type parser struct {
	trace   bool
	scanner scanner.Scanner
}

func (p *parser) init(fset *token.FileSet, src []byte, mode Mode) {
	p.trace = mode&Trace != 0
	_ = stringEndOf(&p.scanner)
}

func (p *parser) printTrace(a ...any) {
	fmt.Println(a...)
}

func readSource(filename string, src any) ([]byte, error) {
	if src != nil {
		if s, ok := src.(string); ok {
			return []byte(s), nil
		}
		if r, ok := src.(io.Reader); ok {
			return io.ReadAll(r)
		}
		return nil, fmt.Errorf("invalid source")
	}
	return os.ReadFile(filename)
}

func ParseFile(fset *token.FileSet, filename string, src any, mode Mode) (*ast.File, error) {
	text, err := readSource(filename, src)
	if err != nil {
		return nil, err
	}
	var p parser
	p.init(fset, text, mode)
	return &ast.File{}, nil
}

func ParseDir(fset *token.FileSet, path string, filter func(fs.FileInfo) bool, mode Mode) (map[string]*ast.Package, error) {
	_, _ = os.ReadDir(path)
	return nil, nil
}

func ParseExprFrom(fset *token.FileSet, filename string, src any, mode Mode) (ast.Expr, error) {
	text, err := readSource(filename, src)
	if err != nil {
		return nil, err
	}
	var p parser
	p.init(fset, text, mode)
	return nil, nil
}

func ParseExpr(x string) (ast.Expr, error) {
	return ParseExprFrom(token.NewFileSet(), "", []byte(x), 0)
}
`
	if err := VerifyGoParserPackageAST(mustParseTestFiles(t, parserMainFor126, validGo126ParserAddon)); err != nil {
		t.Fatalf("validGo126Parser rejected: %v", err)
	}
	for _, badAddon := range []string{
		strings.Replace(validGo126ParserAddon, "return scannerhooks.StringEnd(s)", "scannerhooks.StringEnd = nil\n\treturn 0", 1),
		strings.Replace(validGo126ParserAddon, "return scannerhooks.StringEnd(s)", "fn := scannerhooks.StringEnd\n\treturn fn(s)", 1),
		strings.Replace(validGo126ParserAddon, "scannerhooks.StringEnd(s)", "scannerhooks.Other(s)", 1),
		strings.Replace(validGo126ParserAddon, "\t\"go/internal/scannerhooks\"\n", "", 1),
		validGo126ParserAddon + "\nvar _ = stringEndOf(nil)\n",
	} {
		if err := VerifyGoParserPackageAST(mustParseTestFiles(t, parserMainFor126, badAddon)); err == nil {
			t.Fatalf("expected mutated parser addon %q to fail VerifyGoParserPackageAST", badAddon)
		}
	}

	// If a cached Go 1.26 toolchain archive is available in GOMODCACHE, verify its real stdlib ASTs too.
	modCache := os.Getenv("GOMODCACHE")
	if modCache == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			modCache = filepath.Join(home, "go", "pkg", "mod")
		}
	}
	if modCache != "" {
		matches, _ := filepath.Glob(filepath.Join(modCache, "cache", "download", "golang.org", "toolchain", "@v", "v0.0.1-go1.26.*.zip"))
		for _, zipPath := range matches {
			zr, err := zip.OpenReader(zipPath)
			if err != nil {
				continue
			}
			parseZipPkg := func(pkgRel string) []*ast.File {
				fset := token.NewFileSet()
				var out []*ast.File
				wantDir := "src/" + pkgRel + "/"
				for _, zf := range zr.File {
					_, after, ok := strings.Cut(zf.Name, "/")
					if !ok || !strings.HasPrefix(after, wantDir) {
						continue
					}
					rest := strings.TrimPrefix(after, wantDir)
					if strings.Contains(rest, "/") || !strings.HasSuffix(rest, ".go") || strings.HasSuffix(rest, "_test.go") {
						continue
					}
					rc, err := zf.Open()
					if err != nil {
						t.Fatalf("open %s: %v", zf.Name, err)
					}
					raw, err := io.ReadAll(rc)
					_ = rc.Close()
					if err != nil {
						t.Fatalf("read %s: %v", zf.Name, err)
					}
					parsed, err := parser.ParseFile(fset, rest, raw, 0)
					if err != nil {
						t.Fatalf("parse %s: %v", zf.Name, err)
					}
					out = append(out, parsed)
				}
				return out
			}
			if files := parseZipPkg("go/internal/scannerhooks"); len(files) > 0 {
				if err := VerifyGoScannerHooksPackageAST(files); err != nil {
					_ = zr.Close()
					t.Fatalf("%s go/internal/scannerhooks failed: %v", filepath.Base(zipPath), err)
				}
			}
			if files := parseZipPkg("go/scanner"); len(files) > 0 {
				if err := VerifyGoScannerPackageAST(files); err != nil {
					_ = zr.Close()
					t.Fatalf("%s go/scanner failed: %v", filepath.Base(zipPath), err)
				}
			}
			if files := parseZipPkg("go/parser"); len(files) > 0 {
				if err := VerifyGoParserPackageAST(files); err != nil {
					_ = zr.Close()
					t.Fatalf("%s go/parser failed: %v", filepath.Base(zipPath), err)
				}
			}
			_ = zr.Close()
			break
		}
	}
}

func TestVerifySyntaxPackagesNegativeMutations(t *testing.T) {
	t.Run("go_token_post_init_keywords_write", func(t *testing.T) {
		src := `package token
import "strconv"
type Token int
type FileSet struct { base int }
var tokens = [...]string{0: "ILLEGAL"}
var keywords map[string]Token
func init() { keywords = make(map[string]Token); keywords[tokens[0]] = 0 }
func Mutate(s string) { keywords[s] = Token(len(strconv.Itoa(1))) }
`
		err := VerifyGoTokenPackageAST(mustParseTestFiles(t, src))
		if err == nil || !strings.Contains(err.Error(), "forbidden mutation or address-of package var keywords in Mutate") {
			t.Fatalf("got err=%v, want keywords mutation rejection", err)
		}
	})

	t.Run("go_token_generic_fileset_rejected", func(t *testing.T) {
		src := `package token
type FileSet[T any] struct { base T }
`
		err := VerifyGoTokenPackageAST(mustParseTestFiles(t, src))
		if err == nil || !strings.Contains(err.Error(), "FileSet must be a non-generic non-alias struct") {
			t.Fatalf("got err=%v, want generic FileSet rejection", err)
		}
	})

	t.Run("go_token_exported_fileset_field_rejected", func(t *testing.T) {
		src := `package token
type FileSet struct { Exported int }
`
		err := VerifyGoTokenPackageAST(mustParseTestFiles(t, src))
		if err == nil || !strings.Contains(err.Error(), "FileSet must not expose exported field") {
			t.Fatalf("got err=%v, want exported FileSet field rejection", err)
		}
	})

	t.Run("go_scanner_fprintf_outside_printerror", func(t *testing.T) {
		src := `package scanner
import (
	"fmt"
	"io"
	"path/filepath"
)
func PrintError(w io.Writer, err error) { fmt.Fprintf(w, "%v", err) }
func ScanHelper(p string) string {
	fmt.Fprintf(nil, "%s", filepath.Clean(p))
	return p
}
`
		err := VerifyGoScannerPackageAST(mustParseTestFiles(t, src))
		if err == nil || !strings.Contains(err.Error(), "forbidden fmt.Fprintf in ScanHelper") {
			t.Fatalf("got err=%v, want fmt.Fprintf confinement error", err)
		}
	})

	t.Run("go_scanner_filepath_evalsymlinks", func(t *testing.T) {
		src := `package scanner
import (
	"fmt"
	"io"
	"path/filepath"
)
func PrintError(w io.Writer, err error) { fmt.Fprintf(w, "%v", err) }
func BadPath(p string) (string, error) { return filepath.EvalSymlinks(p) }
`
		err := VerifyGoScannerPackageAST(mustParseTestFiles(t, src))
		if err == nil || !strings.Contains(err.Error(), "forbidden filepath.EvalSymlinks in BadPath") {
			t.Fatalf("got err=%v, want filepath.EvalSymlinks rejection", err)
		}
	})

	t.Run("go_ast_os_outside_print", func(t *testing.T) {
		src := `package ast
import (
	"go/token"
	"io"
	"os"
	"reflect"
)
type FieldFilter func(string, reflect.Value) bool
type Ident struct{ NamePos token.Pos }
func (x *Ident) Pos() token.Pos { return x.NamePos }
func (x *Ident) End() token.Pos { return x.NamePos }
func Fprint(w io.Writer, fset *token.FileSet, x any, f FieldFilter) error { return nil }
func Print(fset *token.FileSet, x any) error { return Fprint(os.Stdout, fset, x, nil) }
func Leak() { _ = os.Stdout }
`
		err := VerifyGoASTPackageAST(mustParseTestFiles(t, src))
		if err == nil || !strings.Contains(err.Error(), "forbidden os.Stdout in Leak") {
			t.Fatalf("got err=%v, want os confinement error", err)
		}
	})

	t.Run("go_ast_impure_pos_method", func(t *testing.T) {
		src := `package ast
import (
	"fmt"
	"go/token"
	"io"
	"os"
	"reflect"
)
type FieldFilter func(string, reflect.Value) bool
type Ident struct{ NamePos token.Pos }
func (x *Ident) Pos() token.Pos { _ = fmt.Sprintf("x"); return x.NamePos }
func (x *Ident) End() token.Pos { return x.NamePos }
func Fprint(w io.Writer, fset *token.FileSet, x any, f FieldFilter) error { return nil }
func Print(fset *token.FileSet, x any) error { return Fprint(os.Stdout, fset, x, nil) }
`
		err := VerifyGoASTPackageAST(mustParseTestFiles(t, src))
		if err == nil || !strings.Contains(err.Error(), "forbidden fmt.Sprintf in Ident.Pos") {
			t.Fatalf("got err=%v, want Pos() purity error", err)
		}
	})

	const baseValidParserSrc = `package parser
import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)
type Mode uint
const (
	PackageClauseOnly Mode = 1 << iota
	ImportsOnly
	ParseComments
	Trace
)
const debugResolve = false
type parser struct { trace bool }
func (p *parser) init(file *token.File, src []byte, mode Mode) {
	p.trace = mode&Trace != 0
}
func (p *parser) printTrace(a ...any) { fmt.Println(a...) }
func trace(p *parser, msg string) *parser { p.printTrace(msg); return p }
func un(p *parser) { p.printTrace(")") }
func (p *parser) step() {
	if p.trace {
		defer un(trace(p, "step"))
	}
}
type resolver struct{}
func (r *resolver) trace(msg string) { fmt.Println(msg) }
func (r *resolver) run() {
	if debugResolve {
		r.trace("x")
	}
}
func readSource(filename string, src any) ([]byte, error) {
	if src != nil {
		switch s := src.(type) {
		case string:
			return []byte(s), nil
		case []byte:
			return s, nil
		case io.Reader:
			return io.ReadAll(s)
		}
		return nil, errors.New("invalid source")
	}
	return os.ReadFile(filename)
}
func ParseFile(fset *token.FileSet, filename string, src any, mode Mode) (*ast.File, error) {
	text, err := readSource(filename, src)
	if err != nil {
		return nil, err
	}
	var p parser
	p.init(nil, text, mode)
	return nil, nil
}
func ParseDir(fset *token.FileSet, path string, filter func(fs.FileInfo) bool, mode Mode) (map[string]*ast.Package, error) {
	_, err := os.ReadDir(filepath.Join(path, "."))
	return nil, err
}
func ParseExprFrom(fset *token.FileSet, filename string, src any, mode Mode) (ast.Expr, error) {
	text, err := readSource(filename, src)
	if err != nil {
		return nil, err
	}
	var p parser
	p.init(nil, text, mode)
	return nil, nil
}
func ParseExpr(x string) (ast.Expr, error) {
	return ParseExprFrom(token.NewFileSet(), "", []byte(x), 0)
}
`
	if err := VerifyGoParserPackageAST(mustParseTestFiles(t, baseValidParserSrc)); err != nil {
		t.Fatalf("baseValidParserSrc rejected: %v", err)
	}

	parserNeg := []struct {
		name    string
		mutate  func(string) string
		wantSub string
	}{
		{
			name: "unguarded_printTrace",
			mutate: func(s string) string {
				return strings.Replace(s, "if p.trace {\n\t\tdefer un(trace(p, \"step\"))\n\t}", "p.printTrace(\"leak\")", 1)
			},
			wantSub: "unguarded .printTrace reference in parser.step",
		},
		{
			name: "funclit_inside_if_trace_unguarded",
			mutate: func(s string) string {
				return strings.Replace(s, "defer un(trace(p, \"step\"))", "fn := func() { p.printTrace(\"leak\") }\n\t\tfn()", 1)
			},
			wantSub: "unguarded .printTrace reference in parser.step",
		},
		{
			name: "debug_resolve_enabled",
			mutate: func(s string) string {
				return strings.Replace(s, "const debugResolve = false", "const debugResolve = true", 1)
			},
			wantSub: "unguarded .trace reference in resolver.run",
		},
		{
			name:    "os_in_non_nil_readsource",
			mutate:  func(s string) string { return strings.Replace(s, "return []byte(s), nil", "return os.ReadFile(s)", 1) },
			wantSub: "forbidden os.ReadFile inside readSource non-nil branch",
		},
		{
			name:    "parseexpr_nonzero_mode",
			mutate:  func(s string) string { return strings.Replace(s, "[]byte(x), 0)", "[]byte(x), Trace)", 1) },
			wantSub: "ParseExpr must pass mode 0",
		},
		{
			name: "parsefile_nil_readsource",
			mutate: func(s string) string {
				return strings.Replace(s, "readSource(filename, src)", "readSource(filename, nil)", 1)
			},
			wantSub: "readSource in ParseFile must forward src",
		},
		{
			name: "parsefile_forced_trace_init",
			mutate: func(s string) string {
				return strings.Replace(s, "p.init(nil, text, mode)", "p.init(nil, text, mode|Trace)", 1)
			},
			wantSub: ".init in ParseFile must forward mode",
		},
		{
			name: "parsefile_readsource_alias",
			mutate: func(s string) string {
				return strings.Replace(s, "text, err := readSource(filename, src)", "rs := readSource\n\t_, _ = rs(filename, nil)\n\ttext, err := readSource(filename, src)", 1)
			},
			wantSub: "without aliasing",
		},
		{
			name:    "trace_iota_broken_by_intermediate_const",
			mutate:  func(s string) string { return strings.Replace(s, "\tImportsOnly\n", "\tImportsOnly = 99\n", 1) },
			wantSub: "Trace constant bit (1 << 3) mismatch",
		},
		{
			name:    "foreign_linkname_directive",
			mutate:  func(s string) string { return s + "\n//go:linkname ParseExpr runtime.evil\n" },
			wantSub: "forbidden linkname directive",
		},
	}
	for _, tc := range parserNeg {
		t.Run(tc.name, func(t *testing.T) {
			mut := tc.mutate(baseValidParserSrc)
			err := VerifyNoForeignDirectives("go/parser", mut)
			if err == nil {
				err = VerifyGoParserPackageAST(mustParseTestFiles(t, mut))
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("got err=%v, want substring %q", err, tc.wantSub)
			}
		})
	}
}
