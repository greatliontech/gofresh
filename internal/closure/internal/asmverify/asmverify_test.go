package asmverify

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
)

func TestEvalConstAsmUintExprAndRODATAFlags(t *testing.T) {
	t.Parallel()

	validExprs := map[string]uint64{
		"0":                  0,
		"8":                  8,
		"0x10":               16,
		"(1 << 4) + (2*3) | 1": 23,
		"16 >> 2":            4,
		"1 >> 64":            0,
		"0x3fffffff":         0x3fffffff,
	}
	for expr, want := range validExprs {
		got, ok := evalConstAsmUintExpr(expr)
		if !ok || got != want {
			t.Errorf("evalConstAsmUintExpr(%q) = (%d, %v), want (%d, true)", expr, got, ok, want)
		}
	}

	invalidExprs := []string{
		"",
		"-1",
		"8 - 4",
		"8 / 2",
		"8 ^ 2",
		"AX + 4",
		"0x40000000",
		"1 << 30",
		"0x20000000 + 0x20000000",
		"0x20000000 * 2",
		"(1 + 2",
		"1 + 2)",
	}
	for _, expr := range invalidExprs {
		if got, ok := evalConstAsmUintExpr(expr); ok {
			t.Errorf("evalConstAsmUintExpr(%q) = (%d, true), want false", expr, got)
		}
	}

	validRODATAFlags := []string{
		"RODATA",
		"$RODATA",
		"RODATA|NOPTR",
		"RODATA | DUPOK | NOPROF",
		"RODATA + NOPTR",
		"$8",
		"$(8 | 16)",
	}
	for _, expr := range validRODATAFlags {
		if !asmFlagsIncludeRODATA(expr) {
			t.Errorf("asmFlagsIncludeRODATA(%q) = false, want true", expr)
		}
	}

	invalidRODATAFlags := []string{
		"",
		"NOPTR",
		"DUPOK",
		"RODATA + RODATA",
		"RODATA | 4",
		"RODATA | TLSBSS",
		"RODATA - 8",
	}
	for _, expr := range invalidRODATAFlags {
		if asmFlagsIncludeRODATA(expr) {
			t.Errorf("asmFlagsIncludeRODATA(%q) = true, want false", expr)
		}
	}
}

func TestScanAsmTokensAndRegisterPredicates(t *testing.T) {
	t.Parallel()

	if f := scanAsmTokens(`MOVQ $"a:b(TLS) R14 PC", AX`); f != 0 {
		t.Errorf("scanAsmTokens on quoted literals = %v, want 0", f)
	}
	if f := scanAsmTokens(`MOVQ $"unclosed, AX`); f != (asmTokUnquotedColon | asmTokForbidden | asmTokPC | asmTokARM64SysReg | asmTokAMD64R14) {
		t.Errorf("scanAsmTokens on unclosed quote = %v, want all hazard flags set", f)
	}
	if f := scanAsmTokens(`MOVD R0:CNTVCT_EL0`); (f&asmTokUnquotedColon) == 0 || (f&asmTokARM64SysReg) == 0 {
		t.Errorf("scanAsmTokens(MOVD R0:CNTVCT_EL0) = %v, want unquoted-colon and arm64-sysreg", f)
	}
	if f := scanAsmTokens(`MOVQ pc+0(FP), AX; MOVQ r14+8(FP), BX; MOVQ g+16(FP), CX; MOVQ tpidr_el0+24(FP), DX`); f != 0 {
		t.Errorf("scanAsmTokens on lowercase frame slots = %v, want 0", f)
	}
	if f := scanAsmTokens(`MOVQ ·pc(SB), AX; MOVQ ·CNTVCT_EL0(SB), BX`); f != 0 {
		t.Errorf("scanAsmTokens on RODATA ·sym(SB) = %v, want 0", f)
	}
	if f := scanAsmTokens(`MOVQ ·ro( SB ), AX`); (f & asmTokForbidden) == 0 {
		t.Errorf("scanAsmTokens on spaced ( SB ) = %v, want asmTokForbidden", f)
	}
	if f := scanAsmTokens(`LEAQ 0(PC), R14`); (f&asmTokPC) == 0 || (f&asmTokAMD64R14) == 0 {
		t.Errorf("scanAsmTokens(LEAQ 0(PC), R14) = %v, want PC and R14 flags", f)
	}

	for _, cleanGPR := range []string{"R0", "R1", "R17", "R19", "R27", "R29", "R30", "LR"} {
		if !isCleanARM64SysRegDestGPR(cleanGPR) {
			t.Errorf("isCleanARM64SysRegDestGPR(%q) = false, want true", cleanGPR)
		}
	}
	for _, badGPR := range []string{"", "R", "R00", "R18", "R28", "R31", "RSP", "SP", "ZR"} {
		if isCleanARM64SysRegDestGPR(badGPR) {
			t.Errorf("isCleanARM64SysRegDestGPR(%q) = true, want false", badGPR)
		}
	}
}

func TestAuditedARM64WordOpcodes(t *testing.T) {
	t.Parallel()

	// MOVZ X0, #0 -> 0xd2800000 (clean)
	// MRS X0, MIDR_EL1 -> 0xd5380000 (clean)
	// MRS X0, ID_AA64ISAR0_EL1 -> 0xd5380600 (clean)
	for _, w := range []uint32{0xd2800000, 0xd5380000, 0xd5380600, 0x04225022, 0xd37df042} {
		if !isAuditedARM64WordOpcode(w) {
			t.Errorf("isAuditedARM64WordOpcode(0x%08x) = false, want true", w)
		}
	}
	// MRS X0, MPIDR_EL1 -> 0xd53800a0 (per-core affinity, rejected)
	// MOVZ X18, #0 -> 0xd2800012 (platform reg, rejected)
	// MOVZ X28, #0 -> 0xd280001c (g reg, rejected)
	// UBFM X0, X28, #0, #63 -> 0xd340ff80 (reads g reg, rejected)
	for _, bad := range []uint32{0xd53800a0, 0xd2800012, 0xd280001c, 0xd340ff80, 0xd503201f} {
		if isAuditedARM64WordOpcode(bad) {
			t.Errorf("isAuditedARM64WordOpcode(0x%08x) = true, want false", bad)
		}
	}
}

func TestCPUIDCallReadsPerCoreStateSSA(t *testing.T) {
	t.Parallel()

	src := `package p

func cpuid(op uint32) (eax, ebx, ecx, edx uint32)

func PureLeaf7() uint32 {
	_, ebx, _, _ := cpuid(7)
	return ebx
}

func PureLeaf1MaskedAPIC() uint32 {
	_, ebx, _, _ := cpuid(1)
	return ebx & 0x00ffffff
}

func ImpureLeaf1UnmaskedAPIC() uint32 {
	_, ebx, _, _ := cpuid(1)
	return ebx
}

func ImpureLeaf0B() uint32 {
	_, _, _, edx := cpuid(0x0b)
	return edx
}

func PureBoundedLoop() uint32 {
	var acc uint32
	for leaf := uint32(2); leaf < 5; leaf++ {
		eax, _, _, _ := cpuid(leaf)
		acc ^= eax
	}
	return acc
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	files := []*ast.File{file}
	pkg := types.NewPackage("example.com/p", "p")
	ssaPkg, _, err := ssautil.BuildPackage(&types.Config{Importer: importer.Default()}, fset, pkg, files, ssa.SanityCheckFunctions)
	if err != nil {
		t.Fatal(err)
	}

	checkFunc := func(fnName string, wantPerCore bool) {
		fn := ssaPkg.Func(fnName)
		if fn == nil {
			t.Fatalf("missing SSA func %s", fnName)
		}
		foundCall := false
		for _, blk := range fn.Blocks {
			for _, instr := range blk.Instrs {
				site, ok := instr.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				if callee := site.Common().StaticCallee(); callee != nil && callee.Name() == "cpuid" {
					foundCall = true
					if got := CPUIDCallReadsPerCoreState(site.Common(), site); got != wantPerCore {
						t.Errorf("%s: CPUIDCallReadsPerCoreState = %v, want %v", fnName, got, wantPerCore)
					}
				}
			}
		}
		if !foundCall {
			t.Fatalf("%s: no cpuid call found", fnName)
		}
	}

	checkFunc("PureLeaf7", false)
	checkFunc("PureLeaf1MaskedAPIC", false)
	checkFunc("ImpureLeaf1UnmaskedAPIC", true)
	checkFunc("ImpureLeaf0B", true)
	checkFunc("PureBoundedLoop", false)
}

func TestVerifyNonStdFilesAndCheckVerifiedTypeScopes(t *testing.T) {
	t.Parallel()

	files := map[string]string{
		"lut.h": "#define SHIFT_AMT \\\n\t$4\n",
		"lut.s": `#include "textflag.h"
#include "lut.h"
DATA ·table+0(SB)/8, $0x0102030405060708
GLOBL ·table(SB), RODATA|NOPTR, $8

TEXT ·Kernel(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), R14
	SHLQ SHIFT_AMT, R14
	XORQ ·table+0(SB), R14
	MOVQ R14, ret+8(FP)
	RET
`,
	}
	readMem := func(full string) ([]byte, error) {
		s, ok := files[filepath.Base(full)]
		if !ok {
			return nil, os.ErrNotExist
		}
		return []byte(s), nil
	}
	cleanPkg := types.NewPackage("example.com/p", "p")
	vp, ok := VerifyNonStdFiles("amd64", "example.com/p", "/virtual/p", []string{"lut.s"}, []string{"lut.h"}, []*types.Package{cleanPkg}, readMem)
	if !ok || vp == nil || !vp.OK {
		t.Fatalf("VerifyNonStdFiles failed: ok=%v vp=%+v", ok, vp)
	}
	if !CheckVerifiedTypeScopes(vp, []*types.Package{cleanPkg}) {
		t.Errorf("CheckVerifiedTypeScopes rejected non-colliding scope")
	}
	collidePkg := types.NewPackage("example.com/p", "p")
	collidePkg.Scope().Insert(types.NewVar(token.NoPos, collidePkg, "table", types.Typ[types.Uint64]))
	if CheckVerifiedTypeScopes(vp, []*types.Package{collidePkg}) {
		t.Errorf("CheckVerifiedTypeScopes admitted colliding RODATA symbol")
	}
}
