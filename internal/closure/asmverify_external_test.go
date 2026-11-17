package closure

import (
	"context"
	"fmt"
	"go/token"
	"go/types"
	"runtime"
	"testing"

	"github.com/greatliontech/gofresh/internal/closure/internal/asmverify"
	progpkg "github.com/greatliontech/gofresh/internal/closure/internal/program"
	"pgregory.net/rapid"
)

func TestPropertyAsmLookupTableValueTypeAndASTConfinement(t *testing.T) {
	t.Parallel()

	// Part 1: Compositional type generator checked against an independent
	// memory-layout scalar-only oracle (rejecting string headers, slices,
	// pointers, uintptr, unsafe.Pointer, maps, channels, funcs, and interfaces).
	type layoutNode struct {
		typ       types.Type
		scalarMem bool
	}
	var genLayout func(rt *rapid.T, depth int) layoutNode
	genLayout = func(rt *rapid.T, depth int) layoutNode {
		if depth >= 3 {
			kind := rapid.IntRange(0, 8).Draw(rt, "leaf")
			switch kind {
			case 0:
				return layoutNode{types.Typ[types.Bool], true}
			case 1:
				return layoutNode{types.Typ[types.Uint8], true}
			case 2:
				return layoutNode{types.Typ[types.Int64], true}
			case 3:
				return layoutNode{types.Typ[types.Float64], true}
			case 4:
				return layoutNode{types.Typ[types.Complex128], true}
			case 5:
				// Go string in memory is {Data *byte, Len int} — contains a pointer!
				return layoutNode{types.Typ[types.String], false}
			case 6:
				return layoutNode{types.Typ[types.Uintptr], false}
			case 7:
				return layoutNode{types.Typ[types.UnsafePointer], false}
			default:
				return layoutNode{types.NewInterfaceType(nil, nil), false}
			}
		}
		switch rapid.IntRange(0, 7).Draw(rt, "comb") {
		case 0:
			return genLayout(rt, 3)
		case 1:
			sub := genLayout(rt, depth+1)
			n := int64(rapid.IntRange(0, 4).Draw(rt, "arr_len"))
			return layoutNode{types.NewArray(sub.typ, n), sub.scalarMem}
		case 2:
			nf := rapid.IntRange(0, 3).Draw(rt, "nfields")
			fields := make([]*types.Var, nf)
			ok := true
			for i := 0; i < nf; i++ {
				sub := genLayout(rt, depth+1)
				fields[i] = types.NewField(token.NoPos, nil, fmt.Sprintf("F%d", i), sub.typ, false)
				ok = ok && sub.scalarMem
			}
			return layoutNode{types.NewStruct(fields, nil), ok}
		case 3:
			sub := genLayout(rt, depth+1)
			return layoutNode{types.NewSlice(sub.typ), false}
		case 4:
			sub := genLayout(rt, depth+1)
			return layoutNode{types.NewPointer(sub.typ), false}
		case 5:
			sub := genLayout(rt, depth+1)
			pkg := types.NewPackage("example.com/p", "p")
			tn := types.NewTypeName(token.NoPos, pkg, "Named", nil)
			named := types.NewNamed(tn, sub.typ.Underlying(), nil)
			return layoutNode{named, sub.scalarMem}
		case 6:
			sub := genLayout(rt, depth+1)
			pkg := types.NewPackage("example.com/p", "p")
			tn := types.NewTypeName(token.NoPos, pkg, "Alias", nil)
			return layoutNode{types.NewAlias(tn, sub.typ), sub.scalarMem}
		default:
			return layoutNode{types.NewChan(types.SendRecv, types.Typ[types.Int]), false}
		}
	}

	rapid.Check(t, func(rt *rapid.T) {
		node := genLayout(rt, 0)
		if got := isAsmLookupTableValueType(node.typ); got != node.scalarMem {
			rt.Fatalf("isAsmLookupTableValueType(%s) = %v, oracle = %v", node.typ, got, node.scalarMem)
		}
	})

	// Part 2: Exhaustive package-AST + SSA matrix over global declaration, init
	// helper, generic, async, linkname, and escape combinations using the in-memory frontend.
	type varCase struct {
		name   string
		src    string
		ref    asmverify.ExternalSBRef
		wantOK bool
	}
	tblRef := asmverify.ExternalSBRef{PkgPath: "example.com/p", Name: "Tbl"}
	cases := []varCase{
		{
			name:   "const_array_composite_lit",
			src:    "package p\nvar Tbl = [4]uint64{1, 2, 3, 4}\n",
			ref:    tblRef,
			wantOK: true,
		},
		{
			name:   "const_nested_struct_composite_lit",
			src:    "package p\ntype Entry struct{ A uint32; B [2]byte }\nvar Tbl = [2]Entry{{A: 1, B: [2]byte{2, 3}}, {A: 4}}\n",
			ref:    tblRef,
			wantOK: true,
		},
		{
			name:   "zero_value_unwritten_struct",
			src:    "package p\nvar Tbl struct{ HasAVX2 bool; Mask uint64 }\n",
			ref:    tblRef,
			wantOK: true,
		},
		{
			name:   "init_direct_write_settled",
			src:    "package p\nvar Tbl struct{ HasAVX2 bool }\nfunc init() { Tbl.HasAVX2 = true }\n",
			ref:    tblRef,
			wantOK: true,
		},
		{
			name:   "init_unexported_sync_helper_settled",
			src:    "package p\nvar Tbl [4]byte\nfunc doinit() { Tbl[0] = 7 }\nfunc init() { doinit() }\n",
			ref:    tblRef,
			wantOK: true,
		},
		{
			name:   "nonconst_decl_initializer_settled",
			src:    "package p\nfunc compute() [2]uint32 { return [2]uint32{1, 2} }\nvar Tbl = compute()\n",
			ref:    tblRef,
			wantOK: true,
		},
		{
			name:   "hwcap_readonly_linkname_admitted",
			src:    "package p\nimport _ \"unsafe\"\n// go:linkname is disallowed in user prose comments and must not poison scanning.\n//go:linkname hw internal/cpu.HWCap\nvar hw uint\nfunc Read() uint { return hw }\n",
			ref:    asmverify.ExternalSBRef{PkgPath: "internal/cpu", Name: "HWCap"},
			wantOK: true,
		},
		{
			name:   "prose_spaced_go_linkname_comment_ignored",
			src:    "package p\n// go:linkname is disallowed in user packages.\n/* go:linkname also ignored in block prose */\nvar Tbl = [4]byte{1, 2, 3, 4}\n",
			ref:    tblRef,
			wantOK: true,
		},
		{
			name:   "hwcap_malformed_three_field_linkname_rejected",
			src:    "package p\nimport _ \"unsafe\"\n//go:linkname hw internal/cpu.HWCap extra\nvar hw uint\n",
			ref:    asmverify.ExternalSBRef{PkgPath: "internal/cpu", Name: "HWCap"},
			wantOK: false,
		},
		{
			name:   "hwcap_mutated_linkname_rejected",
			src:    "package p\nimport _ \"unsafe\"\n//go:linkname hw internal/cpu.HWCap\nvar hw uint\nfunc init() { hw = 1 }\n",
			ref:    asmverify.ExternalSBRef{PkgPath: "internal/cpu", Name: "HWCap"},
			wantOK: false,
		},
		{
			name:   "string_global_rejected_pointer_header",
			src:    "package p\nvar Tbl = \"hello\"\n",
			ref:    tblRef,
			wantOK: false,
		},
		{
			name:   "slice_global_rejected",
			src:    "package p\nvar Tbl = []byte{1, 2, 3}\n",
			ref:    tblRef,
			wantOK: false,
		},
		{
			name:   "uintptr_array_rejected",
			src:    "package p\nvar Tbl = [2]uintptr{1, 2}\n",
			ref:    tblRef,
			wantOK: false,
		},
		{
			name:   "post_init_write_rejected",
			src:    "package p\nvar Tbl = [4]byte{1, 2, 3, 4}\nfunc Mut() { Tbl[1] = 9 }\n",
			ref:    tblRef,
			wantOK: false,
		},
		{
			name:   "exported_init_helper_rejected",
			src:    "package p\nvar Tbl [4]byte\nfunc DoInit() { Tbl[0] = 1 }\nfunc init() { DoInit() }\n",
			ref:    tblRef,
			wantOK: false,
		},
		{
			name:   "init_helper_also_called_outside_init_rejected",
			src:    "package p\nvar Tbl [4]byte\nfunc doinit() { Tbl[0] = 1 }\nfunc init() { doinit() }\nfunc Later() { doinit() }\n",
			ref:    tblRef,
			wantOK: false,
		},
		{
			name:   "init_helper_called_by_uninstantiated_generic_rejected",
			src:    "package p\nvar Tbl [4]byte\nfunc doinit() { Tbl[0] = 1 }\nfunc init() { doinit() }\nfunc Gen[T any]() { doinit() }\n",
			ref:    tblRef,
			wantOK: false,
		},
		{
			name:   "init_go_goroutine_helper_rejected",
			src:    "package p\nvar Tbl [4]byte\nfunc doinit() { Tbl[0] = 1 }\nfunc init() { go doinit() }\n",
			ref:    tblRef,
			wantOK: false,
		},
		{
			name:   "init_closure_write_rejected",
			src:    "package p\nvar Tbl [4]byte\nfunc init() { f := func() { Tbl[0] = 1 }; f() }\n",
			ref:    tblRef,
			wantOK: false,
		},
		{
			name:   "addr_escape_rejected",
			src:    "package p\nvar Tbl = [4]byte{1, 2, 3, 4}\nvar Ptr = &Tbl\n",
			ref:    tblRef,
			wantOK: false,
		},
		{
			name:   "slice_expr_escape_rejected",
			src:    "package p\nvar Tbl = [4]byte{1, 2, 3, 4}\nfunc View() []byte { return Tbl[:] }\n",
			ref:    tblRef,
			wantOK: false,
		},
		{
			name:   "uninstantiated_generic_direct_write_rejected",
			src:    "package p\nvar Tbl = [4]byte{1, 2, 3, 4}\nfunc Gen[T any]() { Tbl[0] = 9 }\n",
			ref:    tblRef,
			wantOK: false,
		},
		{
			name:   "uninstantiated_generic_ptr_recv_method_rejected",
			src:    "package p\ntype Box struct{ N uint64 }\nfunc (b *Box) Touch() { b.N = 9 }\nvar Tbl = Box{N: 1}\nfunc Gen[T ~int](x T) T { Tbl.Touch(); return x + 1 }\n",
			ref:    tblRef,
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prog, _, pkgs := buildInMemorySSA(t, t.TempDir(), "example.com/p", map[string]map[string]string{
				"example.com/p": {"p.go": tc.src},
			})
			prog.GOARCH = runtime.GOARCH
			if tc.name == "uninstantiated_generic_ptr_recv_method_rejected" {
				vObj := pkgs[0].Types.Scope().Lookup("Tbl").(*types.Var)
				if verifyPackageVarASTConfinement(pkgs[0], vObj, true, nil) {
					t.Fatal("verifyPackageVarASTConfinement admitted auto-addressed pointer-receiver method on Tbl")
				}
			}
			vars, ok := classifyAsmExternalGlobalInProg(true, prog, tc.ref)
			if ok != tc.wantOK {
				t.Fatalf("classifyAsmExternalGlobalInProg(%s) = (vars=%d, ok=%v), want ok=%v",
					tc.name, len(vars), ok, tc.wantOK)
			}
			if ok && tc.ref.PkgPath != "internal/cpu" && len(vars) == 0 {
				t.Fatalf("%s: expected non-empty []*types.Var for dependency tracking", tc.name)
			}
		})
	}
}

func TestNonStdAsmLookupTablesCPUGlobalsAndPerTextSplitEndToEnd(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("non-std assembly verification targets amd64 and arm64; got %s", runtime.GOARCH)
	}

	root := t.TempDir()
	writeFile(t, root, "go.mod", "module example.com/e2easm\n\ngo 1.24\n")

	// 1. Cross-package constant lookup table (zero init() writes).
	writeFile(t, root, "tables/tables.go", `package tables

var SBox = [8]byte{11, 22, 33, 44, 55, 66, 77, 88}
`)

	// 2. Kernel package using same-package + cross-package lookup tables, BTQ,
	// intra-package CALL helper<>(SB) + tail JMP/B ·tailAdd(SB).
	writeFile(t, root, "kernel/kernel.go", `package kernel

import _ "example.com/e2easm/tables"

var localLut = [4]uint64{100, 200, 300, 400}

func LookupMix(i uint64) uint64

func UseLookup(i uint64) uint64 {
	return LookupMix(i)
}
`)
	writeFile(t, root, "kernel/kernel_amd64.s", `//go:build amd64

#include "textflag.h"

TEXT helper<>(SB), NOSPLIT, $0-0
	LEAQ ·localLut(SB), R8
	MOVQ 0(R8), CX
	ADDQ CX, AX
	RET

TEXT ·tailAdd(SB), NOSPLIT, $0-16
	MOVQ AX, ret+8(FP)
	RET

TEXT ·LookupMix(SB), NOSPLIT, $0-16
	MOVQ i+0(FP), AX
	ANDQ $7, AX
	LEAQ example.com∕e2easm∕tables·SBox(SB), R9
	BTQ $0, 0(R9)
	MOVBLZX 0(R9)(AX*1), AX
	CALL helper<>(SB)
	JMP ·tailAdd(SB)
`)
	writeFile(t, root, "kernel/kernel_arm64.s", `//go:build arm64

#include "textflag.h"

TEXT helper<>(SB), NOSPLIT, $0-0
	MOVD $·localLut(SB), R8
	MOVD (R8), R2
	ADD R2, R0, R0
	RET

TEXT ·tailAdd(SB), NOSPLIT, $0-16
	MOVD R0, ret+8(FP)
	RET

TEXT ·LookupMix(SB), NOSPLIT, $0-16
	MOVD i+0(FP), R0
	AND $7, R0, R0
	MOVD $example.com∕e2easm∕tables·SBox(SB), R9
	ADD R0, R9, R9
	MOVBU (R9), R0
	BL helper<>(SB)
	B ·tailAdd(SB)
`)

	// Enumerated-root caller of pure lookup-table assembly (sealed unexported interface).
	writeFile(t, root, "widenlut/widenlut.go", `package widenlut

import "example.com/e2easm/kernel"

type runner interface{ M() uint64 }

type box struct{}

func (box) M() uint64 { return kernel.UseLookup(2) }

var _ runner = box{}

func WidenedLookup(r runner) uint64 {
	return r.M()
}

func CallWidened() uint64 {
	return WidenedLookup(box{})
}
`)

	// 3. CPU-feature struct populated in init() via unexported doinit() +
	// cross-package reader + writer-free internal/cpu.HWCap reader.
	writeFile(t, root, "cpufeat/cpufeat.go", `package cpufeat

var Features struct {
	HasFast bool
	Mask    uint32
}

func queryChip(op uint32) (eax, ebx, ecx, edx uint32)
func readFastFlag() bool

func doinit() {
	eax, _, _, _ := queryChip(0)
	Features.Mask = eax
	Features.HasFast = (eax & 1) != 0
}

func init() {
	doinit()
}

func FastFlag() bool {
	return readFastFlag()
}
`)
	writeFile(t, root, "cpufeat/cpufeat_amd64.s", `//go:build amd64

#include "textflag.h"

TEXT ·queryChip(SB), NOSPLIT, $0-24
	MOVL op+0(FP), AX
	XORQ CX, CX
	CPUID
	MOVL AX, eax+8(FP)
	MOVL BX, ebx+12(FP)
	MOVL CX, ecx+16(FP)
	MOVL DX, edx+20(FP)
	RET

TEXT ·readFastFlag(SB), NOSPLIT, $0-1
	MOVBLZX ·Features+0(SB), AX
	MOVB AX, ret+0(FP)
	RET
`)
	writeFile(t, root, "cpufeat/cpufeat_arm64.s", `//go:build arm64

#include "textflag.h"

TEXT ·queryChip(SB), NOSPLIT, $0-24
	MRS MIDR_EL1, R0
	MOVW R0, eax+8(FP)
	MOVW ZR, ebx+12(FP)
	MOVW ZR, ecx+16(FP)
	MOVW ZR, edx+20(FP)
	RET

TEXT ·readFastFlag(SB), NOSPLIT, $0-1
	MOVBU ·Features+0(SB), R0
	MOVB R0, ret+0(FP)
	RET
`)

	writeFile(t, root, "cpureader/cpureader.go", `package cpureader

import _ "example.com/e2easm/cpufeat"

func crossMask() uint32
func readHWCap() uint

func CrossMask() uint32 { return crossMask() }
func HasHWCapBit() bool { return readHWCap() != 0 }
`)
	writeFile(t, root, "cpureader/cpureader_amd64.s", `//go:build amd64

#include "textflag.h"

TEXT ·crossMask(SB), NOSPLIT, $0-4
	MOVL example.com∕e2easm∕cpufeat·Features+4(SB), AX
	MOVL AX, ret+0(FP)
	RET

TEXT ·readHWCap(SB), NOSPLIT, $0-8
	MOVQ internal∕cpu·HWCap(SB), AX
	MOVQ AX, ret+0(FP)
	RET
`)
	writeFile(t, root, "cpureader/cpureader_arm64.s", `//go:build arm64

#include "textflag.h"

TEXT ·crossMask(SB), NOSPLIT, $0-4
	MOVWU example.com∕e2easm∕cpufeat·Features+4(SB), R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·readHWCap(SB), NOSPLIT, $0-8
	MOVD internal∕cpu·HWCap(SB), R0
	MOVD R0, ret+0(FP)
	RET
`)

	// 4. Cross-package constant lookup table reached ONLY via .s (verifying
	// scanVerifiedAsmBodylessFunction enqueueObject(v)), plus negative control
	// stdlib internal/cpu.X86 / internal/cpu.ARM64 (unlogged GODEBUG hazard).
	writeFile(t, root, "exttables/exttables.go", `package exttables

var ExtSBox = [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
`)
	writeFile(t, root, "extkernel/extkernel.go", `package extkernel

import _ "example.com/e2easm/exttables"

func ExportedAsmExt() byte
func ReadExt() byte { return ExportedAsmExt() }
`)
	writeFile(t, root, "extkernel/extkernel_amd64.s", `//go:build amd64

#include "textflag.h"

TEXT ·ExportedAsmExt(SB), NOSPLIT, $0-1
	MOVB example.com∕e2easm∕exttables·ExtSBox+0(SB), AX
	MOVB AX, ret+0(FP)
	RET
`)
	writeFile(t, root, "extkernel/extkernel_arm64.s", `//go:build arm64

#include "textflag.h"

TEXT ·ExportedAsmExt(SB), NOSPLIT, $0-1
	MOVBU example.com∕e2easm∕exttables·ExtSBox+0(SB), R0
	MOVB R0, ret+0(FP)
	RET
`)
	writeFile(t, root, "badstdcpu/badstdcpu.go", `package badstdcpu

func readStdCPU() byte
func ReadStdCPU() byte { return readStdCPU() }
`)
	writeFile(t, root, "badstdcpu/badstdcpu_amd64.s", `//go:build amd64

#include "textflag.h"

TEXT ·readStdCPU(SB), NOSPLIT, $0-1
	MOVB internal∕cpu·X86+0(SB), AX
	MOVB AX, ret+0(FP)
	RET
`)
	writeFile(t, root, "badstdcpu/badstdcpu_arm64.s", `//go:build arm64

#include "textflag.h"

TEXT ·readStdCPU(SB), NOSPLIT, $0-1
	MOVBU internal∕cpu·ARM64+0(SB), R0
	MOVB R0, ret+0(FP)
	RET
`)

	// 5. PackageSafe && !AllTextsVerified split:
	// - Pure-Go init() sets InitOK = true (must NOT poison startupSummary!).
	// - FastPure calls intra-package fastHelper (Verified == true).
	// - BadCorrupt writes to ·InitOK(SB) (Verified == false -> AllTextsVerified == false).
	// - Both UseFastPure and cross-package cleanimp.RunClean MUST carry
	//   RequiresSingleSubject == true (protecting both PackageExecution and GeneralExecution).
	writeFile(t, root, "mixedpkg/mixedpkg.go", `package mixedpkg

var InitOK bool

func init() {
	InitOK = true
}

func FastPure(x uint64) uint64
func BadCorrupt()

func UseFastPure(x uint64) uint64 { return FastPure(x) }
func UseBadCorrupt()              { BadCorrupt() }
`)
	writeFile(t, root, "mixedpkg/mixedpkg_amd64.s", `//go:build amd64

#include "textflag.h"

TEXT ·fastHelper(SB), NOSPLIT, $0-0
	ADDQ $5, AX
	RET

TEXT ·FastPure(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), AX
	CALL ·fastHelper(SB)
	MOVQ AX, ret+8(FP)
	RET

TEXT ·BadCorrupt(SB), NOSPLIT, $0-0
	MOVB $0, ·InitOK(SB)
	RET
`)
	writeFile(t, root, "mixedpkg/mixedpkg_arm64.s", `//go:build arm64

#include "textflag.h"

TEXT ·fastHelper(SB), NOSPLIT, $0-0
	ADD $5, R0, R0
	RET

TEXT ·FastPure(SB), NOSPLIT, $0-16
	MOVD x+0(FP), R0
	BL ·fastHelper(SB)
	MOVD R0, ret+8(FP)
	RET

TEXT ·BadCorrupt(SB), NOSPLIT, $0-0
	MOVB ZR, ·InitOK(SB)
	RET
`)

	writeFile(t, root, "cleanimp/cleanimp.go", `package cleanimp

import "example.com/e2easm/mixedpkg"

func RunClean() uint64 {
	if !mixedpkg.InitOK {
		return 0
	}
	return mixedpkg.UseFastPure(10)
}
`)

	// 6. Unverified raw opcode (`BYTE` / `WORD`) MUST set Verified=false and
	// AllTextsVerified=false, disqualifying in-package lookup tables (`RawReadLocalLut`)
	// and keeping startup zero-global write-hazard gates fail-closed (`mixedzero`).
	writeFile(t, root, "rawcorrupt/rawcorrupt.go", `package rawcorrupt

import _ "example.com/e2easm/tables"

var LocalLut = [4]uint64{1, 2, 3, 4}

func RawOp()
func ReadLocalLut() uint64
func ReadCrossLut() byte

func UseReadLocalLut() uint64 { return ReadLocalLut() }
func UseReadCrossLut() byte   { return ReadCrossLut() }
`)
	writeFile(t, root, "rawcorrupt/rawcorrupt_amd64.s", `//go:build amd64

#include "textflag.h"

TEXT ·RawOp(SB), NOSPLIT, $0-0
	BYTE $0x90
	RET

TEXT ·ReadLocalLut(SB), NOSPLIT, $0-8
	MOVQ ·LocalLut+0(SB), AX
	MOVQ AX, ret+0(FP)
	RET

TEXT ·ReadCrossLut(SB), NOSPLIT, $0-1
	MOVB example.com∕e2easm∕tables·SBox+0(SB), AX
	MOVB AX, ret+0(FP)
	RET
`)
	writeFile(t, root, "rawcorrupt/rawcorrupt_arm64.s", `//go:build arm64

#include "textflag.h"

TEXT ·RawOp(SB), NOSPLIT, $0-0
	WORD $0xd503201f
	RET

TEXT ·ReadLocalLut(SB), NOSPLIT, $0-8
	MOVD ·LocalLut+0(SB), R0
	MOVD R0, ret+0(FP)
	RET

TEXT ·ReadCrossLut(SB), NOSPLIT, $0-1
	MOVBU example.com∕e2easm∕tables·SBox+0(SB), R0
	MOVB R0, ret+0(FP)
	RET
`)

	writeFile(t, root, "mixedzero/mixedzero.go", `package mixedzero

import "os"

var zeroGate uint64

func init() {
	if zeroGate != 0 {
		os.Exit(1)
	}
}

func FastId(x uint64) uint64
func BadClobberZero()

func PureSubject() uint64 { return FastId(7) }
`)
	writeFile(t, root, "mixedzero/mixedzero_amd64.s", `//go:build amd64

#include "textflag.h"

TEXT ·FastId(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), AX
	MOVQ AX, ret+8(FP)
	RET

TEXT ·BadClobberZero(SB), NOSPLIT, $0-0
	MOVQ $1, ·zeroGate(SB)
	RET
`)
	writeFile(t, root, "mixedzero/mixedzero_arm64.s", `//go:build arm64

#include "textflag.h"

TEXT ·FastId(SB), NOSPLIT, $0-16
	MOVD x+0(FP), R0
	MOVD R0, ret+8(FP)
	RET

TEXT ·BadClobberZero(SB), NOSPLIT, $0-0
	MOVD R0, ·zeroGate(SB)
	RET
`)

	h, err := newAt(root)
	if err != nil {
		t.Fatalf("newAt: %v", err)
	}

	sKernel := Subject{Package: "example.com/e2easm/kernel", Symbol: "UseLookup"}
	sWidenLut := Subject{Package: "example.com/e2easm/widenlut", Symbol: "WidenedLookup"}
	sFastFlag := Subject{Package: "example.com/e2easm/cpufeat", Symbol: "FastFlag"}
	sCrossMask := Subject{Package: "example.com/e2easm/cpureader", Symbol: "CrossMask"}
	sHWCap := Subject{Package: "example.com/e2easm/cpureader", Symbol: "HasHWCapBit"}
	sBadStdCPU := Subject{Package: "example.com/e2easm/badstdcpu", Symbol: "ReadStdCPU"}
	sExtKernel := Subject{Package: "example.com/e2easm/extkernel", Symbol: "ReadExt"}
	sExtBodyless := Subject{Package: "example.com/e2easm/extkernel", Symbol: "ExportedAsmExt"}
	sCleanImp := Subject{Package: "example.com/e2easm/cleanimp", Symbol: "RunClean"}
	sMixFast := Subject{Package: "example.com/e2easm/mixedpkg", Symbol: "UseFastPure"}
	sMixBad := Subject{Package: "example.com/e2easm/mixedpkg", Symbol: "UseBadCorrupt"}
	sRawLocal := Subject{Package: "example.com/e2easm/rawcorrupt", Symbol: "UseReadLocalLut"}
	sRawCross := Subject{Package: "example.com/e2easm/rawcorrupt", Symbol: "UseReadCrossLut"}
	sMixZero := Subject{Package: "example.com/e2easm/mixedzero", Symbol: "PureSubject"}

	allSubjs := []Subject{
		sKernel, sWidenLut, sFastFlag, sCrossMask, sHWCap,
		sBadStdCPU, sExtKernel, sExtBodyless, sCleanImp, sMixFast, sMixBad,
		sRawLocal, sRawCross, sMixZero,
	}
	proofs, err := h.ComputeObservabilityBatch(allSubjs)
	if err != nil {
		t.Fatalf("ComputeObservabilityBatch: %v", err)
	}

	// Verify 1: kernel.UseLookup & enumerated-root widenlut.WidenedLookup.
	for _, s := range []Subject{sKernel, sWidenLut, sFastFlag, sCrossMask, sHWCap} {
		if obs := proofs[s]; !obs.Observable || !obs.EffectFree || obs.RequiresSingleSubject {
			t.Fatalf("%v = %+v, want Observable && EffectFree && !RequiresSingleSubject", s, obs)
		}
	}

	// Verify Tier-1 MaximalClosure continues to treat all non-toolchain .s packages as Unverifiable.
	maxBatch, _, err := h.ComputeMaximalBatch([]Subject{sKernel, sFastFlag})
	if err != nil {
		t.Fatalf("ComputeMaximalBatch: %v", err)
	}
	for _, s := range []Subject{sKernel, sFastFlag} {
		if !maxBatch[s].Unverifiable {
			t.Fatalf("ComputeMaximalBatch(%v) = %+v, want Unverifiable=true at Tier 1", s, maxBatch[s])
		}
	}
	hashBefore := maxBatch[sKernel].Hash

	// Verify 2: Negative control internal/cpu.X86 / ARM64 must refuse, while both
	// direct bodyless root (`ExportedAsmExt`) and Go caller (`ReadExt`) admit AND
	// enqueue `exttables.ExtSBox` into Tier-2 `subjectObjects`!
	if obs := proofs[sBadStdCPU]; obs.Observable {
		t.Fatalf("badstdcpu.ReadStdCPU = %+v, want !Observable (unlogged GODEBUG hazard)", obs)
	}
	for _, s := range []Subject{sExtKernel, sExtBodyless} {
		if obs := proofs[s]; !obs.Observable || !obs.EffectFree {
			t.Fatalf("%v = %+v, want Observable && EffectFree", s, obs)
		}
	}
	h.resetCallScope()
	extProg, err := progpkg.Load(t.Context(), h.dir, h.packageEnv, h.buildFlags, "example.com/e2easm/extkernel")
	if err != nil {
		t.Fatalf("progpkg.Load(extkernel): %v", err)
	}
	h.bindProgramReader(extProg)
	extMetas, err := h.list("example.com/e2easm/extkernel")
	if err != nil {
		t.Fatalf("h.list(extkernel): %v", err)
	}
	extBase := newTier2Base(h, extProg, extMetas)
	extReaches, err := attributedReachableSets(t.Context(), h.SelectionAudited(), h.source.pureDelegates, extBase.prog, []Subject{sExtKernel, sExtBodyless})
	if err != nil {
		t.Fatalf("attributedReachableSets(extkernel): %v", err)
	}
	for i, sr := range extReaches {
		sr.functions = sr.subjectFunctions
		res, objs, err := h.tier2ReachableWithObjects(extBase, sr)
		if err != nil {
			t.Fatalf("tier2ReachableWithObjects[%d]: %v", i, err)
		}
		if res.widen || res.unverifiable || len(res.effects) != 0 {
			t.Fatalf("tier2ReachableWithObjects[%d] = %+v, want clean closed result", i, res)
		}
		foundExtVar := false
		for obj := range objs {
			if obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "example.com/e2easm/exttables" && obj.Name() == "ExtSBox" {
				foundExtVar = true
				break
			}
		}
		if !foundExtVar {
			t.Fatalf("subject[%d] subjectObjects did not include example.com/e2easm/exttables.ExtSBox", i)
		}
	}

	// Verify 3: PackageSafe && !AllTextsVerified split & raw-opcode write hazards:
	// - Both cleanimp.RunClean and mixedpkg.UseFastPure carry RequiresSingleSubject=true
	//   (refusing shared-process GeneralExecution / PackageExecution while admitting SingleSubjectExecution).
	// - rawcorrupt.UseReadLocalLut refuses (!Observable) because RawOp leaves AllTextsVerified=false
	//   on rawcorrupt, disqualifying LocalLut from lookup-table immutability!
	// - rawcorrupt.UseReadCrossLut (reading tables.SBox in pure tables pkg) admits with RequiresSingleSubject=true.
	// - mixedzero.PureSubject refuses (!Observable) because !AllTextsVerified blocks startup zero-global pruning.
	for _, tc := range []struct {
		subj    Subject
		wantPkg string
	}{
		{sCleanImp, "example.com/e2easm/mixedpkg"},
		{sMixFast, "example.com/e2easm/mixedpkg"},
		{sRawCross, "example.com/e2easm/rawcorrupt"},
	} {
		obs := proofs[tc.subj]
		wantReason := "package scan: reaches unverified non-standard assembly in " + tc.wantPkg
		if !obs.Observable || !obs.EffectFree || !obs.RequiresSingleSubject || obs.SharedProcessUnsafeReason != wantReason {
			t.Fatalf("%v = %+v, want Observable && EffectFree && RequiresSingleSubject=true && SharedProcessUnsafeReason=%q", tc.subj, obs, wantReason)
		}
	}
	for _, s := range []Subject{sMixBad, sRawLocal, sMixZero} {
		if obs := proofs[s]; obs.Observable {
			t.Fatalf("%v = %+v, want !Observable", s, obs)
		}
	}

	// Verify RootedFunctions completeness across all positive and negative entrypoints.
	rf, err := h.ComputeRootedFunctions(context.Background(), []Subject{
		sKernel, sFastFlag, sCrossMask, sHWCap, sCleanImp, sMixFast, sMixBad, sRawLocal, sRawCross, sBadStdCPU,
	})
	if err != nil {
		t.Fatalf("ComputeRootedFunctions: %v", err)
	}
	for _, s := range []Subject{sKernel, sFastFlag, sCrossMask, sHWCap, sCleanImp, sMixFast, sRawCross} {
		if !rf[s].Complete {
			t.Fatalf("ComputeRootedFunctions(%v).Complete = false, want true", s)
		}
	}
	for _, s := range []Subject{sMixBad, sRawLocal, sBadStdCPU} {
		if rf[s].Complete {
			t.Fatalf("ComputeRootedFunctions(%v).Complete = true, want false", s)
		}
	}

	// Verify closure hash sensitivity on cross-package lookup-table edits.
	writeFile(t, root, "tables/tables.go", `package tables

var SBox = [8]byte{99, 22, 33, 44, 55, 66, 77, 88}
`)
	hAfter, err := newAt(root)
	if err != nil {
		t.Fatalf("newAt after edit: %v", err)
	}
	maxAfter, _, err := hAfter.ComputeMaximalBatch([]Subject{sKernel})
	if err != nil {
		t.Fatalf("ComputeMaximalBatch after edit: %v", err)
	}
	if hashBefore == "" || maxAfter[sKernel].Hash == "" || hashBefore == maxAfter[sKernel].Hash {
		t.Fatalf("cross-package (SB) lookup table edit did not change closure hash: before=%q after=%q", hashBefore, maxAfter[sKernel].Hash)
	}

	// Dotless user module defining package "internal/cpu" (`pkg.Module != nil && !idx.std`)
	// must NOT take the stdlib `internal/cpu.HWCap` fast path: post-init mutation of
	// `internal/cpu.HWCap` must refuse observability!
	dotlessRoot := t.TempDir()
	writeFile(t, dotlessRoot, "go.mod", "module internal\n\ngo 1.24\n")
	writeFile(t, dotlessRoot, "cpu/cpu.go", `package cpu

var HWCap uint

func Mutate() { HWCap = 42 }
`)
	writeFile(t, dotlessRoot, "reader/reader.go", `package reader

import "internal/cpu"

func asmReadHWCap() uint

func ReadUserHWCap() uint {
	_ = cpu.Mutate
	return asmReadHWCap()
}
`)
	writeFile(t, dotlessRoot, "reader/reader_amd64.s", `//go:build amd64

#include "textflag.h"

TEXT ·asmReadHWCap(SB), NOSPLIT, $0-8
	MOVQ internal∕cpu·HWCap(SB), AX
	MOVQ AX, ret+0(FP)
	RET
`)
	writeFile(t, dotlessRoot, "reader/reader_arm64.s", `//go:build arm64

#include "textflag.h"

TEXT ·asmReadHWCap(SB), NOSPLIT, $0-8
	MOVD internal∕cpu·HWCap(SB), R0
	MOVD R0, ret+0(FP)
	RET
`)
	hDotless, err := newAt(dotlessRoot)
	if err != nil {
		t.Fatalf("newAt(dotlessRoot): %v", err)
	}
	sDotless := Subject{Package: "internal/reader", Symbol: "ReadUserHWCap"}
	dotlessProofs, err := hDotless.ComputeObservabilityBatch([]Subject{sDotless})
	if err != nil {
		t.Fatalf("ComputeObservabilityBatch(dotless): %v", err)
	}
	if dotlessProofs[sDotless].Observable {
		t.Fatalf("dotless user module internal/cpu.HWCap post-init mutation admitted: %+v", dotlessProofs[sDotless])
	}

	// Intra-package CALL / BL to a `#ifdef UNDEFINED_MACRO` `TEXT ·helper(SB)` that
	// resolves at link time to a Go-bodied function (`helperInGo`) or an audited pull
	// `//go:linkname` (`helperLink` -> `runtime.vgetrandom`) must refuse observability,
	// refuse `ComputeRootedFunctions.Complete`, and mark `RequiresSingleSubject = true`
	// on clean siblings in the binary!
	shadowRoot := t.TempDir()
	writeFile(t, shadowRoot, "go.mod", "module example.com/shadowasm\n\ngo 1.24\n")
	writeFile(t, shadowRoot, "p/p.go", `package p

import (
	"time"
	_ "unsafe"
)

var MutatedGlobal func() = func() {}

func helperInGo() int64 {
	MutatedGlobal = func() {}
	return time.Now().UnixNano()
}

//go:linkname helperLink runtime.vgetrandom
func helperLink(buf []byte, flags uint64) (int, bool)

func AsmCallsGoShadow() int64
func AsmCallsLinkShadow() int64
func CleanSibling() int64

func CallGoShadow() int64     { return AsmCallsGoShadow() }
func CallLinkShadow() int64   { return AsmCallsLinkShadow() }
func CallCleanSibling() int64 { return CleanSibling() }
`)
	writeFile(t, shadowRoot, "p/p_amd64.s", `//go:build amd64

#include "textflag.h"

#ifdef UNDEFINED_MACRO
TEXT ·helperInGo(SB), NOSPLIT, $0-8
	MOVQ $0, ret+0(FP)
	RET

TEXT ·helperLink(SB), NOSPLIT, $0-32
	MOVQ $0, ret+24(FP)
	RET
#endif

TEXT ·AsmCallsGoShadow(SB), NOSPLIT, $0-8
	CALL ·helperInGo(SB)
	MOVQ $0, ret+0(FP)
	RET

TEXT ·AsmCallsLinkShadow(SB), NOSPLIT, $0-8
	CALL ·helperLink(SB)
	MOVQ $0, ret+0(FP)
	RET

TEXT ·CleanSibling(SB), NOSPLIT, $0-8
	MOVQ $7, AX
	MOVQ AX, ret+0(FP)
	RET
`)
	writeFile(t, shadowRoot, "p/p_arm64.s", `//go:build arm64

#include "textflag.h"

#ifdef UNDEFINED_MACRO
TEXT ·helperInGo(SB), NOSPLIT, $0-8
	MOVD ZR, ret+0(FP)
	RET

TEXT ·helperLink(SB), NOSPLIT, $0-32
	MOVD ZR, ret+24(FP)
	RET
#endif

TEXT ·AsmCallsGoShadow(SB), NOSPLIT, $0-8
	BL ·helperInGo(SB)
	MOVD ZR, ret+0(FP)
	RET

TEXT ·AsmCallsLinkShadow(SB), NOSPLIT, $0-8
	BL ·helperLink(SB)
	MOVD ZR, ret+0(FP)
	RET

TEXT ·CleanSibling(SB), NOSPLIT, $0-8
	MOVD $7, R0
	MOVD R0, ret+0(FP)
	RET
`)
	hShadow, err := newAt(shadowRoot)
	if err != nil {
		t.Fatalf("newAt(shadowRoot): %v", err)
	}
	sGoShadow := Subject{Package: "example.com/shadowasm/p", Symbol: "CallGoShadow"}
	sLinkShadow := Subject{Package: "example.com/shadowasm/p", Symbol: "CallLinkShadow"}
	sCleanSib := Subject{Package: "example.com/shadowasm/p", Symbol: "CallCleanSibling"}
	shadowProofs, err := hShadow.ComputeObservabilityBatch([]Subject{sGoShadow, sLinkShadow, sCleanSib})
	if err != nil {
		t.Fatalf("ComputeObservabilityBatch(shadow): %v", err)
	}
	for _, s := range []Subject{sGoShadow, sLinkShadow} {
		if shadowProofs[s].Observable {
			t.Fatalf("%v = %+v, want !Observable", s, shadowProofs[s])
		}
	}
	wantShadowReason := "package scan: reaches unverified non-standard assembly in example.com/shadowasm/p"
	if obs := shadowProofs[sCleanSib]; !obs.Observable || !obs.EffectFree || !obs.RequiresSingleSubject || obs.SharedProcessUnsafeReason != wantShadowReason {
		t.Fatalf("CallCleanSibling = %+v, want Observable && EffectFree && RequiresSingleSubject=true && SharedProcessUnsafeReason=%q", obs, wantShadowReason)
	}
	shadowRF, err := hShadow.ComputeRootedFunctions(context.Background(), []Subject{sGoShadow, sLinkShadow, sCleanSib})
	if err != nil {
		t.Fatalf("ComputeRootedFunctions(shadow): %v", err)
	}
	for _, s := range []Subject{sGoShadow, sLinkShadow} {
		if shadowRF[s].Complete {
			t.Fatalf("ComputeRootedFunctions(%v).Complete = true, want false", s)
		}
	}
	if !shadowRF[sCleanSib].Complete {
		t.Fatalf("ComputeRootedFunctions(CallCleanSibling).Complete = false, want true")
	}
}
