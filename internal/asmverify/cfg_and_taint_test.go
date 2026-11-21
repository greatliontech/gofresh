package asmverify

import (
	"fmt"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func memReader(files map[string]string) func(string) ([]byte, error) {
	return func(full string) ([]byte, error) {
		s, ok := files[filepath.Base(full)]
		if !ok {
			return nil, os.ErrNotExist
		}
		return []byte(s), nil
	}
}

func TestAsmBlockCFGFalloffTaintBTAndIntraCallMatrix(t *testing.T) {
	t.Parallel()

	const roHeader = "#include \"textflag.h\"\nGLOBL ·ro(SB), RODATA, $16\nDATA ·ro+0(SB)/8, $0x0102030405060708\nDATA ·ro+8(SB)/8, $0x1112131415161718\n"

	validCases := []struct {
		name string
		arch string
		body string
	}{
		{
			name: "bt_family_readonly_on_sb_and_tainted_deref",
			arch: "amd64",
			body: roHeader + `
TEXT ·F(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), AX
	BTQ AX, ·ro(SB)
	BTL $3, ·ro+4(SB)
	BTW $1, ·ro+2(SB)
	BT AX, ·ro(SB)
	LEAQ ·ro(SB), R8
	BTQ AX, 0(R8)
	JCC zero
	MOVQ $1, ret+8(FP)
	RET
zero:
	MOVQ $0, ret+8(FP)
	RET
`,
		},
		{
			name: "cfg_ifdef_else_both_return",
			arch: "amd64",
			body: roHeader + `
TEXT ·F(SB), NOSPLIT, $0-8
#ifdef USE_FAST
	MOVQ $1, ret+0(FP)
	RET
#else
	MOVQ $2, ret+0(FP)
	RET
#endif
`,
		},
		{
			name: "cfg_inbounds_pc_relative_forward_and_backward",
			arch: "amd64",
			body: roHeader + `
TEXT ·F(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), AX
	CMPQ AX, $0
	JEQ 3(PC)
	SUBQ $1, AX
	JNE -1(PC)
	MOVQ AX, ret+8(FP)
	RET
`,
		},
		{
			name: "amd64_leaq_movq_index_load_and_flag_overwrite",
			arch: "amd64",
			body: roHeader + `
TEXT ·F(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), AX
	ANDQ $7, AX
	LEAQ ·ro(SB), R8
	LEAQ 4(R8)(AX*1), R9
	MOVBLZX (R9), CX
	MOVQ $·ro(SB), R10
	ADDQ AX, R10
	MOVB (R10), DL
	XORL BX, BX
	CMPQ CX, $0
	JEQ finish
	ADDQ $1, BX
finish:
	MOVQ BX, ret+8(FP)
	RET
`,
		},
		{
			name: "amd64_fullwidth_load_and_xor_self_clear_taint",
			arch: "amd64",
			body: roHeader + `
TEXT ·F(SB), NOSPLIT, $0-16
	LEAQ ·ro(SB), R8
	MOVQ (R8), R8
	LEAQ ·ro+8(SB), R9
	XORL R9, R9
	ADDQ R9, R8
	MOVQ R8, ret+8(FP)
	RET
`,
		},
		{
			name: "arm64_movd_addr_add_load_and_overwrite_clear",
			arch: "arm64",
			body: roHeader + `
TEXT ·F(SB), NOSPLIT, $0-16
	MOVD x+0(FP), R0
	AND $7, R0, R0
	MOVD $·ro(SB), R8
	ADD R0, R8, R9
	MOVBU (R9), R1
	MOVD $·ro+8(SB), R10
	MOVD (R10), R10
	ADD R1, R10, R10
	MOVD R10, ret+8(FP)
	RET
`,
		},
		{
			name: "amd64_intrapkg_call_jmp_and_static_helper",
			arch: "amd64",
			body: roHeader + `
TEXT localMix<>(SB), NOSPLIT, $0-0
	XORQ $0x55, AX
	RET

TEXT ·tailStore(SB), NOSPLIT, $0-16
	MOVQ AX, ret+8(FP)
	RET

TEXT ·F(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), AX
	CALL localMix<>(SB)
	JMP ·tailStore(SB)
`,
		},
		{
			name: "arm64_intrapkg_bl_and_tail_b",
			arch: "arm64",
			body: roHeader + `
TEXT localStep<>(SB), NOSPLIT, $0-0
	ADD $3, R0, R0
	RET

TEXT ·tailFinish(SB), NOSPLIT, $0-16
	MOVD R0, ret+8(FP)
	RET

TEXT ·F(SB), NOSPLIT, $0-16
	MOVD x+0(FP), R0
	BL localStep<>(SB)
	B ·tailFinish(SB)
`,
		},
	}

	for _, tc := range validCases {
		t.Run("valid_"+tc.name, func(t *testing.T) {
			vp, ok := VerifyNonStdFiles(tc.arch, "example.com/p", "/virtual/p", []string{"k.s"}, nil, nil, memReader(map[string]string{"k.s": tc.body}))
			if !ok || vp == nil || !vp.PackageSafe || !vp.AllTextsVerified {
				t.Fatalf("VerifyNonStdFiles(%s) failed: ok=%v vp=%+v", tc.name, ok, vp)
			}
			sum, found := vp.Funcs["F"]
			if !found || !sum.Verified || sum.ImpureKind != "" {
				t.Fatalf("Funcs[F] = %+v (found=%v), want Verified && pure", sum, found)
			}
		})
	}

	textRejectCases := []struct {
		name string
		arch string
		body string
	}{
		{"bts_rmw_on_sb", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tBTSQ $0, ·ro(SB)\n\tRET\n"},
		{"btr_rmw_on_sb", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tBTRL $1, ·ro(SB)\n\tRET\n"},
		{"btc_rmw_on_sb", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tBTCW $2, ·ro(SB)\n\tRET\n"},
		{"empty_text_falloff", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n"},
		{"missing_ret_falloff", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tMOVQ $1, AX\n"},
		{"branch_to_nonreturning_label_falloff", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-8\n\tCMPQ x+0(FP), $0\n\tJEQ fall\n\tRET\nfall:\n\tMOVQ $1, AX\n"},
		{"ifdef_missing_else_falloff", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n#ifdef M\n\tRET\n#endif\n"},
		{"ifdef_arm_falloff", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n#ifdef M\n\tMOVQ $1, AX\n#else\n\tRET\n#endif\n"},
		{"pc_rel_overshoot_ret", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-8\n\tCMPQ x+0(FP), $0\n\tJEQ 2(PC)\n\tRET\n"},
		{"pc_rel_undershoot_entry", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tJMP -1(PC)\n\tRET\n"},
		{"pc_rel_inside_ifdef", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n#ifdef M\n\tJMP 1(PC)\n#endif\n\tNOP\n\tRET\n"},
		{"amd64_indirect_store_through_leaq", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tLEAQ ·ro(SB), R8\n\tMOVQ $9, (R8)\n\tRET\n"},
		{"amd64_scaled_index_store_through_tainted", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-8\n\tMOVQ p+0(FP), CX\n\tLEAQ ·ro(SB), R8\n\tMOVB $1, 0(CX)(R8*1)\n\tRET\n"},
		{"amd64_forward_jmp_indirect_store", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tJMP load\nclobber:\n\tMOVQ $1, (R8)\n\tRET\nload:\n\tLEAQ ·ro(SB), R8\n\tJMP clobber\n"},
		{"amd64_partial_movw_does_not_clear_taint", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tLEAQ ·ro(SB), R8\n\tMOVW $0, R8W\n\tMOVQ $1, (R8)\n\tRET\n"},
		{"amd64_partial_movb_al_does_not_clear_taint", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tLEAQ ·ro(SB), AX\n\tMOVB $0, AL\n\tMOVQ $1, (AX)\n\tRET\n"},
		{"amd64_cmov_does_not_clear_taint", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-8\n\tMOVQ x+0(FP), CX\n\tCMPQ CX, $0\n\tLEAQ ·ro(SB), R8\n\tCMOVQEQ CX, R8\n\tMOVQ $1, (R8)\n\tRET\n"},
		{"amd64_escape_tainted_to_ret_fp", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-8\n\tLEAQ ·ro(SB), AX\n\tMOVQ AX, ret+0(FP)\n\tRET\n"},
		{"amd64_direct_dollar_sb_to_ret_fp", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-8\n\tMOVQ $·ro(SB), ret+0(FP)\n\tRET\n"},
		{"amd64_push_tainted_gpr", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tLEAQ ·ro(SB), R8\n\tPUSHQ R8\n\tPOPQ AX\n\tRET\n"},
		{"amd64_push_dollar_sb", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tPUSHQ $·ro(SB)\n\tPOPQ AX\n\tRET\n"},
		{"amd64_spill_tainted_to_sp", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-8\n\tLEAQ ·ro(SB), R8\n\tMOVQ R8, -8(SP)\n\tRET\n"},
		{"amd64_smuggle_tainted_to_xmm", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tLEAQ ·ro(SB), R8\n\tVMOVQ R8, X0\n\tRET\n"},
		{"amd64_stosq_implicit_di_tainted", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tLEAQ ·ro(SB), DI\n\tSTOSQ\n\tRET\n"},
		{"amd64_aslr_leak_via_testq_branch", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-8\n\tLEAQ ·ro(SB), R8\n\tTESTQ $0x1000, R8\n\tJZ zero\n\tMOVQ $1, ret+0(FP)\n\tRET\nzero:\n\tMOVQ $0, ret+0(FP)\n\tRET\n"},
		{"amd64_aslr_leak_via_addq_carry_branch", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-8\n\tLEAQ ·ro(SB), R8\n\tADDQ $0x1000, R8\n\tJC zero\n\tMOVQ $1, ret+0(FP)\n\tRET\nzero:\n\tMOVQ $0, ret+0(FP)\n\tRET\n"},
		{"arm64_indirect_movd_store", "arm64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tMOVD $·ro(SB), R8\n\tMOVD R0, (R8)\n\tRET\n"},
		{"arm64_indirect_stp_store", "arm64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tMOVD $·ro(SB), R8\n\tSTP (R0, R1), (R8)\n\tRET\n"},
		{"arm64_movk_does_not_clear_taint", "arm64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tMOVD $·ro(SB), R8\n\tMOVK $0, R8\n\tMOVD R0, (R8)\n\tRET\n"},
		{"arm64_escape_tainted_to_ret_fp", "arm64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-8\n\tMOVD $·ro(SB), R8\n\tMOVD R8, ret+0(FP)\n\tRET\n"},
		{"arm64_aslr_leak_via_cbz", "arm64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-8\n\tMOVD $·ro(SB), R8\n\tCBZ R8, zero\n\tMOVD $1, ret+0(FP)\n\tRET\nzero:\n\tMOVD $0, ret+0(FP)\n\tRET\n"},
		{"call_nonzero_offset_gadget", "amd64", roHeader + "TEXT ·H(SB),NOSPLIT,$0-0\n\tRET\nTEXT ·F(SB),NOSPLIT,$0-0\n\tCALL ·H+1(SB)\n\tRET\n"},
		{"call_cross_pkg_forbidden", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tCALL otherpkg·H(SB)\n\tRET\n"},
		{"call_with_live_tainted_gpr", "amd64", roHeader + "TEXT ·H(SB),NOSPLIT,$0-0\n\tMOVQ $1, (R8)\n\tRET\nTEXT ·F(SB),NOSPLIT,$0-0\n\tLEAQ ·ro(SB), R8\n\tCALL ·H(SB)\n\tRET\n"},
		{"callee_returns_tainted_gpr_stored_by_caller", "amd64", roHeader + "TEXT ·getPtr(SB),NOSPLIT,$0-0\n\tLEAQ ·ro(SB), R8\n\tRET\nTEXT ·F(SB),NOSPLIT,$0-0\n\tCALL ·getPtr(SB)\n\tMOVQ $1, (R8)\n\tRET\n"},
		{"callee_returns_tainted_flags_branched_by_caller", "amd64", roHeader + "TEXT ·leakFlags(SB),NOSPLIT,$0-0\n\tLEAQ ·ro(SB), R8\n\tADDQ $0x1000, R8\n\tMOVQ $0, R8\n\tRET\nTEXT ·F(SB),NOSPLIT,$0-8\n\tCALL ·leakFlags(SB)\n\tJC zero\n\tMOVQ $1, ret+0(FP)\n\tRET\nzero:\n\tMOVQ $0, ret+0(FP)\n\tRET\n"},
		{"amd64_maskmovdqu_implicit_di_tainted", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tLEAQ ·ro(SB), DI\n\tMASKMOVDQU X0, X1\n\tRET\n"},
		{"amd64_xlat_implicit_bx_tainted", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tLEAQ ·ro(SB), BX\n\tXLAT\n\tRET\n"},
		{"arm64_raw_word_ubfm_on_tainted_gpr", "arm64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-8\n\tMOVD $·ro(SB), R8\n\tWORD $0xd340fd00\n\tMOVD R0, ret+0(FP)\n\tRET\n"},
		{"arm64_raw_word_addvl_propagates_taint_to_rd", "arm64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-8\n\tMOVD $·ro(SB), R8\n\tWORD $0x04205100\n\tMOVD R0, ret+0(FP)\n\tRET\n"},
		{"pc_rel_across_pcalign_rejected", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tLEAQ ·ro(SB), R8\n\tJMP 2(PC)\n\tPCALIGN $16\n\tMOVQ $999, (R8)\n\tXORQ R8, R8\n\tRET\n"},
		{"pc_rel_across_funcdata_rejected", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-8\n\tJMP 2(PC)\n\tFUNCDATA $0, ·ro(SB)\n\tMOVQ R14, ret+0(FP)\n\tMOVQ $0, R14\n\tRET\n"},
		{"amd64_sse_xorps_does_not_clear_tainted_flags", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-8\n\tLEAQ ·ro(SB), R8\n\tADDQ $0x1000, R8\n\tXORPS X0, X0\n\tMOVQ $0, R8\n\tJC zero\n\tMOVQ $1, ret+0(FP)\n\tRET\nzero:\n\tMOVQ $0, ret+0(FP)\n\tRET\n"},
		{"amd64_lahf_consumes_tainted_flags", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-8\n\tLEAQ ·ro(SB), R8\n\tADDQ $0x1000, R8\n\tMOVQ $0, AX\n\tLAHF\n\tMOVQ $0, R8\n\tMOVQ AX, ret+0(FP)\n\tRET\n"},
		{"amd64_adoxq_consumes_tainted_flags", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-8\n\tLEAQ ·ro(SB), R8\n\tADDQ $0x1000, R8\n\tMOVQ $0, AX\n\tMOVQ $0, CX\n\tADOXQ CX, AX\n\tMOVQ $0, R8\n\tMOVQ AX, ret+0(FP)\n\tRET\n"},
		{"amd64_stosq_implicit_ax_tainted", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tLEAQ ·ro(SB), AX\n\tLEAQ -8(SP), DI\n\tSTOSQ\n\tXORQ AX, AX\n\tMOVQ -8(SP), R9\n\tMOVQ $999, (R9)\n\tRET\n"},
		{"amd64_mulxq_implicit_dx_tainted", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tLEAQ ·ro(SB), DX\n\tMOVQ $1, CX\n\tMULXQ CX, R9, R10\n\tXORQ DX, DX\n\tMOVQ $999, (R9)\n\tRET\n"},
		{"amd64_leave_implicit_bp_tainted", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tMOVQ SP, R9\n\tLEAQ ·ro+8(SB), BP\n\tLEAVE\n\tPUSHQ $999\n\tMOVQ R9, SP\n\tXORQ BP, BP\n\tRET\n"},
		{"amd64_leaveq_implicit_bp_tainted", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tMOVQ SP, R9\n\tLEAQ ·ro+8(SB), BP\n\tLEAVEQ\n\tPUSHQ $999\n\tMOVQ R9, SP\n\tXORQ BP, BP\n\tRET\n"},
		{"amd64_enter_implicit_bp_tainted", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-8\n\tLEAQ ·ro(SB), BP\n\tENTER $0, $0\n\tPOPQ R9\n\tXORQ BP, BP\n\tMOVQ R9, ret+0(FP)\n\tRET\n"},
		{"amd64_cqo_implicit_dx_tainted", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tLEAQ ·ro(SB), DX\n\tCQO\n\tRET\n"},
		{"amd64_btq_does_not_clear_tainted_zf", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-16\n\tMOVQ guess+0(FP), AX\n\tLEAQ ·ro(SB), R8\n\tADDQ AX, R8\n\tBTQ $0, 0(R8)\n\tMOVQ $0, R8\n\tJZ hit\n\tMOVQ $0, ret+8(FP)\n\tRET\nhit:\n\tMOVQ $1, ret+8(FP)\n\tRET\n"},
		{"amd64_cmpps_does_not_clear_tainted_flags", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-16\n\tMOVQ guess+0(FP), AX\n\tLEAQ ·ro(SB), R8\n\tADDQ AX, R8\n\tCMPPS 0(R8), X0, $0\n\tMOVQ $0, R8\n\tJZ hit\n\tMOVQ $0, ret+8(FP)\n\tRET\nhit:\n\tMOVQ $1, ret+8(FP)\n\tRET\n"},
		{"amd64_cmpps_last_operand_sb_rejected", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tCMPPS $0, X0, ·ro(SB)\n\tRET\n"},
		{"arm64_comma_pair_deref_rejected", "arm64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tMOVD $·ro(SB), R8\n\tLDP (R8, R9), (R0, R1)\n\tRET\n"},
		{"amd64_cmpxchg_implicit_ax_tainted", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tLEAQ ·ro(SB), AX\n\tMOVQ $0, CX\n\tCMPXCHGQ CX, -8(SP)\n\tRET\n"},
		{"amd64_jecxz_implicit_cx_tainted", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tLEAQ ·ro(SB), CX\n\tJECXZ aligned\naligned:\n\tRET\n"},
		{"arm64_st64bv_store_through_tainted", "arm64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tMOVD $·ro(SB), R8\n\tST64BV R0, (R8), R2\n\tRET\n"},
		{"unverified_raw_byte_sets_not_verified", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tBYTE $0x90\n\tRET\n"},
		{"syscall_sets_not_verified", "amd64", roHeader + "TEXT ·F(SB),NOSPLIT,$0-0\n\tSYSCALL\n\tRET\n"},
	}

	for _, tc := range textRejectCases {
		t.Run("reject_"+tc.name, func(t *testing.T) {
			vp, ok := VerifyNonStdFiles(tc.arch, "example.com/p", "/virtual/p", []string{"k.s"}, nil, nil, memReader(map[string]string{"k.s": tc.body}))
			if !ok || vp == nil || !vp.PackageSafe {
				t.Fatalf("%s: expected PackageSafe=true, got ok=%v vp=%+v", tc.name, ok, vp)
			}
			if vp.AllTextsVerified || vp.Funcs["F"].Verified {
				t.Fatalf("%s: expected !AllTextsVerified && !Funcs[F].Verified, got vp=%+v", tc.name, vp)
			}
		})
	}

	// File-static `helper<>(SB)` isolation across two .s files, transitive ImpureKind /
	// ExternalSBRefs / CPUID-callee propagation, and TEXT-vs-Go-Var collision rejection.
	t.Run("multifile_static_isolation_and_transitive_summaries", func(t *testing.T) {
		files := map[string]string{
			"a.s": `#include "textflag.h"
TEXT helper<>(SB), NOSPLIT, $0-0
	MOVQ ·lutA(SB), AX
	RET

TEXT ·PureViaStaticA(SB), NOSPLIT, $0-8
	CALL helper<>(SB)
	MOVQ AX, ret+0(FP)
	RET
`,
			"b.s": `#include "textflag.h"
TEXT helper<>(SB), NOSPLIT, $0-0
	RDTSC
	RET

TEXT ·ImpureViaStaticB(SB), NOSPLIT, $0-8
	CALL helper<>(SB)
	MOVQ AX, ret+0(FP)
	RET

TEXT ·CallsMissingStaticC(SB), NOSPLIT, $0-0
	CALL missingInB<>(SB)
	RET

TEXT ·RawCpuidLeaf(SB), NOSPLIT, $0-24
	MOVL op+0(FP), AX
	XORQ CX, CX
	CPUID
	MOVL AX, eax+8(FP)
	MOVL BX, ebx+12(FP)
	MOVL CX, ecx+16(FP)
	MOVL DX, edx+20(FP)
	RET

TEXT ·CallsCpuidWrapper(SB), NOSPLIT, $0-0
	CALL ·RawCpuidLeaf(SB)
	RET
`,
		}
		vp, ok := VerifyNonStdFiles("amd64", "example.com/multi", "/virtual/multi", []string{"a.s", "b.s"}, nil, nil, memReader(files))
		if !ok || vp == nil || !vp.PackageSafe || vp.AllTextsVerified {
			t.Fatalf("unexpected package summary: ok=%v vp=%+v", ok, vp)
		}
		pureA := vp.Funcs["PureViaStaticA"]
		wantRefA := []ExternalSBRef{{PkgPath: "example.com/multi", Name: "lutA"}}
		if !pureA.Verified || pureA.ImpureKind != "" || !reflect.DeepEqual(pureA.ExternalSBRefs, wantRefA) {
			t.Fatalf("PureViaStaticA = %+v, want Verified, pure, ExternalSBRefs=%+v", pureA, wantRefA)
		}
		impB := vp.Funcs["ImpureViaStaticB"]
		if !impB.Verified || impB.ImpureKind == "" {
			t.Fatalf("ImpureViaStaticB = %+v, want Verified with non-empty ImpureKind", impB)
		}
		if vp.Funcs["CallsMissingStaticC"].Verified {
			t.Fatalf("CallsMissingStaticC should have Verified=false: %+v", vp.Funcs["CallsMissingStaticC"])
		}
		if cp := vp.Funcs["CallsCpuidWrapper"]; !cp.Verified || cp.CPUIDArgs != 0 || cp.ImpureKind == "" || !slices.Equal(cp.GoCallees, []string{"RawCpuidLeaf"}) {
			t.Fatalf("CallsCpuidWrapper = %+v, want CPUIDArgs=0, non-empty ImpureKind, GoCallees=[RawCpuidLeaf]", cp)
		}

		// Transitive GoCallees propagation across a file-static <> intermediary (`Entry -> mid<> -> Leaf`).
		transSrc := `#include "textflag.h"
TEXT ·Leaf(SB), NOSPLIT|NOFRAME, $0-0
	RET

TEXT mid<>(SB), NOSPLIT, $0-0
	JMP ·Leaf(SB)

TEXT ·Entry(SB), NOPROF|NOSPLIT|TOPFRAME, $0-0
	CALL mid<>(SB)
	RET
`
		vpTrans, okTrans := VerifyNonStdFiles("amd64", "example.com/trans", "/virtual/trans", []string{"t.s"}, nil, nil, memReader(map[string]string{"t.s": transSrc}))
		if !okTrans || vpTrans == nil || !vpTrans.AllTextsVerified || !slices.Equal(vpTrans.Funcs["Entry"].GoCallees, []string{"Leaf"}) {
			t.Fatalf("transitive GoCallees failed: ok=%v vp=%+v", okTrans, vpTrans)
		}

		// DUPOK, ABI/wrapper flags, and non-$ frame sizes on TEXT headers must fail PackageSafe.
		for _, badHdr := range []string{
			"#include \"textflag.h\"\nTEXT ·A(SB), DUPOK, $0-0\n\tRET\n",
			"#include \"textflag.h\"\nTEXT ·A(SB), NOSPLIT|DUPOK, $0-0\n\tRET\n",
			"#include \"textflag.h\"\nTEXT ·A(SB), WRAPPER, $0-0\n\tRET\n",
			"#include \"textflag.h\"\nTEXT ·A(SB), NEEDCTXT, $0-0\n\tRET\n",
			"#include \"textflag.h\"\nTEXT ·A(SB), ABIWRAPPER, $0-0\n\tRET\n",
			"#include \"textflag.h\"\nTEXT ·A(SB), RODATA, $0-0\n\tRET\n",
			"#include \"textflag.h\"\nTEXT ·A(SB), NOSPLIT, 0\n\tRET\n",
		} {
			if vpH, okH := VerifyNonStdFiles("amd64", "example.com/hdr", "/virtual/hdr", []string{"h.s"}, nil, nil, memReader(map[string]string{"h.s": badHdr})); okH || (vpH != nil && vpH.PackageSafe) {
				t.Fatalf("admitted forbidden TEXT header %q: ok=%v vp=%+v", badHdr, okH, vpH)
			}
		}

		// CheckVerifiedTypeScopes must reject a Go var colliding with a TEXT name.
		badScope := types.NewPackage("example.com/multi", "multi")
		badScope.Scope().Insert(types.NewVar(token.NoPos, badScope, "PureViaStaticA", types.Typ[types.Int]))
		if CheckVerifiedTypeScopes(vp, []*types.Package{badScope}) {
			t.Fatal("CheckVerifiedTypeScopes admitted Go var colliding with TEXT symbol")
		}
		goodScope := types.NewPackage("example.com/multi", "multi")
		goodScope.Scope().Insert(types.NewFunc(token.NoPos, goodScope, "PureViaStaticA", types.NewSignatureType(nil, nil, nil, nil, nil, false)))
		if !CheckVerifiedTypeScopes(vp, []*types.Package{goodScope}) {
			t.Fatal("CheckVerifiedTypeScopes rejected valid Go func matching TEXT symbol")
		}

		// Semicolon-joined lines mixing instructions with TEXT / GLOBL / DATA must fail PackageSafe.
		for _, semiSrc := range []string{
			"#include \"textflag.h\"\nTEXT ·A(SB),NOSPLIT,$0-0\n\tMOVQ $1, AX; TEXT ·B(SB),NOSPLIT,$0-0\n\tRET\n",
			"#include \"textflag.h\"\nMOVQ $1, AX; GLOBL ·ro(SB), RODATA, $8\n",
			"#include \"textflag.h\"\nGLOBL ·ro(SB), RODATA, $8\nNOP; DATA ·ro+0(SB)/8, $1\n",
		} {
			if vpS, okS := VerifyNonStdFiles("amd64", "example.com/semi", "/virtual/semi", []string{"s.s"}, nil, nil, memReader(map[string]string{"s.s": semiSrc})); okS || (vpS != nil && vpS.PackageSafe) {
				t.Fatalf("admitted semicolon-mixed directive line %q: ok=%v vp=%+v", semiSrc, okS, vpS)
			}
		}
	})
}

func TestPropertyAsmBlockCFGFalloffAndTaintOracle(t *testing.T) {
	t.Parallel()

	// Independent abstract CFG oracle for preprocessor #ifdef/#else, forward
	// conditional jumps, entry R14 safety, non-returning fall-off, and (SB)
	// address GPR (R8 + copied R9) and EFLAGS taint confinement on amd64.
	type genOp uint8
	const (
		opNop genOp = iota
		opKillR14
		opReadR14
		opLoadSBAddrR8
		opCopyR8ToR9
		opClearR9
		opDerefLoadR8Clear
		opDerefLoadR8ToAX
		opIndirectStoreR8
		opIndirectStoreR9
		opEscapeR9ToRet
		opAddOffsetR8TaintFlags
		opOverwriteCleanFlags
		opBranchOnCarryEnd
		opTestR8AndBranchEnd
		opCondBranchEnd
		opRet
	)

	emitOp := func(op genOp) string {
		switch op {
		case opNop:
			return "\tMOVQ $0, AX"
		case opKillR14:
			return "\tMOVQ $0, R14"
		case opReadR14:
			return "\tMOVQ R14, AX"
		case opLoadSBAddrR8:
			return "\tLEAQ ·ro(SB), R8"
		case opCopyR8ToR9:
			return "\tMOVQ R8, R9"
		case opClearR9:
			return "\tXORQ R9, R9"
		case opDerefLoadR8Clear:
			return "\tMOVQ (R8), R8"
		case opDerefLoadR8ToAX:
			return "\tMOVQ (R8), AX"
		case opIndirectStoreR8:
			return "\tMOVQ AX, (R8)"
		case opIndirectStoreR9:
			return "\tMOVQ AX, (R9)"
		case opEscapeR9ToRet:
			return "\tMOVQ R9, ret+0(FP)"
		case opAddOffsetR8TaintFlags:
			return "\tADDQ $16, R8"
		case opOverwriteCleanFlags:
			return "\tCMPQ AX, $0"
		case opBranchOnCarryEnd:
			return "\tJC epilogue"
		case opTestR8AndBranchEnd:
			return "\tTESTQ $1, R8; JNZ epilogue"
		case opCondBranchEnd:
			return "\tCMPQ AX, $0; JEQ epilogue"
		case opRet:
			return "\tRET"
		default:
			return "\tNOP"
		}
	}

	rapid.Check(t, func(rt *rapid.T) {
		const nSteps = 5
		type stepSpec struct {
			useIfdef bool
			hasElse  bool
			thenOp   genOp
			elseOp   genOp
		}
		steps := make([]stepSpec, nSteps)
		opGen := rapid.SampledFrom([]genOp{
			opNop, opKillR14, opReadR14, opLoadSBAddrR8, opCopyR8ToR9, opClearR9,
			opDerefLoadR8Clear, opDerefLoadR8ToAX, opIndirectStoreR8, opIndirectStoreR9,
			opEscapeR9ToRet, opAddOffsetR8TaintFlags, opOverwriteCleanFlags,
			opBranchOnCarryEnd, opTestR8AndBranchEnd, opCondBranchEnd, opRet,
		})
		for i := range steps {
			steps[i] = stepSpec{
				useIfdef: rapid.Bool().Draw(rt, fmt.Sprintf("ifdef_%d", i)),
				hasElse:  rapid.Bool().Draw(rt, fmt.Sprintf("else_%d", i)),
				thenOp:   opGen.Draw(rt, fmt.Sprintf("then_%d", i)),
				elseOp:   opGen.Draw(rt, fmt.Sprintf("elseop_%d", i)),
			}
		}
		epilogueHasRet := rapid.Bool().Draw(rt, "epi_ret")
		epilogueOp := rapid.SampledFrom([]genOp{
			opNop, opReadR14, opIndirectStoreR8, opIndirectStoreR9, opEscapeR9ToRet,
		}).Draw(rt, "epi_op")

		var sb strings.Builder
		sb.WriteString("#include \"textflag.h\"\nGLOBL ·ro(SB), RODATA, $8\nDATA ·ro+0(SB)/8, $1\nTEXT ·F(SB), NOSPLIT, $0-8\n")
		for i, st := range steps {
			if !st.useIfdef {
				sb.WriteString(emitOp(st.thenOp) + "\n")
				continue
			}
			fmt.Fprintf(&sb, "#ifdef COND_%d\n%s\n", i, emitOp(st.thenOp))
			if st.hasElse {
				fmt.Fprintf(&sb, "#else\n%s\n", emitOp(st.elseOp))
			}
			sb.WriteString("#endif\n")
		}
		sb.WriteString("epilogue:\n" + emitOp(epilogueOp) + "\n")
		if epilogueHasRet {
			sb.WriteString("\tRET\n")
		}
		asmSrc := sb.String()

		oracleSafe := true
		type oracleNode struct {
			op    genOp
			hasOp bool
			succs []int
		}
		var oNodes []oracleNode
		newONode := func(op genOp, hasOp bool) int {
			oNodes = append(oNodes, oracleNode{op: op, hasOp: hasOp})
			return len(oNodes) - 1
		}
		oEntry := newONode(0, false)
		oEpilogue := newONode(epilogueOp, true)
		oFalloff := newONode(0, false)
		if epilogueHasRet {
			oRet := newONode(opRet, true)
			oNodes[oEpilogue].succs = []int{oRet}
		} else {
			oNodes[oEpilogue].succs = []int{oFalloff}
		}
		curFront := []int{oEntry}
		wire := func(froms []int, to int) {
			for _, f := range froms {
				if !slices.Contains(oNodes[f].succs, to) {
					oNodes[f].succs = append(oNodes[f].succs, to)
				}
			}
		}
		addArm := func(inFront []int, op genOp) []int {
			nd := newONode(op, true)
			wire(inFront, nd)
			if op == opRet {
				return nil
			}
			if op == opTestR8AndBranchEnd || op == opCondBranchEnd || op == opBranchOnCarryEnd {
				wire([]int{nd}, oEpilogue)
			}
			return []int{nd}
		}
		for _, st := range steps {
			if !st.useIfdef {
				curFront = addArm(curFront, st.thenOp)
				continue
			}
			fThen := addArm(curFront, st.thenOp)
			var fElse []int
			if st.hasElse {
				fElse = addArm(curFront, st.elseOp)
			} else {
				fElse = slices.Clone(curFront)
			}
			merged := slices.Clone(fThen)
			for _, x := range fElse {
				if !slices.Contains(merged, x) {
					merged = append(merged, x)
				}
			}
			curFront = merged
		}
		wire(curFront, oEpilogue)

		type absFact struct {
			reach      bool
			r14Live    bool
			r8Taint    bool
			r9Taint    bool
			flagsTaint bool
		}
		facts := make([]absFact, len(oNodes))
		facts[oEntry] = absFact{reach: true, r14Live: true}
		for {
			changed := false
			for idx, nd := range oNodes {
				f := facts[idx]
				if !f.reach {
					continue
				}
				if idx == oFalloff {
					oracleSafe = false
					break
				}
				out := f
				if nd.hasOp {
					switch nd.op {
					case opKillR14:
						out.r14Live = false
					case opReadR14:
						if f.r14Live {
							oracleSafe = false
						}
					case opLoadSBAddrR8:
						out.r8Taint = true
					case opCopyR8ToR9:
						if f.r8Taint {
							out.r9Taint = true
						} else {
							out.r9Taint = false
						}
					case opClearR9:
						out.r9Taint = false
						out.flagsTaint = false
					case opDerefLoadR8Clear:
						out.r8Taint = false
					case opIndirectStoreR8, opTestR8AndBranchEnd:
						if f.r8Taint {
							oracleSafe = false
						}
						if nd.op == opTestR8AndBranchEnd {
							out.flagsTaint = false
						}
					case opIndirectStoreR9, opEscapeR9ToRet:
						if f.r9Taint {
							oracleSafe = false
						}
					case opAddOffsetR8TaintFlags:
						if f.r8Taint {
							out.flagsTaint = true
						} else {
							out.flagsTaint = false
						}
					case opOverwriteCleanFlags, opCondBranchEnd:
						out.flagsTaint = false
					case opBranchOnCarryEnd:
						if f.flagsTaint {
							oracleSafe = false
						}
					case opRet:
						continue
					}
				}
				if !oracleSafe {
					break
				}
				for _, s := range nd.succs {
					prev := facts[s]
					next := absFact{
						reach:      true,
						r14Live:    prev.r14Live || out.r14Live,
						r8Taint:    prev.r8Taint || out.r8Taint,
						r9Taint:    prev.r9Taint || out.r9Taint,
						flagsTaint: prev.flagsTaint || out.flagsTaint,
					}
					if next != prev {
						facts[s] = next
						changed = true
					}
				}
			}
			if !oracleSafe || !changed {
				break
			}
		}

		vp, ok := VerifyNonStdFiles("amd64", "example.com/prop", "/virtual/prop", []string{"p.s"}, nil, nil, memReader(map[string]string{"p.s": asmSrc}))
		if !ok || vp == nil || !vp.PackageSafe {
			rt.Fatalf("expected PackageSafe=true on generated assembly:\n%s", asmSrc)
		}
		gotVerified := vp.AllTextsVerified && vp.Funcs["F"].Verified
		if gotVerified != oracleSafe {
			rt.Fatalf("VerifyNonStdFiles Verified=%v != oracleSafe=%v on:\n%s", gotVerified, oracleSafe, asmSrc)
		}
	})
}

func FuzzVerifyNonStdFiles(f *testing.F) {
	f.Add("amd64", "#include \"textflag.h\"\nGLOBL ·ro(SB), RODATA, $8\nDATA ·ro+0(SB)/8, $1\nTEXT ·F(SB),NOSPLIT,$0-8\n\tLEAQ ·ro(SB), R8\n\tBTQ AX, 0(R8)\n\tMOVQ (R8), AX\n\tMOVQ AX, ret+0(FP)\n\tRET\n", "")
	f.Add("arm64", "#include \"textflag.h\"\nGLOBL ·ro(SB), RODATA, $8\nTEXT ·H(SB),NOSPLIT,$0-0\n\tRET\nTEXT ·F(SB),NOSPLIT,$0-8\n\tBL ·H(SB)\n\tMOVD $·ro(SB), R8\n\tMOVD (R8), R0\n\tMOVD R0, ret+0(FP)\n\tRET\n", "")
	f.Add("amd64", "#include \"h.h\"\nTEXT ·F(SB),NOSPLIT,$0-0\n\tM(AX)\n\tRET\n", "#define M(r) XORQ r, r\n")
	f.Add("amd64", "TEXT ·F(SB),NOSPLIT,$0-0\n\tJMP 2(PC)\n\tRET\n", "")

	f.Fuzz(func(t *testing.T, arch, asmSrc, hdrSrc string) {
		if arch != "amd64" && arch != "arm64" {
			arch = "amd64"
		}
		hFiles := []string(nil)
		files := map[string]string{"f.s": asmSrc}
		if hdrSrc != "" {
			hFiles = []string{"h.h"}
			files["h.h"] = hdrSrc
		}
		vp1, ok1 := VerifyNonStdFiles(arch, "example.com/fuzz", "/virtual/fuzz", []string{"f.s"}, hFiles, nil, memReader(files))
		vp2, ok2 := VerifyNonStdFiles(arch, "example.com/fuzz", "/virtual/fuzz", []string{"f.s"}, hFiles, nil, memReader(files))
		if ok1 != ok2 || !reflect.DeepEqual(vp1, vp2) {
			t.Fatalf("non-deterministic VerifyNonStdFiles: (%v, %+v) vs (%v, %+v)", ok1, vp1, ok2, vp2)
		}
		if ok1 && vp1 != nil {
			if !vp1.PackageSafe {
				t.Fatalf("VerifyNonStdFiles returned ok=true with PackageSafe=false: %+v", vp1)
			}
			if vp1.AllTextsVerified {
				for fn, sum := range vp1.Funcs {
					if !sum.Verified {
						t.Fatalf("AllTextsVerified=true with unverified Funcs[%s]=%+v", fn, sum)
					}
				}
			}
		}
	})
}
