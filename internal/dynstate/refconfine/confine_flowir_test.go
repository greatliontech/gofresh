package refconfine

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func TestVerifyReadOnlyRefConfinementFlowIRMatrix(t *testing.T) {
	const prelude = `package p

type holder struct {
	items  []int
	matrix [][]int
	m      map[string]int
	iface  any
	tag    int
}

func (h holder) ReadVal() int  { return len(h.items) + h.tag }
func (h *holder) ReadLen() int { return len(h.items) + len(h.m) }
func (h *holder) TakeSlice(_ []int) int { return len(h.items) }

var (
	seed      = holder{items: []int{1, 2}, matrix: [][]int{{3, 4}}, m: map[string]int{"a": 5}, tag: 7}
	other     = &holder{items: []int{8}}
	rawAny    any
	extSinkFn func([][]int)
)

func sinkAny(any) {}
func idGeneric[T any](v T) T { return v }
`
	type tc struct {
		name                string
		extra               string
		allowUnexportedRet  bool
		allowCapsule        bool
		allowFieldProp      bool
		forbidPtrCompare    bool
		seedTypeAssert      bool
		allowMethodExprRecv bool
		want                bool
	}

	cases := []tc{
		{
			name:  "bare_rebind_collider_clean",
			extra: `func F() int { clean := []int{9, 10}; x := seed.items; x = clean; clean[0] = 2; _ = x; return clean[0] }`,
			want:  true,
		},
		{
			name:  "bare_rebind_prior_alias_mutated",
			extra: `func F() { x := seed.items; y := x; x = []int{9, 10}; y[0] = 2; _ = x }`,
			want:  false,
		},
		{
			name:  "fresh_slice_tainted_elem_confined_read",
			extra: `func F() int { fresh := make([][]int, 1); fresh[0] = seed.matrix[0]; return fresh[0][0] }`,
			want:  true,
		},
		{
			name:  "shared_header_fresh_slice_return_escape",
			extra: `func F() [][]int { fresh := make([][]int, 1); alias := fresh; fresh[0] = seed.matrix[0]; return alias }`,
			want:  false,
		},
		{
			name:  "shared_header_reverse_alias_write_return_fresh",
			extra: `func F() [][]int { fresh := make([][]int, 1); alias := fresh; alias[0] = seed.matrix[0]; return fresh }`,
			want:  false,
		},
		{
			name:  "addr_taken_fresh_slice_rebind_to_global_rejected",
			extra: `var globalMat = make([][]int, 1); func F() { v := make([][]int, 1); p := &v; *p = globalMat; v[0] = seed.matrix[0] }`,
			want:  false,
		},
		{
			name:  "shared_header_fresh_slice_call_escape",
			extra: `func F() { fresh := make([][]int, 1); alias := fresh; fresh[0] = seed.matrix[0]; extSinkFn(alias) }`,
			want:  false,
		},
		{
			name:  "shared_header_fresh_slice_nested_elem_write",
			extra: `func F() { fresh := make([][]int, 1); alias := fresh; fresh[0] = seed.matrix[0]; alias[0][0] = 9 }`,
			want:  false,
		},
		{
			name:  "shared_header_fresh_slice_chan_send",
			extra: `func F(ch chan<- [][]int) { fresh := make([][]int, 1); alias := fresh; fresh[0] = seed.matrix[0]; ch <- alias }`,
			want:  false,
		},
		{
			name:  "shared_header_fresh_slice_copy_to_external",
			extra: `func F(dst [][]int) { fresh := make([][]int, 1); alias := fresh; fresh[0] = seed.matrix[0]; copy(dst, alias) }`,
			want:  false,
		},
		{
			name:  "local_value_array_slice_view_disqualified",
			extra: `func F() []int { var arr [1][]int; sl := arr[:]; sl[0] = seed.items; return arr[0] }`,
			want:  false,
		},
		{
			name:  "fresh_slice_append_confined",
			extra: `func F() int { fresh := make([][]int, 0, 2); fresh = append(fresh, seed.items); return len(fresh[0]) }`,
			want:  true,
		},
		{
			name:  "shared_header_append_escape",
			extra: `func F() [][]int { fresh := make([][]int, 0, 2); alias := fresh; fresh = append(fresh, seed.items); _ = fresh; return alias }`,
			want:  false,
		},
		{
			name: "multi_return_assign_and_valuespec_and_nested_call_clean",
			extra: `
func pair() (int, []int) { return seed.tag, seed.items }
func readPair(a int, s []int) int { return a + len(s) }
func F() int {
	a, b := pair()
	var c, d = pair()
	return a + len(b) + c + len(d) + readPair(pair())
}`,
			allowUnexportedRet: true,
			want:               true,
		},
		{
			name: "multi_return_assign_mutates_tainted_slot",
			extra: `
func pair() (int, []int) { return seed.tag, seed.items }
func F() { _, b := pair(); b[0] = 7 }`,
			allowUnexportedRet: true,
			want:               false,
		},
		{
			name: "multi_return_valuespec_returns_tainted_slot",
			extra: `
func pair() (int, []int) { return seed.tag, seed.items }
func F() []int { var _, b = pair(); return b }`,
			allowUnexportedRet: true,
			want:               false,
		},
		{
			name: "multi_return_nested_call_mutates_tainted_slot",
			extra: `
func pair() (int, []int) { return seed.tag, seed.items }
func badPair(_ int, s []int) { s[0] = 1 }
func F() { badPair(pair()) }`,
			allowUnexportedRet: true,
			want:               false,
		},
		{
			name: "variadic_packing_clean",
			extra: `
func sumLengths(xs ...[]int) int {
	n := 0
	for _, x := range xs { n += len(x) }
	return n
}
func F() int { return sumLengths(seed.items, seed.matrix[0]) }`,
			want: true,
		},
		{
			name: "variadic_packing_mutates_elem",
			extra: `
func clobber(xs ...[]int) { xs[0][0] = 1 }
func F() { clobber(seed.items) }`,
			want: false,
		},
		{
			name: "variadic_ellipsis_spread_mutates_elem",
			extra: `
func clobber(xs ...[]int) { xs[0][0] = 1 }
func F() { clobber(seed.matrix...) }`,
			want: false,
		},
		{
			name:                "method_expr_approved_recv_and_value_recv_method_val_clean",
			extra:               `func F() int { fn := seed.ReadVal; return (*holder).ReadLen(&seed) + fn() }`,
			allowMethodExprRecv: true,
			want:                true,
		},
		{
			name:                "method_expr_unapproved_arg1_rejected",
			extra:               `func F() int { return (*holder).TakeSlice(&seed, seed.items) }`,
			allowMethodExprRecv: true,
			want:                false,
		},
		{
			name:  "method_expr_unapproved_recv_rejected",
			extra: `func F() int { return (*holder).ReadLen(&seed) }`,
			want:  false,
		},
		{
			name:  "method_expr_mutating_rejected",
			extra: `func (h *holder) Mutate() { h.items[0] = 99 }; func F() { (*holder).Mutate(&seed) }`,
			want:  false,
		},
		{
			name:  "auto_addr_method_val_mutating_rejected",
			extra: `func (h *holder) Mutate() { h.tag = 99 }; func F() { cp := seed; fn := cp.Mutate; fn() }`,
			want:  false,
		},
		{
			name:  "generic_type_param_erasure_rejected",
			extra: `func F() *holder { return idGeneric(&seed) }`,
			want:  false,
		},
		{
			name:             "forbid_ptr_compare_generic_comparable_erasure_rejected",
			extra:            `func eqGeneric[T comparable](a, b T) bool { return a == b }; func F() bool { var h1, h2 holder; return eqGeneric(&h1, &h2) }`,
			forbidPtrCompare: true,
			want:             false,
		},
		{
			name:           "seed_type_assert_on_untainted_arg_clean",
			extra:          `func F() int { s, ok := rawAny.([]int); if !ok { return 0 }; return len(s) }`,
			seedTypeAssert: true,
			want:           true,
		},
		{
			name:           "seed_type_assert_on_untainted_arg_mutated_rejected",
			extra:          `func F() { s, ok := rawAny.([]int); if ok { s[0] = 99 } }`,
			seedTypeAssert: true,
			want:           false,
		},
		{
			name:  "type_assert_on_tainted_iface_rejected",
			extra: `func F() int { s, _ := seed.iface.([]int); return len(s) }`,
			want:  false,
		},
		{
			name: "capsule_field_propagation_clean_sibling_write",
			extra: `
type walkState struct {
	s     []int
	count int
}
func (w *walkState) step() { w.count += len(w.s) }
func F() int { w := &walkState{s: seed.items}; w.step(); return w.count }`,
			allowFieldProp: true,
			want:           true,
		},
		{
			name: "capsule_field_propagation_exported_sig_escape_rejected",
			extra: `
type walkState struct {
	s []int
}
func ExportWrap() *walkState { return &walkState{s: seed.items} }`,
			allowFieldProp: true,
			want:           false,
		},
		{
			name:             "forbid_ptr_compare_nil_allowed",
			extra:            `func F() bool { p := &seed; return p == nil || nil != p }`,
			forbidPtrCompare: true,
			want:             true,
		},
		{
			name:             "forbid_ptr_compare_non_nil_rejected",
			extra:            `func F() bool { p := &seed; return p == other }`,
			forbidPtrCompare: true,
			want:             false,
		},
		{
			name:             "forbid_ptr_compare_switch_case_rejected",
			extra:            `func F() int { p := &seed; switch p { case other: return 1 }; return 0 }`,
			forbidPtrCompare: true,
			want:             false,
		},
		{
			name:             "forbid_ptr_compare_map_key_rejected",
			extra:            `func F() int { var m map[*holder]int; return len(m) }`,
			forbidPtrCompare: true,
			want:             false,
		},
		{
			name: "enclosing_param_rebound_in_iife_not_fresh_container",
			extra: `
func SmuggleToCallerParam(ext [][]int) {
	func() {
		if false {
			ext = nil
		}
	}()
	ext[0] = seed.matrix[0]
}`,
			want: false,
		},
		{
			name: "enclosing_outer_local_rebound_in_closure_not_fresh_container",
			extra: `
func SmuggleViaOuterLocal(ext [][]int) {
	outer := ext
	fn := func() {
		if false {
			outer = nil
		}
	}
	fn()
	outer[0] = seed.matrix[0]
}`,
			want: false,
		},
		{
			name: "auto_addr_ptr_recv_method_rebinds_fresh_slice_header_rejected",
			extra: `
type sliceBox [][]int
func (h *sliceBox) pointTo(b [][]int) { *h = b }
func Exploit(ext [][]int) {
	fresh := make(sliceBox, 1)
	fresh.pointTo(ext)
	fresh[0] = seed.matrix[0]
}`,
			want: false,
		},
		{
			name: "auto_addr_ptr_recv_method_val_rebinds_fresh_slice_header_rejected",
			extra: `
type sliceBox [][]int
func (h *sliceBox) pointTo(b [][]int) { *h = b }
func Exploit(ext [][]int) {
	fresh := make(sliceBox, 1)
	fn := fresh.pointTo
	fn(ext)
	fresh[0] = seed.matrix[0]
}`,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkg := mustTypecheckPkg(t, "example.com/p", prelude+"\n"+tc.extra+"\n")
			idx := BuildPkgIndex(pkg)
			seedObj := pkg.Types.Scope().Lookup("seed").(*types.Var)
			otherObj := pkg.Types.Scope().Lookup("other").(*types.Var)
			holderNamed := pkg.Types.Scope().Lookup("holder").(*types.TypeName).Type().(*types.Named)

			var rejectPos token.Pos
			var rejectClause string
			cfg := Config{
				Index: idx,
				SeedExpr: func(expr ast.Expr) (bool, bool) {
					e := ast.Unparen(expr)
					if id, ok := e.(*ast.Ident); ok {
						if pkg.TypesInfo.Uses[id] == seedObj {
							return false, true
						}
						if pkg.TypesInfo.Uses[id] == otherObj {
							return true, true
						}
					}
					if tc.seedTypeAssert {
						if _, ok := e.(*ast.TypeAssertExpr); ok {
							return true, true
						}
					}
					return false, false
				},
				SeedStructOrigin: func(named *types.Named) bool {
					return named != nil && named.Origin() == holderNamed.Origin()
				},
				AllowReturnFromUnexportedFunc:     tc.allowUnexportedRet,
				AllowCompositeLitFieldPropagation: tc.allowFieldProp,
				ForbidNonNilSeedStructPtrCompare:  tc.forbidPtrCompare,
				OnReject: func(pos token.Pos, clause string) {
					if rejectClause == "" {
						rejectPos = pos
						rejectClause = clause
					}
				},
			}
			if tc.allowMethodExprRecv {
				cfg.AllowCallArg = func(_ *ast.CallExpr, argIdx int, _ ast.Expr) bool {
					return argIdx == 0
				}
			}
			if tc.allowCapsule {
				cfg.CanBeSeedStructCapsule = func(named *types.Named) bool {
					return named != nil && !named.Obj().Exported()
				}
				cfg.AllowCompositeLitIntoSeedStruct = true
			}

			got := VerifyReadOnlyRefConfinement(pkg, cfg)
			if got != tc.want {
				t.Fatalf("VerifyReadOnlyRefConfinement = %v, want %v (rejectClause=%q)", got, tc.want, rejectClause)
			}
			if !tc.want && (rejectClause == "" || !rejectPos.IsValid()) {
				t.Fatalf("expected valid OnReject diagnostic on rejection, got pos=%v clause=%q", rejectPos, rejectClause)
			}
			if tc.want && rejectClause != "" {
				t.Fatalf("unexpected OnReject diagnostic on accepted package: %q", rejectClause)
			}
		})
	}
}

func TestPropertyRefconfineFlowIRConfinementOracle(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		const numLocals = 3
		// Abstract provenance model:
		// local s0..s2 hold []int values; each slot tracks whether it may alias seed backing.
		// container c0 holds [][]int; cShared tracks whether alias0 shares c0's slice header;
		// cHasSeed tracks whether c0's backing array contains a seed-backed []int element.
		seedBacked := [numLocals]bool{true, false, false}
		cShared := rapid.Bool().Draw(rt, "cShared")
		cHasSeed := false
		violated := false

		var sb strings.Builder
		sb.WriteString(`package prop

type holder struct {
	items  []int
	matrix [][]int
}

var (
	seed    = holder{items: []int{1, 2}, matrix: [][]int{{3, 4}}}
	extSink []int
	extMat  [][]int
)

func readHelper(s []int) int { return len(s) }
func mutHelper(s []int)      { s[0] = 42 }
func pairSeed() (int, []int) { return 1, seed.items }
func pairClean() (int, []int) { return 1, make([]int, 2) }

func Run() ([]int, [][]int, int) {
	s0 := seed.items
	s1 := make([]int, 2)
	s2 := []int{7, 8}
	c0 := make([][]int, 1)
`)
		if cShared {
			sb.WriteString("\talias0 := c0\n")
		} else {
			sb.WriteString("\talias0 := make([][]int, 1)\n")
		}
		sb.WriteString("\tacc := 0\n")

		steps := rapid.IntRange(2, 6).Draw(rt, "steps")
		for step := 0; step < steps; step++ {
			op := rapid.IntRange(0, 8).Draw(rt, fmt.Sprintf("op_%d", step))
			dst := rapid.IntRange(0, numLocals-1).Draw(rt, fmt.Sprintf("dst_%d", step))
			src := rapid.IntRange(0, numLocals-1).Draw(rt, fmt.Sprintf("src_%d", step))
			switch op {
			case 0: // bare copy s_dst = s_src
				fmt.Fprintf(&sb, "\ts%d = s%d\n", dst, src)
				seedBacked[dst] = seedBacked[src]
			case 1: // bare rebind to clean slice literal
				fmt.Fprintf(&sb, "\ts%d = []int{10, 20}\n", dst)
				seedBacked[dst] = false
			case 2: // multi-return unpack from pairSeed or pairClean
				fromSeed := rapid.Bool().Draw(rt, fmt.Sprintf("pair_seed_%d", step))
				if fromSeed {
					fmt.Fprintf(&sb, "\t_, s%d = pairSeed()\n", dst)
					seedBacked[dst] = true
				} else {
					fmt.Fprintf(&sb, "\t_, s%d = pairClean()\n", dst)
					seedBacked[dst] = false
				}
			case 3: // store s_src into c0[0]
				fmt.Fprintf(&sb, "\tc0[0] = s%d\n", src)
				if seedBacked[src] {
					cHasSeed = true
				}
			case 4: // read helper + scalar read
				fmt.Fprintf(&sb, "\tacc += readHelper(s%d) + len(c0[0])\n", src)
			case 5: // element write s_dst[0] = 99
				fmt.Fprintf(&sb, "\ts%d[0] = 99\n", dst)
				if seedBacked[dst] {
					violated = true
				}
			case 6: // mutating helper call mutHelper(s_src)
				fmt.Fprintf(&sb, "\tmutHelper(s%d)\n", src)
				if seedBacked[src] {
					violated = true
				}
			case 7: // nested element write through alias0[0][0] = 5
				fmt.Fprintf(&sb, "\talias0[0][0] = 5\n")
				if cShared && cHasSeed {
					violated = true
				}
			case 8: // store s_src to package global extSink
				fmt.Fprintf(&sb, "\textSink = s%d\n", src)
				if seedBacked[src] {
					violated = true
				}
			}
		}

		retSlice := rapid.IntRange(-1, numLocals-1).Draw(rt, "retSlice")
		retAlias := rapid.Bool().Draw(rt, "retAlias")
		retSliceExpr := "nil"
		if retSlice >= 0 {
			retSliceExpr = fmt.Sprintf("s%d", retSlice)
			if seedBacked[retSlice] {
				violated = true
			}
		}
		retMatExpr := "nil"
		if retAlias {
			retMatExpr = "alias0"
			if cShared && cHasSeed {
				violated = true
			}
		}
		sb.WriteString("\t_ = s0; _ = s1; _ = s2; _ = c0; _ = alias0\n")
		fmt.Fprintf(&sb, "\treturn %s, %s, acc\n}\n", retSliceExpr, retMatExpr)

		srcCode := sb.String()
		// Note: flow-insensitive local taint is sound (over-approximating bare rebind
		// `s_i = clean` when `s_i` was previously tainted in the same body). Recompute
		// exact flow-insensitive monotone taint oracle over the generated ops so we check
		// both soundness (violated => !got) AND exactness against the monotone specification!
		monoTainted := [numLocals]bool{true, false, false}
		// Iterate monotone equations on the generated source lines:
		lines := strings.Split(srcCode, "\n")
		monoCHasSeed := false
		for changed := true; changed; {
			changed = false
			for _, ln := range lines {
				ln = strings.TrimSpace(ln)
				for d := 0; d < numLocals; d++ {
					for s := 0; s < numLocals; s++ {
						if ln == fmt.Sprintf("s%d = s%d", d, s) && monoTainted[s] && !monoTainted[d] {
							monoTainted[d] = true
							changed = true
						}
					}
					if ln == fmt.Sprintf("_, s%d = pairSeed()", d) && !monoTainted[d] {
						monoTainted[d] = true
						changed = true
					}
				}
				for s := 0; s < numLocals; s++ {
					if ln == fmt.Sprintf("c0[0] = s%d", s) && monoTainted[s] && !monoCHasSeed {
						monoCHasSeed = true
						changed = true
					}
				}
			}
		}
		monoViolated := false
		for _, ln := range lines {
			ln = strings.TrimSpace(ln)
			for d := 0; d < numLocals; d++ {
				if (ln == fmt.Sprintf("s%d[0] = 99", d) ||
					ln == fmt.Sprintf("mutHelper(s%d)", d) ||
					ln == fmt.Sprintf("extSink = s%d", d)) && monoTainted[d] {
					monoViolated = true
				}
			}
			if ln == "alias0[0][0] = 5" && cShared && monoCHasSeed {
				monoViolated = true
			}
		}
		if retSlice >= 0 && monoTainted[retSlice] {
			monoViolated = true
		}
		if retAlias && cShared && monoCHasSeed {
			monoViolated = true
		}

		pkg := mustTypecheckPkg(t, "example.com/prop", srcCode)
		seedObj := pkg.Types.Scope().Lookup("seed").(*types.Var)
		holderNamed := pkg.Types.Scope().Lookup("holder").(*types.TypeName).Type().(*types.Named)
		var rejClause string
		got := VerifyReadOnlyRefConfinement(pkg, Config{
			SeedExpr: func(expr ast.Expr) (bool, bool) {
				if id, ok := ast.Unparen(expr).(*ast.Ident); ok && pkg.TypesInfo.Uses[id] == seedObj {
					return false, true
				}
				return false, false
			},
			SeedStructOrigin: func(named *types.Named) bool {
				return named != nil && named.Origin() == holderNamed.Origin()
			},
			AllowReturnFromUnexportedFunc: true,
			OnReject: func(_ token.Pos, clause string) {
				if rejClause == "" {
					rejClause = clause
				}
			},
		})
		if violated && got {
			rt.Fatalf("unsound acceptance on dynamic seed violation!\nsrc:\n%s", srcCode)
		}
		want := !monoViolated
		if got != want {
			rt.Fatalf("VerifyReadOnlyRefConfinement = %v, want %v (rejClause=%q)\nsrc:\n%s", got, want, rejClause, srcCode)
		}
		if !got && rejClause == "" {
			rt.Fatalf("rejected without OnReject diagnostic\nsrc:\n%s", srcCode)
		}
	})
}
