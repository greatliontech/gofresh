package asmverify

import (
	"go/constant"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/closure/internal/cprep"
)

func parseAsmFrameSlotOffset(opnd string) (int, bool) {
	opnd = strings.TrimSpace(opnd)
	if !strings.HasSuffix(opnd, "(FP)") {
		return 0, false
	}
	head := strings.TrimSuffix(opnd, "(FP)")
	plus := strings.LastIndexByte(head, '+')
	if plus <= 0 {
		return 0, false
	}
	ident := head[:plus]
	for i := 0; i < len(ident); i++ {
		if !cprep.IsASCIIIdentByte(ident[i]) || (i == 0 && ident[i] >= '0' && ident[i] <= '9') {
			return 0, false
		}
	}
	off, err := strconv.Atoi(head[plus+1:])
	if err != nil || off < 0 {
		return 0, false
	}
	return off, true
}

func verifyCanonicalCPUIDTextBlock(blk asmTextBlock) (int, bool) {
	if len(blk.labels) != 0 || len(blk.lines) == 0 {
		return 0, false
	}
	phase := 0 // 0 = pre-CPUID, 1 = post-CPUID, 2 = post-RET
	loadedAX := false
	cxMode := 0 // 0 = unset, 1 = zeroed (1-arg), 2 = loaded +4(FP) (2-arg)
	var storeOff [4]int
	storedMask := 0
	seenText := false

	for _, line := range blk.lines {
		if line.condOp != asmCondNone || line.condDepth != blk.openCondDepth || len(line.choices) != 1 {
			return 0, false
		}
		for _, stmt := range splitAsmStatements(line.choices[0]) {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if _, _, hasLbl := cutAsmLabel(stmt); hasLbl {
				return 0, false
			}
			op, rest := splitAsmOp(stmt)
			uop := strings.ToUpper(op)
			if uop == "TEXT" {
				if seenText || phase != 0 {
					return 0, false
				}
				seenText = true
				continue
			}
			switch phase {
			case 0:
				if uop == "CPUID" && rest == "" {
					if !loadedAX || (cxMode != 1 && cxMode != 2) {
						return 0, false
					}
					phase = 1
					continue
				}
				operands := splitAsmOperands(rest)
				if len(operands) != 2 {
					return 0, false
				}
				src := strings.TrimSpace(operands[0])
				dst := strings.ToUpper(strings.TrimSpace(operands[1]))
				switch uop {
				case "MOVL":
					if dst == "AX" {
						off, ok := parseAsmFrameSlotOffset(src)
						if !ok || off != 0 || loadedAX {
							return 0, false
						}
						loadedAX = true
						continue
					}
					if dst == "CX" {
						if src == "$0" {
							if cxMode != 0 {
								return 0, false
							}
							cxMode = 1
							continue
						}
						off, ok := parseAsmFrameSlotOffset(src)
						if !ok || off != 4 || cxMode != 0 {
							return 0, false
						}
						cxMode = 2
						continue
					}
				case "MOVQ":
					if dst == "CX" && src == "$0" && cxMode == 0 {
						cxMode = 1
						continue
					}
				case "XORL", "XORQ":
					if strings.EqualFold(src, "CX") && dst == "CX" && cxMode == 0 {
						cxMode = 1
						continue
					}
				}
				return 0, false
			case 1:
				if uop == "RET" && rest == "" {
					phase = 2
					continue
				}
				if uop != "MOVL" {
					return 0, false
				}
				operands := splitAsmOperands(rest)
				if len(operands) != 2 {
					return 0, false
				}
				src := strings.ToUpper(strings.TrimSpace(operands[0]))
				off, ok := parseAsmFrameSlotOffset(operands[1])
				if !ok {
					return 0, false
				}
				regIdx := -1
				switch src {
				case "AX":
					regIdx = 0
				case "BX":
					regIdx = 1
				case "CX":
					regIdx = 2
				case "DX":
					regIdx = 3
				default:
					return 0, false
				}
				if storedMask&(1<<regIdx) != 0 {
					return 0, false
				}
				storedMask |= 1 << regIdx
				storeOff[regIdx] = off
			default:
				return 0, false
			}
		}
	}
	if phase != 2 || storedMask != 0x0f {
		return 0, false
	}
	retBase := storeOff[0]
	if retBase != 8 || storeOff[1] != retBase+4 || storeOff[2] != retBase+8 || storeOff[3] != retBase+12 {
		return 0, false
	}
	if cxMode == 1 {
		return 1, true
	}
	if cxMode == 2 {
		return 2, true
	}
	return 0, false
}

// CPUIDCallReadsPerCoreState reports whether an SSA call to a canonical CPUID
// wrapper may observe per-core APIC/topology bits.
func CPUIDCallReadsPerCoreState(c *ssa.CallCommon, site ssa.CallInstruction) bool {
	if c == nil || site == nil || len(c.Args) == 0 {
		return true
	}
	callVal, ok := site.(*ssa.Call)
	if !ok {
		return true
	}
	leaves, known := evalBoundedUint32Leaves(c.Args[0], site.Block(), 0)
	tup, isTuple := callVal.Type().Underlying().(*types.Tuple)
	if !isTuple || tup.Len() != 4 {
		if !known {
			return true
		}
		for _, leaf := range leaves {
			if isPerCoreCPUIDLeaf(leaf) {
				return true
			}
		}
		return false
	}
	if callVal.Referrers() == nil {
		return false
	}
	var extracts [4][]*ssa.Extract
	for _, ref := range *callVal.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Extract:
			if r.Tuple != callVal || r.Index < 0 || r.Index >= 4 {
				return true
			}
			extracts[r.Index] = append(extracts[r.Index], r)
		default:
			return true
		}
	}
	hasUsedExtract := func(idx int) bool {
		for _, ex := range extracts[idx] {
			if ex.Referrers() == nil {
				continue
			}
			for _, ref := range *ex.Referrers() {
				if _, isDbg := ref.(*ssa.DebugRef); !isDbg {
					return true
				}
			}
		}
		return false
	}
	extractMasksBits := func(idx int, forbiddenMask uint32) bool {
		for _, ex := range extracts[idx] {
			if !ssaUint32MasksOutBits(ex, forbiddenMask, 0) {
				return false
			}
		}
		return true
	}

	mayBeLeaf := func(target uint32) bool {
		if !known {
			return true
		}
		for _, l := range leaves {
			if l == target {
				return true
			}
		}
		return false
	}

	// Leaf 0x01: EBX[31:24] holds Initial APIC ID of the current logical processor.
	if mayBeLeaf(0x01) && !extractMasksBits(1, 0xff000000) {
		return true
	}
	// Leaves 0x0B, 0x1F, 0x80000026: EDX[31:0] holds x2APIC / Extended APIC ID.
	if (mayBeLeaf(0x0b) || mayBeLeaf(0x1f) || mayBeLeaf(0x80000026)) && hasUsedExtract(3) {
		return true
	}
	// AMD Leaf 0x8000001E: EAX holds ExtendedApicId; EBX[7:0] holds ComputeUnitId; ECX[7:0] holds NodeId.
	if mayBeLeaf(0x8000001e) {
		if hasUsedExtract(0) || !extractMasksBits(1, 0x000000ff) || !extractMasksBits(2, 0x000000ff) {
			return true
		}
	}
	return false
}

func isPerCoreCPUIDLeaf(leaf uint32) bool {
	switch leaf {
	case 0x01, 0x0b, 0x1f, 0x8000001e, 0x80000026:
		return true
	default:
		return false
	}
}

func ssaUint32MasksOutBits(v ssa.Value, forbiddenMask uint32, depth int) bool {
	if forbiddenMask == 0 {
		return true
	}
	if v == nil || depth > 4 {
		return false
	}
	if v.Referrers() == nil {
		return true
	}
	for _, ref := range *v.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
			continue
		case *ssa.BinOp:
			switch r.Op {
			case token.AND:
				var c *ssa.Const
				if r.X == v {
					c, _ = r.Y.(*ssa.Const)
				} else if r.Y == v {
					c, _ = r.X.(*ssa.Const)
				}
				if c == nil {
					return false
				}
				mask, ok := constUint32(c)
				if !ok {
					return false
				}
				if mask&forbiddenMask == 0 {
					continue
				}
				if !ssaUint32MasksOutBits(r, forbiddenMask&mask, depth+1) {
					return false
				}
			case token.SHR:
				if r.X != v {
					return false
				}
				c, ok := r.Y.(*ssa.Const)
				if !ok {
					return false
				}
				shift, ok := constUint32(c)
				if !ok || shift >= 32 {
					if ok && shift >= 32 {
						continue
					}
					return false
				}
				shiftedForbidden := forbiddenMask >> shift
				if !ssaUint32MasksOutBits(r, shiftedForbidden, depth+1) {
					return false
				}
			case token.SHL:
				if r.X != v {
					return false
				}
				c, ok := r.Y.(*ssa.Const)
				if !ok {
					return false
				}
				shift, ok := constUint32(c)
				if !ok || shift >= 32 {
					if ok && shift >= 32 {
						continue
					}
					return false
				}
				shiftedForbidden := forbiddenMask << shift
				if !ssaUint32MasksOutBits(r, shiftedForbidden, depth+1) {
					return false
				}
			default:
				return false
			}
		case *ssa.Convert:
			b, ok := r.Type().Underlying().(*types.Basic)
			if !ok {
				return false
			}
			var narrowMask uint32 = 0xffffffff
			switch b.Kind() {
			case types.Uint8, types.Int8:
				narrowMask = 0x000000ff
			case types.Uint16, types.Int16:
				narrowMask = 0x0000ffff
			}
			if forbiddenMask&narrowMask == 0 {
				continue
			}
			if !ssaUint32MasksOutBits(r, forbiddenMask&narrowMask, depth+1) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func constUint32(c *ssa.Const) (uint32, bool) {
	if c == nil || c.Value == nil || c.Value.Kind() != constant.Int {
		return 0, false
	}
	v, ok := constant.Uint64Val(c.Value)
	if !ok || v > 0xffffffff {
		return 0, false
	}
	return uint32(v), true
}

func evalBoundedUint32Leaves(v ssa.Value, useBlock *ssa.BasicBlock, depth int) ([]uint32, bool) {
	if v == nil || depth > 4 {
		return nil, false
	}
	switch x := v.(type) {
	case *ssa.Const:
		u, ok := constUint32(x)
		if !ok {
			return nil, false
		}
		return []uint32{u}, true
	case *ssa.Convert:
		b, ok := x.Type().Underlying().(*types.Basic)
		if !ok || (b.Info()&types.IsInteger) == 0 {
			return nil, false
		}
		return evalBoundedUint32Leaves(x.X, useBlock, depth+1)
	case *ssa.BinOp:
		if x.Op == token.ADD {
			left, lok := evalBoundedUint32Leaves(x.X, useBlock, depth+1)
			right, rok := evalBoundedUint32Leaves(x.Y, useBlock, depth+1)
			if !lok || !rok || len(left)*len(right) > 16 {
				return nil, false
			}
			out := make([]uint32, 0, len(left)*len(right))
			for _, l := range left {
				for _, r := range right {
					out = append(out, l+r)
				}
			}
			return out, true
		}
	case *ssa.Phi:
		if len(x.Edges) == 2 && x.Block() != nil && useBlock != nil {
			stepIdx := 1
			initConst, ok0 := x.Edges[0].(*ssa.Const)
			stepOp, ok1 := x.Edges[1].(*ssa.BinOp)
			if !ok0 || !ok1 {
				stepIdx = 0
				initConst, ok0 = x.Edges[1].(*ssa.Const)
				stepOp, ok1 = x.Edges[0].(*ssa.BinOp)
			}
			if ok0 && ok1 && stepOp.Op == token.ADD {
				lo, loOK := constUint32(initConst)
				var stepConst *ssa.Const
				if stepOp.X == x {
					stepConst, _ = stepOp.Y.(*ssa.Const)
				} else if stepOp.Y == x {
					stepConst, _ = stepOp.X.(*ssa.Const)
				}
				step, stepOK := constUint32(stepConst)
				if loOK && stepOK && step == 1 {
					if hi, hiOK := phiBoundedLoopUpperBound(x, stepOp, stepIdx, useBlock); hiOK && hi > lo && hi <= 0x7fffffff && hi-lo <= 16 {
						out := make([]uint32, 0, hi-lo)
						for cur := lo; cur < hi; cur++ {
							out = append(out, cur)
						}
						return out, true
					}
				}
			}
		}
	}
	return nil, false
}

func phiBoundedLoopUpperBound(phi *ssa.Phi, stepOp *ssa.BinOp, stepIdx int, useBlock *ssa.BasicBlock) (uint32, bool) {
	blk := phi.Block()
	if blk == nil || useBlock == nil {
		return 0, false
	}
	if len(blk.Instrs) > 0 && len(blk.Succs) == 2 && blk.Succs[0] != blk.Succs[1] {
		if ifInstr, ok := blk.Instrs[len(blk.Instrs)-1].(*ssa.If); ok {
			if blk.Succs[0] == useBlock || blk.Succs[0].Dominates(useBlock) {
				if hi, ok := cmpStrictUpperBound(ifInstr.Cond, phi, true); ok {
					return hi, true
				}
			} else if blk.Succs[1] == useBlock || blk.Succs[1].Dominates(useBlock) {
				if hi, ok := cmpStrictUpperBound(ifInstr.Cond, phi, false); ok {
					return hi, true
				}
			}
		}
	}
	if (blk == useBlock || blk.Dominates(useBlock)) && stepIdx >= 0 && stepIdx < len(blk.Preds) {
		predStep := blk.Preds[stepIdx]
		if predStep != nil && stepOp.Block() == predStep && len(predStep.Instrs) > 0 && len(predStep.Succs) == 2 && predStep.Succs[0] != predStep.Succs[1] {
			if ifInstr, ok := predStep.Instrs[len(predStep.Instrs)-1].(*ssa.If); ok {
				if predStep.Succs[0] == blk {
					return cmpStrictUpperBound(ifInstr.Cond, stepOp, true)
				}
				if predStep.Succs[1] == blk {
					return cmpStrictUpperBound(ifInstr.Cond, stepOp, false)
				}
			}
		}
	}
	return 0, false
}

func cmpStrictUpperBound(cond, target ssa.Value, wantTrue bool) (uint32, bool) {
	cmp, ok := cond.(*ssa.BinOp)
	if !ok {
		return 0, false
	}
	op := cmp.Op
	if !wantTrue {
		switch op {
		case token.GEQ:
			op = token.LSS
		case token.GTR:
			op = token.LEQ
		case token.LEQ:
			op = token.GTR
		case token.LSS:
			op = token.GEQ
		default:
			return 0, false
		}
	}
	switch op {
	case token.LSS:
		if cmp.X == target {
			if c, ok := cmp.Y.(*ssa.Const); ok {
				return constUint32(c)
			}
		}
	case token.LEQ:
		if cmp.X == target {
			if c, ok := cmp.Y.(*ssa.Const); ok {
				if hi, ok := constUint32(c); ok && hi < 0xffffffff {
					return hi + 1, true
				}
			}
		}
	case token.GTR:
		if cmp.Y == target {
			if c, ok := cmp.X.(*ssa.Const); ok {
				return constUint32(c)
			}
		}
	case token.GEQ:
		if cmp.Y == target {
			if c, ok := cmp.X.(*ssa.Const); ok {
				if hi, ok := constUint32(c); ok && hi < 0xffffffff {
					return hi + 1, true
				}
			}
		}
	}
	return 0, false
}
