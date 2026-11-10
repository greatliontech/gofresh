package closure

import (
	"go/token"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// cellOf resolves a load's address to the local allocation it names —
// the allocation itself, or a free variable bound to it by every
// closure creation of its function (a free variable bound to different
// cells across creations names none). Nothing else is a cell.
func cellOf(addr ssa.Value, seen map[ssa.Value]bool) *ssa.Alloc {
	switch a := addr.(type) {
	case *ssa.Alloc:
		return a
	case *ssa.FieldAddr:
		return cellOf(a.X, seen)
	case *ssa.IndexAddr:
		return cellOf(a.X, seen)
	case *ssa.FreeVar:
		if seen[a] {
			return nil
		}
		seen[a] = true
		var cell *ssa.Alloc
		index := slices.Index(a.Parent().FreeVars, a)
		if index < 0 {
			return nil
		}
		for _, mk := range closureCreations(a.Parent()) {
			// A creation binding this free variable to a different cell
			// than another creation did names none: one closure body,
			// two cells — the fail-closed backstop no fixture
			// constructs.
			if index >= len(mk.Bindings) {
				return nil
			}
			bound := cellOf(mk.Bindings[index], seen)
			if bound == nil || (cell != nil && bound != cell) {
				return nil
			}
			cell = bound
		}
		return cell
	}
	return nil
}

// closureCreations lists the MakeClosure instructions creating fn.
func closureCreations(fn *ssa.Function) []*ssa.MakeClosure {
	var creations []*ssa.MakeClosure
	if fn == nil || fn.Parent() == nil {
		return nil
	}
	for _, block := range fn.Parent().Blocks {
		for _, instr := range block.Instrs {
			if mk, ok := instr.(*ssa.MakeClosure); ok && mk.Fn == fn {
				creations = append(creations, mk)
			}
		}
	}
	return creations
}

// walkLoadCellReferrers walks every referrer of the local cell backing loadAddr,
// failing closed on any address escape or non-zero whole-struct overwrite when
// loadAddr selects a specific field, and applying walkVal only to stores that
// can populate loadAddr.
func walkLoadCellReferrers(loadAddr ssa.Value, walkVal func(ssa.Value) bool) bool {
	return walkLoadCellReferrersWithFP(loadAddr, nil, walkVal)
}

func structElemCellOf(addr ssa.Value, seen map[ssa.Value]bool) *ssa.Alloc {
	switch a := addr.(type) {
	case *ssa.Alloc:
		return a
	case *ssa.IndexAddr:
		return structElemCellOf(a.X, seen)
	case *ssa.Slice:
		return structElemCellOf(a.X, seen)
	case *ssa.FreeVar:
		if seen[a] {
			return nil
		}
		seen[a] = true
		var cell *ssa.Alloc
		index := slices.Index(a.Parent().FreeVars, a)
		if index < 0 {
			return nil
		}
		for _, mk := range closureCreations(a.Parent()) {
			if index >= len(mk.Bindings) {
				return nil
			}
			bound := structElemCellOf(mk.Bindings[index], seen)
			if bound == nil || (cell != nil && bound != cell) {
				return nil
			}
			cell = bound
		}
		return cell
	}
	return nil
}

func walkLoadCellReferrersWithFP(loadAddr ssa.Value, fp *freshParamAnalysis, walkVal func(ssa.Value) bool) bool {
	if fa, ok := loadAddr.(*ssa.FieldAddr); ok {
		cell := cellOf(loadAddr, map[ssa.Value]bool{})
		if cell != nil {
			if _, isFV := fa.X.(*ssa.FreeVar); fa.X == cell || isFV {
				return walkValueFieldReferrersWithFP(cell, fa.Field, map[ssa.Value]bool{}, fp, walkVal)
			}
		}
		if fp != nil && fp.selectionAudited {
			if elemCell := structElemCellOf(fa.X, map[ssa.Value]bool{}); elemCell != nil {
				return walkValueFieldReferrersWithFP(elemCell, fa.Field, map[ssa.Value]bool{}, fp, walkVal)
			}
		}
		if cell == nil {
			return false
		}
		return walkCellReferrersWithFP(cell, map[ssa.Value]bool{}, fp, walkVal)
	}
	cell := cellOf(loadAddr, map[ssa.Value]bool{})
	if cell == nil {
		return false
	}
	return walkCellReferrersWithFP(cell, map[ssa.Value]bool{}, fp, walkVal)
}

func walkValueFieldReferrersWithFP(target ssa.Value, fieldIdx int, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool) bool {
	if visited[target] {
		return true
	}
	visited[target] = true
	refs := target.Referrers()
	if refs == nil {
		return true
	}
	noEscapeOnly := func(ssa.Value) bool { return true }
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Store:
			if r.Addr != target {
				return false
			}
			if c, isZero := r.Val.(*ssa.Const); isZero && c.Value == nil {
				continue
			}
			if fp != nil && fp.selectionAudited {
				if u, ok := r.Val.(*ssa.UnOp); ok && u.Op == token.MUL {
					if elemCell := structElemCellOf(u.X, map[ssa.Value]bool{}); elemCell != nil && elemCell != target {
						if walkValueFieldReferrersWithFP(elemCell, fieldIdx, visited, fp, walkVal) {
							continue
						}
					}
				}
			}
			return false
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != target {
				return false
			}
		case *ssa.Slice:
			if fp == nil || !fp.selectionAudited || r.X != target || !walkValueFieldReferrersWithFP(r, fieldIdx, visited, fp, walkVal) {
				return false
			}
		case *ssa.IndexAddr:
			if fp == nil || !fp.selectionAudited || r.X != target || !walkValueFieldReferrersWithFP(r, fieldIdx, visited, fp, walkVal) {
				return false
			}
		case *ssa.Call:
			if fp == nil || !fp.selectionAudited || r.Common() == nil || r.Common().IsInvoke() || len(r.Common().Args) != 1 || r.Common().Args[0] != target {
				return false
			}
			b, ok := r.Common().Value.(*ssa.Builtin)
			if !ok || (b.Name() != "len" && b.Name() != "cap") {
				return false
			}
		case *ssa.FieldAddr:
			if r.X != target {
				return false
			}
			cb := noEscapeOnly
			if r.Field == fieldIdx {
				cb = walkVal
			}
			if !walkCellReferrersWithFP(r, visited, fp, cb) {
				return false
			}
		case *ssa.MakeClosure:
			fn, ok := r.Fn.(*ssa.Function)
			if !ok {
				return false
			}
			for i, b := range r.Bindings {
				if b == target {
					if i >= len(fn.FreeVars) || !walkValueFieldReferrersWithFP(fn.FreeVars[i], fieldIdx, visited, fp, walkVal) {
						return false
					}
				}
			}
		default:
			return false
		}
	}
	return true
}

// walkCellReferrersWithFP walks every referrer of a local cell (and of every free
// variable a closure binds to it, recursively), applying walkVal to each
// stored value and failing closed on any address escape.
func walkCellReferrersWithFP(alias ssa.Value, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool) bool {
	if visited[alias] {
		return true
	}
	visited[alias] = true
	refs := alias.Referrers()
	if refs == nil {
		return true
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Store:
			if r.Addr != alias {
				return false
			}
			if u, ok := r.Val.(*ssa.UnOp); ok && u.Op == token.MUL && cellOf(u.X, map[ssa.Value]bool{}) == cellOf(alias, map[ssa.Value]bool{}) {
				return false
			}
			if appendElem := selfCellAppendElem(alias, r.Val); appendElem != nil {
				if !walkVal(appendElem) {
					return false
				}
				continue
			}
			if !walkVal(r.Val) {
				return false
			}
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != alias {
				return false
			}
			if r.Type() != nil {
				if _, isSlice := types.Unalias(r.Type()).Underlying().(*types.Slice); isSlice {
					elemWalk := walkVal
					if fp == nil || !fp.selectionAudited {
						elemWalk = func(ssa.Value) bool { return false }
					}
					if !walkMakeSliceIndexedStoresWithFP(r, visited, fp, elemWalk) {
						return false
					}
				}
			}
		case *ssa.Slice:
			if r.X != alias || !walkMakeSliceIndexedStoresWithFP(r, visited, fp, walkVal) {
				return false
			}
		case *ssa.FieldAddr:
			if r.X != alias || !walkCellReferrersWithFP(r, visited, fp, walkVal) {
				return false
			}
		case *ssa.IndexAddr:
			if r.X != alias || !walkCellReferrersWithFP(r, visited, fp, walkVal) {
				return false
			}
		case *ssa.MakeClosure:
			fn, ok := r.Fn.(*ssa.Function)
			if !ok {
				return false
			}
			for i, binding := range r.Bindings {
				if binding == alias {
					if i >= len(fn.FreeVars) || !walkCellReferrersWithFP(fn.FreeVars[i], visited, fp, walkVal) {
						return false
					}
				}
			}
		default:
			return false
		}
	}
	return true
}

func selfCellAppendElem(alias, val ssa.Value) ssa.Value {
	call, ok := val.(*ssa.Call)
	if !ok || call.Common() == nil {
		return nil
	}
	b, ok := call.Common().Value.(*ssa.Builtin)
	if !ok || b.Name() != "append" || len(call.Common().Args) != 2 {
		return nil
	}
	load, ok := call.Common().Args[0].(*ssa.UnOp)
	if !ok || load.Op != token.MUL || load.X != alias {
		return nil
	}
	return call.Common().Args[1]
}

func walkMakeSliceIndexedStoresWithFP(s ssa.Value, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool) bool {
	if s == nil {
		return false
	}
	if visited[s] {
		return true
	}
	visited[s] = true
	refs := s.Referrers()
	if refs == nil {
		return true
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.BinOp:
			if r.Op != token.EQL && r.Op != token.NEQ {
				return false
			}
		case *ssa.IndexAddr:
			if r.X != s || !walkCellReferrersWithFP(r, visited, fp, walkVal) {
				return false
			}
		case *ssa.Slice:
			if r.X != s || !walkMakeSliceIndexedStoresWithFP(r, visited, fp, walkVal) {
				return false
			}
		case *ssa.Phi:
			if !walkMakeSliceIndexedStoresWithFP(r, visited, fp, walkVal) {
				return false
			}
		case *ssa.Return:
			if !walkContainerReturnReferrer(s, r, visited, fp, walkVal, walkMakeSliceIndexedStoresWithFP) {
				return false
			}
		case *ssa.MapUpdate:
			if r.Value != s || r.Map == s || fp == nil || !fp.selectionAudited || !walkMapSliceReadsWithFP(r.Map, visited, fp, walkVal) {
				return false
			}
		case *ssa.Store:
			if !walkContainerStoreReferrer(s, r, visited, fp, walkVal, walkMakeSliceIndexedStoresWithFP) {
				return false
			}
		case *ssa.MakeInterface:
			if r.X != s || fp == nil || !fp.selectionAudited || !makeInterfaceOnlyVarargsLogged(r, fp.selectionAudited) {
				return false
			}
		case ssa.CallInstruction:
			if r.Common() == nil {
				return false
			}
			if b, ok := r.Common().Value.(*ssa.Builtin); ok {
				if b.Name() == "len" || b.Name() == "cap" {
					continue
				}
				if b.Name() == "copy" && len(r.Common().Args) == 2 {
					if r.Common().Args[0] == s && !walkVal(r.Common().Args[1]) {
						return false
					}
					continue
				}
				if b.Name() == "append" && len(r.Common().Args) == 2 {
					if r.Common().Args[0] == s {
						if !walkVal(r.Common().Args[1]) {
							return false
						}
						if rVal, ok := r.(ssa.Value); !ok || !walkMakeSliceIndexedStoresWithFP(rVal, visited, fp, walkVal) {
							return false
						}
					}
					continue
				}
				return false
			}
			if _, isGo := r.(*ssa.Go); isGo {
				return false
			}
			if r.Common().IsInvoke() {
				if fp == nil || !fp.selectionAudited || r.Common().Value == s {
					return false
				}
				targets, ok := closedInvokeTargets(r, fp)
				if !ok {
					return false
				}
				for callee := range targets {
					if callee == nil || len(callee.Blocks) == 0 || len(r.Common().Args)+1 != len(callee.Params) {
						return false
					}
					for i, arg := range r.Common().Args {
						if arg == s && !walkMakeSliceIndexedStoresWithFP(callee.Params[i+1], visited, fp, walkVal) {
							return false
						}
					}
				}
				continue
			}
			callee := r.Common().StaticCallee()
			if fp != nil && fp.selectionAudited && callee != nil && funcPkgPath(callee) == "slices" {
				if admitted, aliasesReturn := isAuditedSlicesCallForSlice(functionSymbolName(callee), r.Common().Args, s); admitted {
					if aliasesReturn {
						if rVal, ok := r.(ssa.Value); ok && !walkMakeSliceIndexedStoresWithFP(rVal, visited, fp, walkVal) {
							return false
						}
					}
					continue
				}
			}
			if callee == nil || len(callee.Blocks) == 0 || len(r.Common().Args) != len(callee.Params) {
				return false
			}
			for i, arg := range r.Common().Args {
				if arg == s && !walkMakeSliceIndexedStoresWithFP(callee.Params[i], visited, fp, walkVal) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func isAuditedSlicesCallForSlice(name string, args []ssa.Value, s ssa.Value) (admitted, aliasesReturn bool) {
	maxArgIdx := 0
	switch name {
	case "Compact", "CompactFunc":
		aliasesReturn = true
	case "Equal", "EqualFunc", "Compare", "CompareFunc":
		maxArgIdx = 1
	case "Clone", "Sort", "SortFunc", "SortStableFunc", "Reverse",
		"IsSorted", "IsSortedFunc", "BinarySearch", "BinarySearchFunc",
		"Index", "IndexFunc", "Contains", "ContainsFunc",
		"Min", "MinFunc", "Max", "MaxFunc":
	default:
		return false, false
	}
	found := false
	for i, arg := range args {
		if arg == s {
			if i > maxArgIdx {
				return false, false
			}
			found = true
		}
	}
	if !found {
		return false, false
	}
	return true, aliasesReturn
}

func walkContainerReturnReferrer(container ssa.Value, r *ssa.Return, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool, walkContainer func(ssa.Value, map[ssa.Value]bool, *freshParamAnalysis, func(ssa.Value) bool) bool) bool {
	if fp == nil || !fp.selectionAudited || r.Parent() == nil {
		return false
	}
	fn := r.Parent()
	if !fp.calleeSeen[fn] {
		if fp.programValueRef[fn] || len(fp.programSites[fn]) == 0 {
			return false
		}
		for retIdx, res := range r.Results {
			if res != container {
				continue
			}
			for _, site := range fp.programSites[fn] {
				if !walkCallResultContainerWithFP(site, retIdx, len(r.Results), visited, fp, walkVal, walkContainer) {
					return false
				}
			}
		}
	}
	return true
}

func walkContainerStoreReferrer(container ssa.Value, r *ssa.Store, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool, walkContainer func(ssa.Value, map[ssa.Value]bool, *freshParamAnalysis, func(ssa.Value) bool) bool) bool {
	if r.Val != container || r.Addr == container || fp == nil || !fp.selectionAudited {
		return false
	}
	switch addr := r.Addr.(type) {
	case *ssa.Alloc, *ssa.FreeVar:
		cell := cellOf(addr, map[ssa.Value]bool{})
		return cell != nil && walkContainerCellLoadsWithFP(cell, visited, fp, walkVal, walkContainer)
	case *ssa.FieldAddr:
		if addr.X == nil || fp.summary == nil {
			return false
		}
		named := derefNamedStruct(fp.userPkgPaths(), addr.X.Type())
		if named == nil {
			return false
		}
		key := structFieldKey{named: named, field: addr.Field}
		if fp.structPoisoned[key] || !fp.structReferencedByType[named] {
			return false
		}
		for _, rd := range fp.summary.structFieldReads[key] {
			if !walkContainer(rd, visited, fp, walkVal) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func walkContainerCellLoadsWithFP(alias ssa.Value, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool, walkContainer func(ssa.Value, map[ssa.Value]bool, *freshParamAnalysis, func(ssa.Value) bool) bool) bool {
	if alias == nil {
		return false
	}
	if visited[alias] {
		return true
	}
	visited[alias] = true
	refs := alias.Referrers()
	if refs == nil {
		return true
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Store:
			if r.Addr != alias {
				return false
			}
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != alias || !walkContainer(r, visited, fp, walkVal) {
				return false
			}
		case *ssa.MakeClosure:
			fn, ok := r.Fn.(*ssa.Function)
			if !ok {
				return false
			}
			for i, binding := range r.Bindings {
				if binding == alias {
					if i >= len(fn.FreeVars) || !walkContainerCellLoadsWithFP(fn.FreeVars[i], visited, fp, walkVal, walkContainer) {
						return false
					}
				}
			}
		default:
			return false
		}
	}
	return true
}

func walkMapForwardReferrer(m ssa.Value, ref ssa.Instruction, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool, walkMap func(ssa.Value, map[ssa.Value]bool, *freshParamAnalysis, func(ssa.Value) bool) bool) bool {
	switch r := ref.(type) {
	case *ssa.BinOp:
		return r.Op == token.EQL || r.Op == token.NEQ
	case *ssa.Phi:
		return walkMap(r, visited, fp, walkVal)
	case *ssa.Store:
		return walkContainerStoreReferrer(m, r, visited, fp, walkVal, walkMap)
	case ssa.CallInstruction:
		if _, isGo := r.(*ssa.Go); isGo || r.Common() == nil {
			return false
		}
		if b, ok := r.Common().Value.(*ssa.Builtin); ok {
			return b.Name() == "len" || b.Name() == "delete" || b.Name() == "clear"
		}
		callee := r.Common().StaticCallee()
		if r.Common().IsInvoke() || callee == nil || len(callee.Blocks) == 0 || len(r.Common().Args) != len(callee.Params) {
			return false
		}
		for i, arg := range r.Common().Args {
			if arg == m && !walkMap(callee.Params[i], visited, fp, walkVal) {
				return false
			}
		}
		return true
	case *ssa.MakeClosure:
		fn, ok := r.Fn.(*ssa.Function)
		if !ok {
			return false
		}
		for i, binding := range r.Bindings {
			if binding == m {
				if i >= len(fn.FreeVars) || !walkMap(fn.FreeVars[i], visited, fp, walkVal) {
					return false
				}
			}
		}
		return true
	default:
		return false
	}
}

func makeInterfaceOnlyVarargsLogged(mi *ssa.MakeInterface, audited bool) bool {
	if mi == nil || mi.Referrers() == nil {
		return false
	}
	for _, ref := range *mi.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Store:
			if r.Val != mi || r.Addr == mi {
				return false
			}
			ia, ok := r.Addr.(*ssa.IndexAddr)
			if !ok {
				return false
			}
			alloc, ok := ia.X.(*ssa.Alloc)
			if !ok || alloc.Referrers() == nil {
				return false
			}
			for _, aref := range *alloc.Referrers() {
				switch ar := aref.(type) {
				case *ssa.DebugRef, *ssa.IndexAddr:
				case *ssa.Slice:
					if ar.X != alloc || ar.Referrers() == nil {
						return false
					}
					for _, sref := range *ar.Referrers() {
						switch sr := sref.(type) {
						case *ssa.DebugRef:
						case ssa.CallInstruction:
							if _, isGo := sr.(*ssa.Go); isGo || sr.Common() == nil || sr.Common().IsInvoke() {
								return false
							}
							callee := sr.Common().StaticCallee()
							if callee == nil {
								return false
							}
							if funcPkgPath(callee) == "fmt" {
								continue
							}
							if _, ok := harnessCalleeEffect(audited, callee, false); ok {
								continue
							}
							return false
						default:
							return false
						}
					}
				default:
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func walkMakeMapValuesWithFP(m ssa.Value, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool) bool {
	if m == nil {
		return false
	}
	if visited[m] {
		return true
	}
	visited[m] = true
	refs := m.Referrers()
	if refs == nil {
		return true
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Lookup:
			if r.X != m {
				return false
			}
		case *ssa.Range:
			if r.X != m {
				return false
			}
		case *ssa.Return:
			if !walkContainerReturnReferrer(m, r, visited, fp, walkVal, walkMakeMapValuesWithFP) {
				return false
			}
		case *ssa.MapUpdate:
			if r.Map != m || !walkVal(r.Value) {
				return false
			}
		default:
			if !walkMapForwardReferrer(m, r, visited, fp, walkVal, walkMakeMapValuesWithFP) {
				return false
			}
		}
	}
	return true
}

func walkMapSliceReadsWithFP(m ssa.Value, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool) bool {
	if m == nil {
		return false
	}
	if visited[m] {
		return true
	}
	visited[m] = true
	refs := m.Referrers()
	if refs == nil {
		return true
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.MapUpdate:
			if r.Map != m {
				return false
			}
		case *ssa.Lookup:
			if r.X != m {
				return false
			}
			if !r.CommaOk {
				if !walkMakeSliceIndexedStoresWithFP(r, visited, fp, walkVal) {
					return false
				}
				continue
			}
			if r.Referrers() != nil {
				for _, lref := range *r.Referrers() {
					switch lr := lref.(type) {
					case *ssa.DebugRef:
					case *ssa.Extract:
						if lr.Tuple != r {
							return false
						}
						if lr.Index == 0 && !walkMakeSliceIndexedStoresWithFP(lr, visited, fp, walkVal) {
							return false
						}
					default:
						return false
					}
				}
			}
		case *ssa.Range:
			if r.X != m {
				return false
			}
			if r.Referrers() != nil {
				for _, rref := range *r.Referrers() {
					switch rr := rref.(type) {
					case *ssa.DebugRef:
					case *ssa.Next:
						if rr.Iter != r {
							return false
						}
						if rr.Referrers() != nil {
							for _, nref := range *rr.Referrers() {
								switch nr := nref.(type) {
								case *ssa.DebugRef:
								case *ssa.Extract:
									if nr.Tuple != rr {
										return false
									}
									if nr.Index == 2 && !walkMakeSliceIndexedStoresWithFP(nr, visited, fp, walkVal) {
										return false
									}
								default:
									return false
								}
							}
						}
					default:
						return false
					}
				}
			}
		default:
			if !walkMapForwardReferrer(m, r, visited, fp, walkVal, walkMapSliceReadsWithFP) {
				return false
			}
		}
	}
	return true
}
