package observability

import (
	"go/token"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/auditset"
)

func verifyWrapperRootConfined(root ssa.Value, wk wrapperKind, fp *freshParamAnalysis, depth int, callStack map[*ssa.Function]wrapperCallFrame) (bool, string) {
	if root == nil || wk == wrapperNone || depth > 16 {
		return false, "wrapper_depth_or_nil"
	}
	ptrVisited := map[ssa.Value]bool{}
	ifaceVisited := map[ssa.Value]bool{}
	var ptrQueue []ssa.Value
	var ifaceQueue []ssa.Value
	downwardSites := map[*ssa.Function][]ssa.CallInstruction{}

	addPtr := func(v ssa.Value) {
		if v != nil && !ptrVisited[v] {
			ptrVisited[v] = true
			ptrQueue = append(ptrQueue, v)
		}
	}
	addIface := func(v ssa.Value) {
		if v != nil && !ifaceVisited[v] {
			ifaceVisited[v] = true
			ifaceQueue = append(ifaceQueue, v)
		}
	}
	addValByType := func(v ssa.Value) {
		if v == nil || v.Type() == nil {
			return
		}
		if _, isIf := types.Unalias(v.Type()).Underlying().(*types.Interface); isIf {
			addIface(v)
		} else {
			addPtr(v)
		}
	}
	propagateReturn := func(r *ssa.Return, val ssa.Value) bool {
		fn := r.Parent()
		if fn == nil {
			return false
		}
		if frame, inOrigin := callStack[fn]; inOrigin && frame.resultVal != nil {
			if frame.tupleIdx < 0 {
				if len(r.Results) != 1 || r.Results[0] != val {
					return false
				}
			} else {
				if frame.tupleIdx >= len(r.Results) || r.Results[frame.tupleIdx] != val {
					return false
				}
				for j, res := range r.Results {
					if j != frame.tupleIdx && res == val {
						return false
					}
				}
			}
			addValByType(frame.resultVal)
			return true
		}
		sites := downwardSites[fn]
		if len(sites) == 0 {
			return false
		}
		for _, site := range sites {
			sv := site.Value()
			if sv == nil {
				return false
			}
			if len(r.Results) == 1 {
				if r.Results[0] != val {
					return false
				}
				addValByType(sv)
				continue
			}
			if sv.Referrers() == nil {
				return false
			}
			for _, ref := range *sv.Referrers() {
				switch ex := ref.(type) {
				case *ssa.DebugRef:
				case *ssa.Extract:
					if ex.Index < 0 || ex.Index >= len(r.Results) {
						return false
					}
					if r.Results[ex.Index] == val {
						addValByType(ex)
					}
				default:
					return false
				}
			}
		}
		return true
	}
	addLocalCellLoads := func(alloc *ssa.Alloc, val ssa.Value, asIface bool) bool {
		if alloc == nil || alloc.Parent() != val.Parent() || alloc.Referrers() == nil {
			return false
		}
		for _, ref := range *alloc.Referrers() {
			switch r := ref.(type) {
			case *ssa.DebugRef:
			case *ssa.Store:
				if r.Addr != alloc || r.Val == alloc {
					return false
				}
			case *ssa.UnOp:
				if r.Op != token.MUL || r.X != alloc {
					return false
				}
				if asIface {
					addIface(r)
				} else {
					addPtr(r)
				}
			default:
				return false
			}
		}
		return true
	}
	addClosureCaptures := func(mc *ssa.MakeClosure, val ssa.Value, asIface bool) bool {
		fn, ok := mc.Fn.(*ssa.Function)
		if !ok || fn == nil || mc.Fn == val || fn == root.Parent() || callStack[fn].resultVal != nil {
			return false
		}
		if fp.summary != nil {
			if !fp.summary.strictLocalFunc[fn] || fp.programValueRef[fn] || len(fp.closures[fn]) == 0 {
				return false
			}
			for _, site := range fp.programSites[fn] {
				if site == nil {
					return false
				}
				if !slices.Contains(downwardSites[fn], site) {
					downwardSites[fn] = append(downwardSites[fn], site)
				}
			}
		} else {
			if fn.Parent() == nil || mc.Referrers() == nil {
				return false
			}
			for _, ref := range *mc.Referrers() {
				switch r := ref.(type) {
				case *ssa.DebugRef:
				case ssa.CallInstruction:
					if _, isGo := r.(*ssa.Go); isGo || r.Common() == nil || r.Common().IsInvoke() || r.Common().Value != mc || slices.Contains(r.Common().Args, ssa.Value(mc)) {
						return false
					}
					if !slices.Contains(downwardSites[fn], r) {
						downwardSites[fn] = append(downwardSites[fn], r)
					}
				default:
					return false
				}
			}
		}
		for i, b := range mc.Bindings {
			if b == val {
				if i >= len(fn.FreeVars) {
					return false
				}
				if asIface {
					addIface(fn.FreeVars[i])
				} else {
					addPtr(fn.FreeVars[i])
				}
			}
		}
		return true
	}
	propagateUserCall := func(site ssa.CallInstruction, val ssa.Value, asIface bool) bool {
		c := site.Common()
		if c == nil || c.IsInvoke() {
			return false
		}
		var targets []*ssa.Function
		if sc := c.StaticCallee(); sc != nil {
			targets = []*ssa.Function{sc}
		} else {
			resolved, ok := closedDynamicTargets(c.Value, resetWalkState(fp))
			if !ok || len(resolved) == 0 {
				return false
			}
			for t := range resolved {
				targets = append(targets, t)
			}
		}
		for _, callee := range targets {
			if callee == nil || callee == root.Parent() || callStack[callee].resultVal != nil || fp.isStdFunc(callee) || len(callee.Blocks) == 0 || parameterizedBody(callee) || callee.Signature == nil || callee.Signature.Variadic() || len(c.Args) != len(callee.Params) {
				return false
			}
			if !slices.Contains(downwardSites[callee], site) {
				downwardSites[callee] = append(downwardSites[callee], site)
			}
			for i, arg := range c.Args {
				if arg == val {
					if asIface {
						addIface(callee.Params[i])
					} else {
						addPtr(callee.Params[i])
					}
				}
			}
		}
		return true
	}

	addPtr(root)
	for len(ptrQueue) > 0 || len(ifaceQueue) > 0 {
		for len(ptrQueue) > 0 {
			v := ptrQueue[0]
			ptrQueue = ptrQueue[1:]
			refs := v.Referrers()
			if refs == nil {
				return false, "wrapper_nil_referrers"
			}
			for _, ref := range *refs {
				switch r := ref.(type) {
				case *ssa.DebugRef:
				case *ssa.Phi:
					addPtr(r)
				case *ssa.ChangeType:
					addPtr(r)
				case *ssa.BinOp:
					if r.Op != token.EQL && r.Op != token.NEQ {
						return false, "wrapper_binop"
					}
				case *ssa.Return:
					if !propagateReturn(r, v) {
						return false, "wrapper_escaped_return"
					}
				case *ssa.Store:
					alloc, ok := r.Addr.(*ssa.Alloc)
					if !ok || r.Val != v || !addLocalCellLoads(alloc, v, false) {
						return false, "wrapper_store_escape"
					}
				case *ssa.MakeClosure:
					if !addClosureCaptures(r, v, false) {
						return false, "wrapper_closure_escape"
					}
				case *ssa.MakeInterface:
					if r.X != v {
						return false, "wrapper_bad_make_iface"
					}
					addIface(r)
				case ssa.CallInstruction:
					if _, isGo := r.(*ssa.Go); isGo || r.Common() == nil {
						return false, "wrapper_go_call"
					}
					c := r.Common()
					if callee := c.StaticCallee(); callee != nil && fp.isStdFunc(callee) {
						okStd, whyStd := checkStdWrapperPtrCall(r, c, callee, v, wk, fp, depth, callStack, addPtr)
						if !okStd {
							return false, whyStd
						}
						continue
					}
					if !propagateUserCall(r, v, false) {
						return false, "wrapper_unconfined_call"
					}
				default:
					return false, "wrapper_ptr_escape"
				}
			}
		}

		for len(ifaceQueue) > 0 {
			iv := ifaceQueue[0]
			ifaceQueue = ifaceQueue[1:]
			refs := iv.Referrers()
			if refs == nil {
				return false, "wrapper_iface_nil_referrers"
			}
			for _, ref := range *refs {
				switch r := ref.(type) {
				case *ssa.DebugRef:
				case *ssa.Phi:
					addIface(r)
				case *ssa.ChangeInterface:
					addIface(r)
				case *ssa.BinOp:
					if r.Op != token.EQL && r.Op != token.NEQ {
						return false, "wrapper_iface_binop"
					}
				case *ssa.Return:
					if !propagateReturn(r, iv) {
						return false, "wrapper_iface_escaped_return"
					}
				case *ssa.Store:
					alloc, ok := r.Addr.(*ssa.Alloc)
					if !ok || r.Val != iv || !addLocalCellLoads(alloc, iv, true) {
						return false, "wrapper_iface_store_escape"
					}
				case *ssa.MakeClosure:
					if !addClosureCaptures(r, iv, true) {
						return false, "wrapper_iface_closure_escape"
					}
				case *ssa.TypeAssert:
					if r.X != iv {
						return false, "wrapper_iface_bad_assert"
					}
					if !r.CommaOk {
						if _, isIf := types.Unalias(r.AssertedType).Underlying().(*types.Interface); isIf {
							addIface(r)
						} else {
							addPtr(r)
						}
						continue
					}
					if r.Referrers() == nil {
						return false, "wrapper_iface_assert_tuple"
					}
					for _, tr := range *r.Referrers() {
						switch ex := tr.(type) {
						case *ssa.DebugRef:
						case *ssa.Extract:
							if ex.Index == 0 {
								if _, isIf := types.Unalias(ex.Type()).Underlying().(*types.Interface); isIf {
									addIface(ex)
								} else {
									addPtr(ex)
								}
							}
						default:
							return false, "wrapper_iface_assert_extract"
						}
					}
				case ssa.CallInstruction:
					if _, isGo := r.(*ssa.Go); isGo || r.Common() == nil {
						return false, "wrapper_iface_go_call"
					}
					c := r.Common()
					if c.IsInvoke() {
						if c.Value != iv || slices.Contains(c.Args, iv) || c.Method == nil {
							return false, "wrapper_iface_invoke_arg_escape"
						}
						switch c.Method.Name() {
						case "Write", "Read", "WriteByte", "WriteString", "ReadByte", "ReadRune", "Flush":
							continue
						default:
							return false, "wrapper_iface_invoke_method:" + c.Method.Name()
						}
					}
					if callee := c.StaticCallee(); callee != nil && fp.isStdFunc(callee) {
						if !checkStdWrapperIfaceCall(r, c, callee, iv, fp, depth, callStack, addPtr) {
							return false, "wrapper_iface_std_escape:" + callee.String()
						}
						continue
					}
					if !propagateUserCall(r, iv, true) {
						return false, "wrapper_iface_user_escape"
					}
				default:
					return false, "wrapper_iface_escape"
				}
			}
		}
	}
	return true, ""
}

func checkStdWrapperPtrCall(site ssa.CallInstruction, c *ssa.CallCommon, callee *ssa.Function, v ssa.Value, defaultWK wrapperKind, fp *freshParamAnalysis, depth int, callStack map[*ssa.Function]wrapperCallFrame, addPtr func(ssa.Value)) (bool, string) {
	if len(c.Args) == 0 || c.Args[0] != v || slices.Contains(c.Args[1:], v) {
		return false, "wrapper_ptr_arg_pos"
	}
	wk := wrapperKindOfType(v.Type())
	if wk == wrapperNone {
		wk = defaultWK
	}
	pkgPath, name := funcPkgPath(callee), functionSymbolName(callee)
	switch wk {
	case wrapperBufioWriter:
		if pkgPath != "bufio" {
			return false, "bufio_writer_foreign_std:" + pkgPath
		}
		switch name {
		case "Write", "WriteByte", "WriteRune", "WriteString", "Flush", "Buffered", "Available", "AvailableBuffer", "Size":
			return true, ""
		case "Reset":
			if len(c.Args) != 2 {
				return false, "bufio_writer_reset_arity"
			}
			return inMemoryStreamValue(c.Args[1], streamKindWriter, fp, depth+1, callStack)
		case "ReadFrom":
			if len(c.Args) != 2 {
				return false, "bufio_writer_readfrom_arity"
			}
			return inMemoryStreamValue(c.Args[1], streamKindReader, fp, depth+1, callStack)
		}
	case wrapperTabwriter:
		if pkgPath != "text/tabwriter" {
			return false, "tabwriter_foreign_std:" + pkgPath
		}
		switch name {
		case "Write", "Flush":
			return true, ""
		case "Init":
			if len(c.Args) != 7 {
				return false, "tabwriter_init_arity"
			}
			if okW, why := inMemoryStreamValue(c.Args[1], streamKindWriter, fp, depth+1, callStack); !okW {
				return false, "tabwriter_init_rebind:" + why
			}
			if site.Value() != nil {
				addPtr(site.Value())
			}
			return true, ""
		}
	case wrapperBufioReader:
		if pkgPath != "bufio" {
			return false, "bufio_reader_foreign_std:" + pkgPath
		}
		switch name {
		case "Buffered", "Discard", "Peek", "Read", "ReadByte", "ReadBytes", "ReadLine", "ReadRune", "ReadSlice", "ReadString", "Size", "UnreadByte", "UnreadRune":
			return true, ""
		case "Reset":
			if len(c.Args) != 2 {
				return false, "bufio_reader_reset_arity"
			}
			return inMemoryStreamValue(c.Args[1], streamKindReader, fp, depth+1, callStack)
		case "WriteTo":
			if len(c.Args) != 2 {
				return false, "bufio_reader_writeto_arity"
			}
			return inMemoryStreamValue(c.Args[1], streamKindWriter, fp, depth+1, callStack)
		}
	}
	return false, "wrapper_unsupported_method:" + pkgPath + "." + name
}

func checkStdWrapperIfaceCall(site ssa.CallInstruction, c *ssa.CallCommon, callee *ssa.Function, iv ssa.Value, fp *freshParamAnalysis, depth int, callStack map[*ssa.Function]wrapperCallFrame, addPtr func(ssa.Value)) bool {
	pkgPath, name := funcPkgPath(callee), functionSymbolName(callee)
	if auditset.WriterFirstStdFunc(pkgPath, name) {
		return len(c.Args) > 0 && c.Args[0] == iv && !slices.Contains(c.Args[1:], iv)
	}
	if pkgPath == "fmt" && auditset.FmtReaderFunc(name) {
		return len(c.Args) > 0 && c.Args[0] == iv && !slices.Contains(c.Args[1:], iv)
	}
	if pkgPath == "go/parser" && auditset.GoParserSourceFunc(name) {
		return len(c.Args) == 4 && c.Args[2] == iv && c.Args[0] != iv && c.Args[1] != iv && c.Args[3] != iv
	}
	switch pkgPath {
	case "bufio":
		switch name {
		case "NewWriter", "NewWriterSize", "NewReader", "NewReaderSize":
			if len(c.Args) < 1 || c.Args[0] != iv || slices.Contains(c.Args[1:], iv) || site.Value() == nil {
				return false
			}
			addPtr(site.Value())
			return true
		case "Reset":
			if len(c.Args) != 2 || c.Args[1] != iv || c.Args[0] == iv {
				return false
			}
			addPtr(c.Args[0])
			return true
		case "ReadFrom":
			if len(c.Args) != 2 || c.Args[1] != iv || c.Args[0] == iv {
				return false
			}
			okW, _ := inMemoryStreamValue(c.Args[0], streamKindWriter, fp, depth+1, callStack)
			return okW
		case "WriteTo":
			if len(c.Args) != 2 || c.Args[1] != iv || c.Args[0] == iv {
				return false
			}
			okR, _ := inMemoryStreamValue(c.Args[0], streamKindReader, fp, depth+1, callStack)
			return okR
		}
	case "text/tabwriter":
		switch name {
		case "NewWriter":
			if len(c.Args) != 6 || c.Args[0] != iv || slices.Contains(c.Args[1:], iv) || site.Value() == nil {
				return false
			}
			addPtr(site.Value())
			return true
		case "Init":
			if len(c.Args) != 7 || c.Args[1] != iv || c.Args[0] == iv || slices.Contains(c.Args[2:], iv) {
				return false
			}
			addPtr(c.Args[0])
			if site.Value() != nil {
				addPtr(site.Value())
			}
			return true
		}
	case "io":
		switch name {
		case "WriteString", "ReadAll", "ReadFull", "ReadAtLeast":
			return len(c.Args) >= 1 && c.Args[0] == iv && !slices.Contains(c.Args[1:], iv)
		case "Copy", "CopyN", "CopyBuffer":
			if len(c.Args) < 2 {
				return false
			}
			if c.Args[0] == iv && !slices.Contains(c.Args[1:], iv) {
				okR, _ := inMemoryStreamValue(c.Args[1], streamKindReader, fp, depth+1, callStack)
				return okR
			}
			if c.Args[1] == iv && c.Args[0] != iv && !slices.Contains(c.Args[2:], iv) {
				okW, _ := inMemoryStreamValue(c.Args[0], streamKindWriter, fp, depth+1, callStack)
				return okW
			}
		}
	}
	return false
}
