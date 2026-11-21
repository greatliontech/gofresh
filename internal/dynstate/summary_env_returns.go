package dynstate

import (
	"go/ast"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type closureOutflowSummaries struct {
	returnEnvFree          map[string]bool
	returnEnvDeps          map[string]map[syntaxutil.FuncKey]bool
	returnEnvParamDeps     map[string]map[syntaxutil.ParamKey]bool
	returnEnvMethodDeps    map[string]map[syntaxutil.FuncKey]bool
	returnFieldDefer       map[string]map[syntaxutil.ReturnFieldParamDefer]bool
	returnFieldPoison      map[string]map[syntaxutil.ReturnFieldParamPoison]bool
	paramInsertionFree     map[syntaxutil.ParamKey]bool
	paramInsertionDeps     map[syntaxutil.ParamKey]map[syntaxutil.EnvAuditTarget]bool
	paramInsertionParams   map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool
	paramInsertionMethods  map[syntaxutil.ParamKey]map[syntaxutil.FuncKey]bool
	returnInsertionCallDep map[string]map[syntaxutil.EnvAuditTarget]bool
}

type resolvedInsertionState struct {
	poison     map[types.Object]bool
	uses       map[types.Object]map[syntaxutil.EnvAuditTarget]bool
	paramDeps  map[types.Object]map[syntaxutil.ParamKey]bool
	methodDeps map[types.Object]map[syntaxutil.FuncKey]bool
}

type outflowEvalCtx struct {
	insMode      bool
	resolved     resolvedInsertionState
	localFree    map[types.Object]int // 0 unknown, 2 free, 3 refused
	provingDepth map[types.Object]int
	curDepth     int
	fnDeps       map[syntaxutil.FuncKey]bool
	useDeps      map[syntaxutil.EnvAuditTarget]bool
	paramDeps    map[syntaxutil.ParamKey]bool
	methodDeps   map[syntaxutil.FuncKey]bool
	onRefusal    func(*flowir.Value)
}

func newOutflowEvalCtx(insMode bool, resolved resolvedInsertionState) *outflowEvalCtx {
	return &outflowEvalCtx{
		insMode:      insMode,
		resolved:     resolved,
		localFree:    map[types.Object]int{},
		provingDepth: map[types.Object]int{},
		fnDeps:       map[syntaxutil.FuncKey]bool{},
		useDeps:      map[syntaxutil.EnvAuditTarget]bool{},
		paramDeps:    map[syntaxutil.ParamKey]bool{},
		methodDeps:   map[syntaxutil.FuncKey]bool{},
	}
}

type outflowInsertionUse struct {
	call        *flowir.Value
	root        types.Object
	calleeParam syntaxutil.ParamKey
	args        []*flowir.Value
}

// outflowAnalyzer holds per-function lowered state for constructor-result
// environment freedom (ReturnEnvFree*) and parameter-insertion environment
// freedom (ParamInsertionFree*).
type outflowAnalyzer struct {
	audited        bool
	p              *packages.Package
	fc             *pkgFlowCache
	ownPath        string
	settledGlobals settledGlobalMap
	pkgConf        *packageConfinementSummary
	hooks          *syntaxutil.ExplainHookSet
	out            *closureOutflowSummaries

	fd         *ast.FuncDecl
	body       *flowir.Body
	fnKey      string
	ownFuncKey syntaxutil.FuncKey

	params           map[types.Object]bool
	paramIndex       map[types.Object]int
	localSources     map[types.Object][]*flowir.Value
	directBinds      map[types.Object][]*flowir.Value
	hasZeroDecl      map[types.Object]bool
	rangeBound       map[types.Object]bool
	hasSpreadAppend  map[types.Object]bool
	writeSources     map[types.Object][]*flowir.Value
	insertionWrites  map[types.Object][]*flowir.Value
	localBroken      map[types.Object]bool
	paramRebound     map[types.Object]bool
	captureBroken    map[types.Object]bool
	aliasPairs       [][2]types.Object
	heldPairs        [][2]types.Object
	stmtCallDeps     map[syntaxutil.FuncKey]bool
	rawObjParamDeps  map[types.Object]map[syntaxutil.ParamKey]bool
	rawObjMethodDeps map[types.Object]map[syntaxutil.FuncKey]bool

	pendingStores        []outflowPendingStore
	pendingAppendSlices  []outflowPendingStore
	pendingInsertionUses []outflowInsertionUse

	aliasFind             func(types.Object) types.Object
	reachFind             func(types.Object) types.Object
	headerFind            func(types.Object) types.Object
	freshObj              map[types.Object]bool
	sharedWrites          map[types.Object][]*flowir.Value
	sharedInsertionWrites map[types.Object][]*flowir.Value
	objParamDeps          map[types.Object]map[syntaxutil.ParamKey]bool
	objMethodDeps         map[types.Object]map[syntaxutil.FuncKey]bool
	visitingLits          map[*ast.FuncLit]bool
}

func newObjectUnionFind(pairSets ...[][2]types.Object) func(types.Object) types.Object {
	roots := map[types.Object]types.Object{}
	var find func(types.Object) types.Object
	find = func(x types.Object) types.Object {
		r, ok := roots[x]
		if !ok || r == x {
			return x
		}
		root := find(r)
		roots[x] = root
		return root
	}
	for _, pairs := range pairSets {
		for _, pair := range pairs {
			a, b := find(pair[0]), find(pair[1])
			if a != b {
				roots[a] = b
			}
		}
	}
	return find
}

func outflowSharesHeader(t types.Type) bool {
	if t == nil {
		return true
	}
	if tup, ok := types.Unalias(t).(*types.Tuple); ok && tup.Len() > 0 {
		t = tup.At(0).Type()
	}
	switch types.Unalias(t).Underlying().(type) {
	case *types.Struct, *types.Array, *types.Basic:
		return false
	}
	return true
}

func (a *outflowAnalyzer) classifyWants(
	wants map[syntaxutil.ParamKey]bool,
	methodWants map[syntaxutil.FuncKey]bool,
	paramOut map[syntaxutil.ParamKey]bool,
	methodOut map[syntaxutil.FuncKey]bool,
) bool {
	return a.pkgConf.resolveWants(a.ownPath, wants, methodWants, paramOut, methodOut)
}

// analyzeClosureOutflowSummaries proves, per plain named function of the
// package, constructor-result environment freedom (ReturnEnvFree*) and
// parameter-insertion environment freedom (ParamInsertionFree*) in a single
// pass over each lowered function body.
func analyzeClosureOutflowSummaries(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	settledGlobals settledGlobalMap,
	pkgConf *packageConfinementSummary,
	hooks *syntaxutil.ExplainHookSet,
) closureOutflowSummaries {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return closureOutflowSummaries{}
	}
	ownPath := p.Types.Path()
	out := closureOutflowSummaries{
		returnEnvFree:          map[string]bool{},
		returnEnvDeps:          map[string]map[syntaxutil.FuncKey]bool{},
		returnEnvParamDeps:     map[string]map[syntaxutil.ParamKey]bool{},
		returnEnvMethodDeps:    map[string]map[syntaxutil.FuncKey]bool{},
		returnFieldDefer:       map[string]map[syntaxutil.ReturnFieldParamDefer]bool{},
		returnFieldPoison:      map[string]map[syntaxutil.ReturnFieldParamPoison]bool{},
		paramInsertionFree:     map[syntaxutil.ParamKey]bool{},
		paramInsertionDeps:     map[syntaxutil.ParamKey]map[syntaxutil.EnvAuditTarget]bool{},
		paramInsertionParams:   map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{},
		paramInsertionMethods:  map[syntaxutil.ParamKey]map[syntaxutil.FuncKey]bool{},
		returnInsertionCallDep: map[string]map[syntaxutil.EnvAuditTarget]bool{},
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name == nil || fd.Body == nil || fd.Name.Name == "init" {
				continue
			}
			body := fc.funcBody(p, fd)
			if body == nil {
				continue
			}
			fnKey := fd.Name.Name
			a := &outflowAnalyzer{
				audited:          audited,
				p:                p,
				fc:               fc,
				ownPath:          ownPath,
				settledGlobals:   settledGlobals,
				pkgConf:          pkgConf,
				hooks:            hooks,
				out:              &out,
				fd:               fd,
				body:             body,
				fnKey:            fnKey,
				ownFuncKey:       syntaxutil.FuncKey{Pkg: ownPath, Name: fnKey},
				params:           map[types.Object]bool{},
				paramIndex:       map[types.Object]int{},
				localSources:     map[types.Object][]*flowir.Value{},
				directBinds:      map[types.Object][]*flowir.Value{},
				hasZeroDecl:      map[types.Object]bool{},
				rangeBound:       map[types.Object]bool{},
				hasSpreadAppend:  map[types.Object]bool{},
				writeSources:     map[types.Object][]*flowir.Value{},
				insertionWrites:  map[types.Object][]*flowir.Value{},
				localBroken:      map[types.Object]bool{},
				paramRebound:     map[types.Object]bool{},
				captureBroken:    map[types.Object]bool{},
				stmtCallDeps:     map[syntaxutil.FuncKey]bool{},
				rawObjParamDeps:  map[types.Object]map[syntaxutil.ParamKey]bool{},
				rawObjMethodDeps: map[types.Object]map[syntaxutil.FuncKey]bool{},
				visitingLits:     map[*ast.FuncLit]bool{},
			}
			a.analyzeFunc()
		}
	}
	return out
}

func recordReturnFieldRegistrants(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	fnKey string,
	body *flowir.Body,
	retDefer map[string]map[syntaxutil.ReturnFieldParamDefer]bool,
	retPoison map[string]map[syntaxutil.ReturnFieldParamPoison]bool,
) {
	if body == nil {
		return
	}
	ownPath := ""
	if p.Types != nil {
		ownPath = p.Types.Path()
	}
	ownFuncKey := syntaxutil.FuncKey{Pkg: ownPath, Name: fnKey}
	emit := func(m fieldRegMark) {
		switch m.class {
		case 'd':
			if retDefer[fnKey] == nil {
				retDefer[fnKey] = map[syntaxutil.ReturnFieldParamDefer]bool{}
			}
			retDefer[fnKey][syntaxutil.ReturnFieldParamDefer{
				Pos:   syntaxutil.ReturnFieldPosKey{Func: ownFuncKey, Field: m.field, Index: m.idx},
				Param: m.param,
			}] = true
		case 'p':
			if retPoison[fnKey] == nil {
				retPoison[fnKey] = map[syntaxutil.ReturnFieldParamPoison]bool{}
			}
			if m.field == "" {
				retPoison[fnKey][syntaxutil.ReturnFieldParamPoison{Func: ownFuncKey}] = true
			} else {
				retPoison[fnKey][syntaxutil.ReturnFieldParamPoison{Func: ownFuncKey, HasPos: true, Field: m.field, Index: m.idx}] = true
			}
		}
	}

	var scanBody func(b *flowir.Body)
	var scanRVal func(v *flowir.Value)

	scanPlaceWrite := func(dst flowir.Place, src *flowir.Value) {
		if src != nil && len(dst.Projs) > 0 {
			last := dst.Projs[len(dst.Projs)-1]
			if last.Kind == flowir.ProjField && last.Field != nil && last.Selection != nil && last.Type != nil {
				if _, isSig := types.Unalias(last.Type).Underlying().(*types.Signature); isSig {
					classifyFieldRegistrantFlowValue(audited, p, fc, last.Field.Name(), src, emit)
				}
			}
		}
		if _, mapKey, isMapW := dst.AsMapWrite(); isMapW && mapKey != nil {
			classifyRegistrantFlowValue(audited, p, fc, mapKey, emit)
		}
		dst.ForEachChildValue(func(cv *flowir.Value) bool {
			scanRVal(cv)
			return true
		})
	}

	scanRVal = func(v *flowir.Value) {
		if v == nil || v.IsTypeExpr {
			return
		}
		switch v.Kind {
		case flowir.ValAllocFresh:
			if v.AllocKind == flowir.AllocCompositeLit {
				classifyRegistrantCompositeValue(audited, p, fc, v, emit)
				return
			}
		case flowir.ValMakeClosure:
			classifyLiteralRegistrant(audited, p, fc, syntaxutil.ElemPositionField, v.Lit, emit)
			return
		case flowir.ValMethodVal:
			emit(fieldRegMark{class: 'p', field: syntaxutil.ElemPositionField, idx: -1})
		case flowir.ValPlace:
			if v.Place.Root == flowir.RootFunc {
				classifyFieldRegistrantFlowValue(audited, p, fc, syntaxutil.ElemPositionField, v, emit)
				return
			}
			if v.Place.Root == flowir.RootPkgGlobal && v.Place.Obj != nil && refconfine.TypeCarriesSignature(v.Place.Obj.Type()) {
				emit(fieldRegMark{class: 'p', idx: -1})
			}
			for _, proj := range v.Place.Projs {
				if (proj.Kind == flowir.ProjField || proj.Kind == flowir.ProjIndex) && refconfine.TypeCarriesSignature(proj.Type) {
					emit(fieldRegMark{class: 'p', field: syntaxutil.ElemPositionField, idx: -1})
					break
				}
			}
			v.Place.ForEachChildValue(func(cv *flowir.Value) bool {
				scanRVal(cv)
				return true
			})
			return
		case flowir.ValCall:
			if v.CallKind != flowir.CallBuiltin && (v.CallKind != flowir.CallPlain || v.IsMethodExprCall) {
				if refconfine.TypeCarriesSignature(v.Type) {
					emit(fieldRegMark{class: 'p', field: syntaxutil.ElemPositionField, idx: -1})
				}
			}
			if v.CallKind == flowir.CallIIFE && v.IIFE != nil {
				scanBody(v.IIFE)
			}
		}
		v.ForEachChildValue(func(ch *flowir.Value) bool {
			scanRVal(ch)
			return true
		})
	}

	scanBody = func(b *flowir.Body) {
		if b == nil {
			return
		}
		b.ForEachSyncOp(func(op *flowir.Op) bool {
			switch op.Kind {
			case flowir.OpAssign:
				switch op.AssignKind {
				case flowir.AssignZeroDecl:
					// Zero declarations introduce no non-nil function registrants.
				case flowir.AssignIncDec:
					for _, dst := range op.Dsts {
						scanPlaceWrite(dst, nil)
					}
				case flowir.AssignRange:
					for _, dst := range op.Dsts {
						dst.ForEachChildValue(func(cv *flowir.Value) bool {
							scanRVal(cv)
							return true
						})
					}
					for _, src := range op.Srcs {
						scanRVal(src)
					}
				default:
					op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
						scanPlaceWrite(dst, src)
						return true
					})
					for _, src := range op.Srcs {
						scanRVal(src)
					}
				}
			case flowir.OpTypeSwitchBind:
				scanRVal(op.SwitchSrc)
			case flowir.OpChanSend:
				op.ChanPlace.ForEachChildValue(func(cv *flowir.Value) bool {
					scanRVal(cv)
					return true
				})
				scanRVal(op.ChanVal)
				scanRVal(op.SendVal)
			case flowir.OpReturn:
				for _, r := range op.Results {
					scanRVal(r)
				}
			case flowir.OpDefer, flowir.OpGo:
				scanRVal(op.Call)
			case flowir.OpExpr:
				scanRVal(op.Expr)
			}
			return true
		})
	}
	scanBody(body)
}
