package structmut

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type ptrMethodClass uint8

const (
	ptrMethodRawDeref ptrMethodClass = iota
	ptrMethodIsNil
	ptrMethodAsValue
	ptrMethodAsIface
	ptrMethodApplyOffset
	ptrMethodElemLoad
	ptrMethodAtomicLoad
	ptrMethodPointerSlice
	ptrMethodAppendPointerSlice
	ptrMethodSetPointer
)

type capGoTypeKey struct {
	owner *types.Named
	fld   *types.Var
}

type ptrProv uint8

const (
	provBase ptrProv = 1 << iota
	provApplied
	provAtomicLoaded
	provFresh
	provRaw
)

type rvProv uint8

const (
	rvFresh rvProv = 1 << iota
	rvOneofElem
	rvMapOrConv
	rvRaw
)

type wrapperPtrDiscipline struct {
	p                               *packages.Package
	idx                             *refconfine.PkgIndex
	foreignReflectFields            map[*types.Var]bool
	instantiatedNamed               map[*types.Named]bool
	isInsideCompileTimeUnsafeLayout func(ast.Node) bool
	isReflectStructFieldOffsetType  func(*types.Named) bool
	conv                            *ast.CallExpr
	dstOwner                        *types.Named
	dstFld                          *types.Var
	seedFn                          *types.Func

	methodClass             map[*types.Func]ptrMethodClass
	applyOffsetTypes        []*types.Named
	mset                    *types.MethodSet
	applyOffsetSet          map[*types.Named]bool
	capsuleStructs          map[*types.Named]bool
	zeroInstantiatedStructs map[*types.Named]bool
	reboundStructs          map[*types.Named]bool
	verifiedEmbHopMemo      map[*types.Var]bool
	verifiedEmbHopDone      map[*types.Var]bool
	provenNonZeroMemo       map[types.Object]bool
	provenNonZeroDone       map[types.Object]bool
	funcLitsForField        map[types.Object][]*ast.FuncLit
	funcObjsForField        map[types.Object][]*types.Func
	funcLitsForLocal        map[*types.Var][]*ast.FuncLit
	funcObjsForLocal        map[*types.Var][]*types.Func
	unknownSourceFields     map[types.Object]bool
	unknownSourceLocals     map[*types.Var]bool
	seedBaseMethods         map[*types.Func]bool
	ptrCtorOfValue          map[*types.Func]bool
	ptrCtorOfIface          map[*types.Func]bool
	ptrCtorInterfaceToPtr   map[*types.Func]bool
	contextSensitiveFuncs   map[*types.Func]bool
	ownerMethods            map[*types.Func]bool
	isInternalCapsulePkg    bool
	verifiedCapGoTypeMemo   map[capGoTypeKey]bool
	verifiedCapGoTypeDone   map[capGoTypeKey]bool
	visitingCapGoType       map[capGoTypeKey]bool
	varProv                 map[*types.Var]ptrProv
	sliceVarProv            map[*types.Var]ptrProv
	fieldProv               map[types.Object]ptrProv
	fnReturnProv            map[*types.Func][]ptrProv
	litReturnProv           map[*ast.FuncLit][]ptrProv
	rvVarProv               map[*types.Var]rvProv
}

func runWrapperBasePtrOffsetDiscipline(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	foreignReflectFields map[*types.Var]bool,
	instantiatedNamed map[*types.Named]bool,
	isInsideCompileTimeUnsafeLayout func(ast.Node) bool,
	isReflectStructFieldOffsetType func(*types.Named) bool,
	conv *ast.CallExpr,
	dstOwner *types.Named,
	dstFld *types.Var,
) (bool, map[*types.Func]bool) {
	if dstOwner == nil || dstOwner.Obj() == nil || dstOwner.Obj().Pkg() != p.Types || dstOwner.Obj().Exported() {
		return false, nil
	}
	enclFD := idx.EnclFunc[conv]
	if enclFD == nil || enclFD.Name == nil {
		return false, nil
	}
	seedFn, _ := p.TypesInfo.Defs[enclFD.Name].(*types.Func)
	if seedFn == nil {
		return false, nil
	}
	wpd := &wrapperPtrDiscipline{
		p:                               p,
		idx:                             idx,
		foreignReflectFields:            foreignReflectFields,
		instantiatedNamed:               instantiatedNamed,
		isInsideCompileTimeUnsafeLayout: isInsideCompileTimeUnsafeLayout,
		isReflectStructFieldOffsetType:  isReflectStructFieldOffsetType,
		conv:                            conv,
		dstOwner:                        dstOwner,
		dstFld:                          dstFld,
		seedFn:                          seedFn,
		isInternalCapsulePkg:            strings.Contains("/"+p.PkgPath+"/", "/internal/"),
		verifiedCapGoTypeMemo:           map[capGoTypeKey]bool{},
		verifiedCapGoTypeDone:           map[capGoTypeKey]bool{},
		visitingCapGoType:               map[capGoTypeKey]bool{},
		varProv:                         map[*types.Var]ptrProv{},
		sliceVarProv:                    map[*types.Var]ptrProv{},
		fieldProv:                       map[types.Object]ptrProv{},
		fnReturnProv:                    map[*types.Func][]ptrProv{},
		litReturnProv:                   map[*ast.FuncLit][]ptrProv{},
		rvVarProv:                       map[*types.Var]rvProv{},
	}
	if !wpd.classifyMethodsAndCallables() {
		return false, nil
	}
	wpd.initOffsetAndCapsuleStructs()
	if !wpd.runProvenanceLFP() {
		return false, nil
	}
	return wpd.verifyCallSiteSinks()
}

func (wpd *wrapperPtrDiscipline) classifyMethodsAndCallables() bool {
	if pkgExportedAPIReaches(wpd.p, wpd.typeMentionsDstOwner, wpd.typeMentionsDstOwner, func(sig *types.Signature) bool {
		return wpd.typeMentionsDstOwner(sig)
	}) {
		return false
	}
	wpd.classifyOwnerMethods()
	return wpd.classifyCallableSourcesAndConstructors()
}

func (wpd *wrapperPtrDiscipline) classifyOwnerMethods() {
	wpd.methodClass = map[*types.Func]ptrMethodClass{}
	wpd.mset = types.NewMethodSet(types.NewPointer(wpd.dstOwner))
	for mi := 0; mi < wpd.mset.Len(); mi++ {
		mfn, _ := wpd.mset.At(mi).Obj().(*types.Func)
		if mfn == nil || mfn.Pkg() != wpd.p.Types {
			continue
		}
		mfd := wpd.idx.FuncDecls[mfn]
		if mfd == nil || mfd.Body == nil {
			continue
		}
		sig, okS := mfn.Type().(*types.Signature)
		if !okS {
			continue
		}
		var recvVar *types.Var
		if mfd.Recv != nil && len(mfd.Recv.List) == 1 && len(mfd.Recv.List[0].Names) == 1 {
			recvVar, _ = wpd.p.TypesInfo.Defs[mfd.Recv.List[0].Names[0]].(*types.Var)
		}
		if recvVar != nil && sig.Params().Len() == 0 && sig.Results().Len() == 1 &&
			types.Identical(types.Unalias(sig.Results().At(0).Type()), wpd.dstOwner) && len(mfd.Body.List) == 1 {
			if ret, isRet := mfd.Body.List[0].(*ast.ReturnStmt); isRet && len(ret.Results) == 1 {
				if valExpr, okL := wpd.isOwnerSingleFieldLit(ret.Results[0]); okL {
					if st, isSt := valExpr.(*ast.StarExpr); isSt && wpd.isUnsafePtrSlotCastOfField(st.X, recvVar) {
						wpd.methodClass[mfn] = ptrMethodElemLoad
						continue
					}
					if ac, isAC := valExpr.(*ast.CallExpr); isAC && len(ac.Args) == 1 && !ac.Ellipsis.IsValid() {
						afn := syntaxutil.ResolveCalledFuncObj(wpd.p, ac.Fun)
						if afn != nil && afn.Pkg() != nil && afn.Pkg().Path() == "sync/atomic" && afn.Name() == "LoadPointer" &&
							wpd.isUnsafePtrSlotCastOfField(ac.Args[0], recvVar) {
							wpd.methodClass[mfn] = ptrMethodAtomicLoad
							continue
						}
					}
				}
			}
		}
		if recvVar != nil && sig.Params().Len() == 1 && sig.Results().Len() == 1 &&
			types.Identical(types.Unalias(sig.Params().At(0).Type()), wpd.dstOwner) &&
			types.Identical(types.Unalias(sig.Results().At(0).Type()), wpd.dstOwner) && len(mfd.Body.List) == 2 {
			valParam := sig.Params().At(0)
			ifs, isIf := mfd.Body.List[0].(*ast.IfStmt)
			ret2, isRet2 := mfd.Body.List[1].(*ast.ReturnStmt)
			if isIf && ifs.Init == nil && ifs.Else == nil && ifs.Body != nil && len(ifs.Body.List) == 1 && isRet2 && len(ret2.Results) == 1 {
				ret1, isRet1 := ifs.Body.List[0].(*ast.ReturnStmt)
				ccond, isCC := ast.Unparen(ifs.Cond).(*ast.CallExpr)
				valExpr2, okL2 := wpd.isOwnerSingleFieldLit(ret2.Results[0])
				if isRet1 && len(ret1.Results) == 1 && isCC && len(ccond.Args) == 3 && !ccond.Ellipsis.IsValid() && okL2 {
					r1id, isR1 := ast.Unparen(ret1.Results[0]).(*ast.Ident)
					cfn := syntaxutil.ResolveCalledFuncObj(wpd.p, ccond.Fun)
					ac2, isAC2 := valExpr2.(*ast.CallExpr)
					vsel, isVS := ast.Unparen(ccond.Args[2]).(*ast.SelectorExpr)
					if isR1 && wpd.p.TypesInfo.Uses[r1id] == valParam &&
						cfn != nil && cfn.Pkg() != nil && cfn.Pkg().Path() == "sync/atomic" && cfn.Name() == "CompareAndSwapPointer" &&
						wpd.isUnsafePtrSlotCastOfField(ccond.Args[0], recvVar) &&
						isVS && wpd.p.TypesInfo.Uses[vsel.Sel] == wpd.dstFld &&
						isAC2 && len(ac2.Args) == 1 && wpd.isUnsafePtrSlotCastOfField(ac2.Args[0], recvVar) {
						if vid, isVID := ast.Unparen(vsel.X).(*ast.Ident); isVID && wpd.p.TypesInfo.Uses[vid] == valParam {
							if afn2 := syntaxutil.ResolveCalledFuncObj(wpd.p, ac2.Fun); afn2 != nil && afn2.Pkg() != nil && afn2.Pkg().Path() == "sync/atomic" && afn2.Name() == "LoadPointer" {
								wpd.methodClass[mfn] = ptrMethodAtomicLoad
								continue
							}
						}
					}
				}
			}
		}
		if recvVar != nil && sig.Params().Len() == 0 && sig.Results().Len() == 1 &&
			wpd.isOwnerSliceType(sig.Results().At(0).Type()) && len(mfd.Body.List) == 1 {
			if ret, isRet := mfd.Body.List[0].(*ast.ReturnStmt); isRet && len(ret.Results) == 1 && wpd.isOwnerSlicePtrDeref(ret.Results[0], recvVar) {
				wpd.methodClass[mfn] = ptrMethodPointerSlice
				continue
			}
		}
		if recvVar != nil && sig.Params().Len() == 1 && sig.Results().Len() == 0 &&
			types.Identical(types.Unalias(sig.Params().At(0).Type()), wpd.dstOwner) && len(mfd.Body.List) == 1 {
			valParam := sig.Params().At(0)
			switch st0 := mfd.Body.List[0].(type) {
			case *ast.AssignStmt:
				if st0.Tok == token.ASSIGN && len(st0.Lhs) == 1 && len(st0.Rhs) == 1 {
					if wpd.isOwnerSlicePtrDeref(st0.Lhs[0], recvVar) {
						if apCall, isAP := ast.Unparen(st0.Rhs[0]).(*ast.CallExpr); isAP && len(apCall.Args) == 2 && !apCall.Ellipsis.IsValid() {
							if apID, isID := ast.Unparen(apCall.Fun).(*ast.Ident); isID {
								if bObj, isB := wpd.p.TypesInfo.Uses[apID].(*types.Builtin); isB && bObj.Name() == "append" && wpd.isOwnerSlicePtrDeref(apCall.Args[0], recvVar) {
									if a1, isA1 := ast.Unparen(apCall.Args[1]).(*ast.Ident); isA1 && wpd.p.TypesInfo.Uses[a1] == valParam {
										wpd.methodClass[mfn] = ptrMethodAppendPointerSlice
										continue
									}
								}
							}
						}
					}
					if lhsStar, isLS := ast.Unparen(st0.Lhs[0]).(*ast.StarExpr); isLS && wpd.isUnsafePtrSlotCastOfField(lhsStar.X, recvVar) {
						rhs := ast.Unparen(st0.Rhs[0])
						if rc, isRC := rhs.(*ast.CallExpr); isRC && len(rc.Args) == 1 && !rc.Ellipsis.IsValid() {
							if rtv := wpd.p.TypesInfo.Types[ast.Unparen(rc.Fun)]; rtv.IsType() && syntaxutil.IsUnsafePointerType(rtv.Type) {
								rhs = ast.Unparen(rc.Args[0])
							}
						}
						if vsel, isVS := rhs.(*ast.SelectorExpr); isVS && wpd.p.TypesInfo.Uses[vsel.Sel] == wpd.dstFld {
							if vid, isVID := ast.Unparen(vsel.X).(*ast.Ident); isVID && wpd.p.TypesInfo.Uses[vid] == valParam {
								wpd.methodClass[mfn] = ptrMethodSetPointer
								continue
							}
						}
					}
				}
			case *ast.ExprStmt:
				if sc, isSC := ast.Unparen(st0.X).(*ast.CallExpr); isSC && len(sc.Args) == 2 && !sc.Ellipsis.IsValid() {
					sfn := syntaxutil.ResolveCalledFuncObj(wpd.p, sc.Fun)
					if sfn != nil && sfn.Pkg() != nil && sfn.Pkg().Path() == "sync/atomic" && sfn.Name() == "StorePointer" &&
						wpd.isUnsafePtrSlotCastOfField(sc.Args[0], recvVar) {
						if vsel, isVS := ast.Unparen(sc.Args[1]).(*ast.SelectorExpr); isVS && wpd.p.TypesInfo.Uses[vsel.Sel] == wpd.dstFld {
							if vid, isVID := ast.Unparen(vsel.X).(*ast.Ident); isVID && wpd.p.TypesInfo.Uses[vid] == valParam {
								wpd.methodClass[mfn] = ptrMethodSetPointer
								continue
							}
						}
					}
				}
			}
		}
		isRecvDstField := func(expr ast.Expr, wantRecv *types.Var) bool {
			sel, isS := ast.Unparen(expr).(*ast.SelectorExpr)
			if !isS || wpd.p.TypesInfo.Uses[sel.Sel] != wpd.dstFld {
				return false
			}
			rid, isID := ast.Unparen(sel.X).(*ast.Ident)
			return wantRecv != nil && isID && wpd.p.TypesInfo.Uses[rid] == wantRecv
		}
		isNilCheckOnRecvField := func(expr ast.Expr, wantRecv *types.Var) bool {
			bin, isBin := ast.Unparen(expr).(*ast.BinaryExpr)
			if !isBin || (bin.Op != token.EQL && bin.Op != token.NEQ) {
				return false
			}
			return (isRecvDstField(bin.X, wantRecv) && syntaxutil.IsNilIdent(wpd.p.TypesInfo, ast.Unparen(bin.Y))) ||
				(syntaxutil.IsNilIdent(wpd.p.TypesInfo, ast.Unparen(bin.X)) && isRecvDstField(bin.Y, wantRecv))
		}
		isDirectIsNilMethodDecl := func(fd *ast.FuncDecl) bool {
			if fd == nil || fd.Body == nil || len(fd.Body.List) != 1 || fd.Recv == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 {
				return false
			}
			rv, _ := wpd.p.TypesInfo.Defs[fd.Recv.List[0].Names[0]].(*types.Var)
			ret, isRet := fd.Body.List[0].(*ast.ReturnStmt)
			return rv != nil && isRet && len(ret.Results) == 1 && isNilCheckOnRecvField(ret.Results[0], rv)
		}
		if recvVar != nil && sig.Params().Len() == 0 && sig.Results().Len() == 1 && isDirectIsNilMethodDecl(mfd) {
			wpd.methodClass[mfn] = ptrMethodIsNil
			continue
		}
		if recvVar != nil && sig.Params().Len() == 1 && sig.Results().Len() == 1 &&
			syntaxutil.IsNamedInPkg(sig.Results().At(0).Type(), "reflect", "Value") && len(mfd.Body.List) == 1 {
			tParam := sig.Params().At(0)
			if ret, isRet := mfd.Body.List[0].(*ast.ReturnStmt); isRet && len(ret.Results) == 1 {
				if rc, isRC := ast.Unparen(ret.Results[0]).(*ast.CallExpr); isRC && len(rc.Args) == 2 && !rc.Ellipsis.IsValid() {
					callee := syntaxutil.ResolveCalledFuncObj(wpd.p, rc.Fun)
					aid, isAID := ast.Unparen(rc.Args[0]).(*ast.Ident)
					if callee != nil && callee.Pkg() != nil && callee.Pkg().Path() == "reflect" && callee.Name() == "NewAt" &&
						isAID && wpd.p.TypesInfo.Uses[aid] == tParam && isRecvDstField(rc.Args[1], recvVar) {
						wpd.methodClass[mfn] = ptrMethodAsValue
						continue
					}
				}
			}
		}
		if recvVar != nil && sig.Params().Len() == 1 && sig.Results().Len() == 1 &&
			types.Identical(types.Unalias(sig.Results().At(0).Type()), wpd.dstOwner) &&
			(len(mfd.Body.List) == 1 || len(mfd.Body.List) == 2) {
			on, isON := types.Unalias(sig.Params().At(0).Type()).(*types.Named)
			offParam := sig.Params().At(0)
			if isON && wpd.isReflectStructFieldOffsetType(on) {
				offOK := true
				for _, ouid := range wpd.idx.UsesOf[offParam] {
					if identIsWrittenAddrOrAutoAddr(wpd.p, wpd.idx, offParam, ouid) {
						offOK = false
						break
					}
				}
				if offOK && len(mfd.Body.List) == 2 {
					ifs, isIf := mfd.Body.List[0].(*ast.IfStmt)
					if !isIf || ifs.Init != nil || ifs.Else != nil || ifs.Body == nil || len(ifs.Body.List) != 1 {
						offOK = false
					} else {
						condOK := isNilCheckOnRecvField(ifs.Cond, recvVar)
						if !condOK {
							if cc, isCC := ast.Unparen(ifs.Cond).(*ast.CallExpr); isCC && len(cc.Args) == 0 && !cc.Ellipsis.IsValid() {
								if csel, isCS := ast.Unparen(cc.Fun).(*ast.SelectorExpr); isCS {
									rid, isRID := ast.Unparen(csel.X).(*ast.Ident)
									cfn := syntaxutil.ResolveCalledFuncObj(wpd.p, cc.Fun)
									if isRID && wpd.p.TypesInfo.Uses[rid] == recvVar && cfn != nil && cfn.Pkg() == wpd.p.Types && isDirectIsNilMethodDecl(wpd.idx.FuncDecls[cfn]) {
										condOK = true
									}
								}
							}
						}
						es, isES := ifs.Body.List[0].(*ast.ExprStmt)
						panicOK := false
						if isES {
							if pc, isPC := ast.Unparen(es.X).(*ast.CallExpr); isPC && len(pc.Args) == 1 && !pc.Ellipsis.IsValid() {
								if pid, isPID := ast.Unparen(pc.Fun).(*ast.Ident); isPID {
									if bObj, isB := wpd.p.TypesInfo.Uses[pid].(*types.Builtin); isB && bObj.Name() == "panic" &&
										wpd.p.TypesInfo.Types[ast.Unparen(pc.Args[0])].Value != nil {
										panicOK = true
									}
								}
							}
						}
						if !condOK || !panicOK {
							offOK = false
						}
					}
				}
				if offOK {
					if ret, isRet := mfd.Body.List[len(mfd.Body.List)-1].(*ast.ReturnStmt); isRet && len(ret.Results) == 1 {
						if valE, okL := wpd.isOwnerSingleFieldLit(ret.Results[0]); okL {
							if upCall, isUP := valE.(*ast.CallExpr); isUP && len(upCall.Args) == 1 && !upCall.Ellipsis.IsValid() {
								utv := wpd.p.TypesInfo.Types[ast.Unparen(upCall.Fun)]
								if utv.IsType() && syntaxutil.IsUnsafePointerType(utv.Type) {
									if bin, isBin := ast.Unparen(upCall.Args[0]).(*ast.BinaryExpr); isBin && bin.Op == token.ADD {
										isUintptrOf := func(e ast.Expr, check func(ast.Expr) bool) bool {
											c, isC := ast.Unparen(e).(*ast.CallExpr)
											if !isC || len(c.Args) != 1 || c.Ellipsis.IsValid() {
												return false
											}
											tv := wpd.p.TypesInfo.Types[ast.Unparen(c.Fun)]
											b, isB := types.Unalias(tv.Type).Underlying().(*types.Basic)
											return tv.IsType() && isB && b.Kind() == types.Uintptr && check(c.Args[0])
										}
										isOffIdent := func(e ast.Expr) bool {
											id, isID := ast.Unparen(e).(*ast.Ident)
											return isID && wpd.p.TypesInfo.Uses[id] == offParam
										}
										isRecvFld := func(e ast.Expr) bool {
											return isRecvDstField(e, recvVar)
										}
										if (isUintptrOf(bin.X, isRecvFld) && isUintptrOf(bin.Y, isOffIdent)) ||
											(isUintptrOf(bin.X, isOffIdent) && isUintptrOf(bin.Y, isRecvFld)) {
											wpd.methodClass[mfn] = ptrMethodApplyOffset
											wpd.applyOffsetTypes = append(wpd.applyOffsetTypes, on)
											continue
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	// Second pass for delegating methods like AsIfaceOf -> AsValueOf.Interface() or IsNil delegation.
	for mi := 0; mi < wpd.mset.Len(); mi++ {
		mfn, _ := wpd.mset.At(mi).Obj().(*types.Func)
		if mfn == nil || mfn.Pkg() != wpd.p.Types || wpd.methodClass[mfn] != ptrMethodRawDeref {
			continue
		}
		msig, okMS := mfn.Type().(*types.Signature)
		if !okMS {
			continue
		}
		mfd := wpd.idx.FuncDecls[mfn]
		if mfd == nil || mfd.Body == nil || len(mfd.Body.List) != 1 || mfd.Recv == nil || len(mfd.Recv.List) != 1 || len(mfd.Recv.List[0].Names) != 1 {
			continue
		}
		rv, _ := wpd.p.TypesInfo.Defs[mfd.Recv.List[0].Names[0]].(*types.Var)
		if rv == nil || len(wpd.idx.UsesOf[rv]) != 1 {
			continue
		}
		u := wpd.idx.UsesOf[rv][0]
		sel, isS := wpd.idx.ParentUnparen(u).(*ast.SelectorExpr)
		if !isS || ast.Unparen(sel.X) != u {
			continue
		}
		c, isC := wpd.idx.ParentUnparen(sel).(*ast.CallExpr)
		if !isC || ast.Unparen(c.Fun) != sel {
			continue
		}
		cfn := syntaxutil.ResolveCalledFuncObj(wpd.p, c.Fun)
		if cfn == nil {
			continue
		}
		if wpd.methodClass[cfn] == ptrMethodIsNil {
			ret, isRet := wpd.idx.ParentUnparen(c).(*ast.ReturnStmt)
			if msig.Params().Len() == 0 && msig.Results().Len() == 1 && len(c.Args) == 0 && !c.Ellipsis.IsValid() && isRet && len(ret.Results) == 1 {
				wpd.methodClass[mfn] = ptrMethodIsNil
			}
		} else if wpd.methodClass[cfn] == ptrMethodAsValue && msig.Params().Len() == 1 && msig.Results().Len() == 1 &&
			isEmptyInterfaceType(msig.Results().At(0).Type()) && len(c.Args) == 1 && !c.Ellipsis.IsValid() {
			aid, isAID := ast.Unparen(c.Args[0]).(*ast.Ident)
			if !isAID || wpd.p.TypesInfo.Uses[aid] != msig.Params().At(0) {
				continue
			}
			parSel, isPS := wpd.idx.ParentUnparen(c).(*ast.SelectorExpr)
			if !isPS || ast.Unparen(parSel.X) != c || parSel.Sel == nil || parSel.Sel.Name != "Interface" {
				continue
			}
			parCall, isPC := wpd.idx.ParentUnparen(parSel).(*ast.CallExpr)
			ret, isRet := wpd.idx.ParentUnparen(parCall).(*ast.ReturnStmt)
			if isPC && ast.Unparen(parCall.Fun) == parSel && len(parCall.Args) == 0 && isRet && len(ret.Results) == 1 {
				wpd.methodClass[mfn] = ptrMethodAsIface
			}
		}
	}
}

func (wpd *wrapperPtrDiscipline) typeMentionsDstOwner(root types.Type) bool {
	seenT := map[types.Type]bool{}
	hit := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || hit {
			return
		}
		t = types.Unalias(t)
		if types.Identical(t, wpd.dstOwner) {
			hit = true
			return
		}
		if seenT[t] {
			return
		}
		seenT[t] = true
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			walk(u.Elem())
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
			walk(u.Elem())
		case *types.Chan:
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if f := u.Field(i); f.Exported() || f.Embedded() {
					walk(f.Type())
				}
			}
		case *types.Signature:
			for i := 0; i < u.Params().Len(); i++ {
				walk(u.Params().At(i).Type())
			}
			for i := 0; i < u.Results().Len(); i++ {
				walk(u.Results().At(i).Type())
			}
		}
	}
	walk(root)
	return hit
}

func (wpd *wrapperPtrDiscipline) isOwnerSingleFieldLit(expr ast.Expr) (ast.Expr, bool) {
	cl, isCL := ast.Unparen(expr).(*ast.CompositeLit)
	if !isCL || len(cl.Elts) != 1 || syntaxutil.DerefNamedStruct(wpd.p.TypesInfo.TypeOf(cl)) != wpd.dstOwner {
		return nil, false
	}
	kv, isKV := cl.Elts[0].(*ast.KeyValueExpr)
	if !isKV {
		return nil, false
	}
	kid, isKID := ast.Unparen(kv.Key).(*ast.Ident)
	if !isKID || wpd.p.TypesInfo.Uses[kid] != wpd.dstFld {
		return nil, false
	}
	return ast.Unparen(kv.Value), true
}

func (wpd *wrapperPtrDiscipline) isUnsafePtrSlotCastOfField(expr ast.Expr, wantRecv *types.Var) bool {
	cc, isCC := ast.Unparen(expr).(*ast.CallExpr)
	if !isCC || len(cc.Args) != 1 || cc.Ellipsis.IsValid() {
		return false
	}
	ctv := wpd.p.TypesInfo.Types[ast.Unparen(cc.Fun)]
	if !ctv.IsType() || ctv.Type == nil {
		return false
	}
	ptrT, isP := types.Unalias(ctv.Type).Underlying().(*types.Pointer)
	if !isP || !syntaxutil.IsUnsafePointerType(ptrT.Elem()) {
		return false
	}
	sel, isS := ast.Unparen(cc.Args[0]).(*ast.SelectorExpr)
	if !isS || wpd.p.TypesInfo.Uses[sel.Sel] != wpd.dstFld {
		return false
	}
	if wantRecv != nil {
		rid, isID := ast.Unparen(sel.X).(*ast.Ident)
		if !isID || wpd.p.TypesInfo.Uses[rid] != wantRecv {
			return false
		}
	}
	return true
}

func (wpd *wrapperPtrDiscipline) isOwnerSliceType(t types.Type) bool {
	if t == nil {
		return false
	}
	sl, isSl := types.Unalias(t).Underlying().(*types.Slice)
	return isSl && types.Identical(types.Unalias(sl.Elem()), wpd.dstOwner)
}

func (wpd *wrapperPtrDiscipline) isOwnerSlicePtrDeref(expr ast.Expr, wantRecv *types.Var) bool {
	st, isSt := ast.Unparen(expr).(*ast.StarExpr)
	if !isSt {
		return false
	}
	cc, isCC := ast.Unparen(st.X).(*ast.CallExpr)
	if !isCC || len(cc.Args) != 1 || cc.Ellipsis.IsValid() {
		return false
	}
	ctv := wpd.p.TypesInfo.Types[ast.Unparen(cc.Fun)]
	if !ctv.IsType() || ctv.Type == nil {
		return false
	}
	ptrT, isP := types.Unalias(ctv.Type).Underlying().(*types.Pointer)
	if !isP || !wpd.isOwnerSliceType(ptrT.Elem()) {
		return false
	}
	sel, isS := ast.Unparen(cc.Args[0]).(*ast.SelectorExpr)
	if !isS || wpd.p.TypesInfo.Uses[sel.Sel] != wpd.dstFld {
		return false
	}
	rid, isID := ast.Unparen(sel.X).(*ast.Ident)
	return isID && wpd.p.TypesInfo.Uses[rid] == wantRecv
}
