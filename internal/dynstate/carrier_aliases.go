package dynstate

import (
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type carrierAliasConfig struct {
	parentAliases        map[types.Object]localCarrierAliases
	parentLinks          map[types.Object][]*types.Var
	carrierVar           func(types.Object) (*types.Var, bool)
	skipMethodRecv       func(*flowir.Value) bool
	skipNonBuiltinCalls  bool
	descendNested        bool
	trackLinks           bool
	onCarrierLink        func(own, target *types.Var)
	onNonCarrierPkgBind  func(pkgVar *types.Var, pos token.Pos, composite bool, allVars, linkVars []*types.Var)
	onParamCompositeBind func(pos token.Pos, allVars, linkVars []*types.Var)
	onRHSMethodValue     func(mv *flowir.Value, aliases map[types.Object]localCarrierAliases)
	onPlainCall          func(
		callVal *flowir.Value,
		valSources func(*flowir.Value) (rootSrcs, allSrcs []*types.Var),
		valLinks func(*flowir.Value) []*types.Var,
	)
}

type carrierAliasSolver struct {
	audited       bool
	b             *flowir.Body
	cfg           carrierAliasConfig
	aliased       map[types.Object]localCarrierAliases
	linkAliased   map[types.Object][]*types.Var
	memAliases    map[types.Object]map[types.Object]bool
	addrTakenBare map[*types.Var]bool
	isTopParam    map[*types.Var]bool
}

func computeBodyCarrierAliases(
	audited bool,
	fc *pkgFlowCache,
	b *flowir.Body,
	cfg carrierAliasConfig,
) (map[types.Object]localCarrierAliases, map[types.Object][]*types.Var) {
	aliased := make(map[types.Object]localCarrierAliases, len(cfg.parentAliases))
	for obj, entry := range cfg.parentAliases {
		aliased[obj] = localCarrierAliases{
			root: append([]*types.Var(nil), entry.root...),
			all:  append([]*types.Var(nil), entry.all...),
		}
	}
	var linkAliased map[types.Object][]*types.Var
	if cfg.trackLinks {
		linkAliased = make(map[types.Object][]*types.Var, len(cfg.parentLinks))
		for obj, lvars := range cfg.parentLinks {
			linkAliased[obj] = append([]*types.Var(nil), lvars...)
		}
	}
	if b == nil || cfg.carrierVar == nil {
		return aliased, linkAliased
	}
	s := &carrierAliasSolver{
		audited:       audited,
		b:             b,
		cfg:           cfg,
		aliased:       aliased,
		linkAliased:   linkAliased,
		memAliases:    fc.scopedLocalCarrierAliases(audited, b, nil),
		addrTakenBare: map[*types.Var]bool{},
		isTopParam:    make(map[*types.Var]bool, len(b.Params)),
	}
	for _, pv := range b.Params {
		if pv != nil {
			s.isTopParam[pv] = true
		}
	}
	s.solve()
	return s.aliased, s.linkAliased
}

func (s *carrierAliasSolver) visitOps(fn func(*flowir.Op)) {
	if s.cfg.descendNested {
		flowir.VisitAllOps(s.b, fn)
	} else {
		flowir.VisitSyncAndIIFEOps(s.b, fn)
	}
}

func (s *carrierAliasSolver) checkAddr(v *flowir.Value) {
	if v == nil {
		return
	}
	if !s.cfg.descendNested {
		if v.Kind == flowir.ValMakeClosure {
			return
		}
		if v.Kind == flowir.ValCall && v.CallKind == flowir.CallIIFE {
			for _, a := range v.Args {
				s.checkAddr(a)
			}
			return
		}
	}
	if v.Kind == flowir.ValAddrOf && !v.IsArraySlice && v.AddrPlace.IsBareVar() {
		s.addrTakenBare[v.AddrPlace.Obj] = true
	}
	if v.Kind == flowir.ValMethodVal && v.AutoAddr && v.HasRecvPlace && v.RecvPlace.IsBareVar() {
		s.addrTakenBare[v.RecvPlace.Obj] = true
	}
	if v.Kind == flowir.ValCall && v.AutoAddrRecv && v.HasRecvPlace && v.RecvPlace.IsBareVar() {
		s.addrTakenBare[v.RecvPlace.Obj] = true
	}
	v.ForEachChildValue(func(ch *flowir.Value) bool {
		s.checkAddr(ch)
		return true
	})
}

func (s *carrierAliasSolver) addAliases(dst types.Object, rootSrcs, allSrcs []*types.Var) bool {
	if dst == nil || (len(rootSrcs) == 0 && len(allSrcs) == 0) {
		return false
	}
	if _, isC := s.cfg.carrierVar(dst); isC {
		return false
	}
	entry := s.aliased[dst]
	changed := false
	if len(rootSrcs) > 0 && (syntaxutil.IsRefHeaderType(dst.Type()) || isTypeParamType(dst.Type())) {
		if appendUniqueVars(&entry.root, rootSrcs) {
			changed = true
		}
		if appendUniqueVars(&entry.all, rootSrcs) {
			changed = true
		}
	}
	if appendUniqueVars(&entry.all, allSrcs) {
		changed = true
	}
	if changed {
		s.aliased[dst] = entry
	}
	return changed
}

func (s *carrierAliasSolver) addLinkAliases(dst types.Object, lvars []*types.Var) bool {
	if !s.cfg.trackLinks || dst == nil || len(lvars) == 0 {
		return false
	}
	if _, isC := s.cfg.carrierVar(dst); isC {
		return false
	}
	cur := s.linkAliased[dst]
	if appendUniqueVars(&cur, lvars) {
		s.linkAliased[dst] = cur
		return true
	}
	return false
}

func (s *carrierAliasSolver) valSources(v *flowir.Value) (rootSrcs, allSrcs []*types.Var) {
	return valueCarrierSources(s.audited, v, s.cfg.carrierVar, s.aliased, s.cfg.skipMethodRecv, s.cfg.skipNonBuiltinCalls)
}

func (s *carrierAliasSolver) valLinks(v *flowir.Value) []*types.Var {
	if !s.cfg.trackLinks {
		return nil
	}
	return collectValueLinkVars(v, s.cfg.carrierVar, s.linkAliased)
}

func (s *carrierAliasSolver) propagateMem(obj *types.Var, pos token.Pos, derefStore bool, rootSrcs, allSrcs, lvars []*types.Var) bool {
	if len(s.memAliases[obj]) == 0 {
		return false
	}
	changed := false
	for next := range s.memAliases[obj] {
		var nextRoot []*types.Var
		if nv, ok := next.(*types.Var); ok {
			if derefStore && s.addrTakenBare[nv] {
				nextRoot = rootSrcs
			}
			if s.cfg.onParamCompositeBind != nil && s.isTopParam[nv] {
				s.cfg.onParamCompositeBind(pos, allSrcs, lvars)
			}
		}
		if s.addAliases(next, nextRoot, allSrcs) {
			changed = true
		}
		if s.addLinkAliases(next, lvars) {
			changed = true
		}
	}
	return changed
}

func (s *carrierAliasSolver) bindObj(obj *types.Var, pos token.Pos, composite, inPlace, derefStore bool, rootSrcs, allSrcs, lvars []*types.Var) bool {
	if obj == nil || (len(rootSrcs) == 0 && len(allSrcs) == 0 && len(lvars) == 0) {
		return false
	}
	if cv, isC := s.cfg.carrierVar(obj); isC {
		if s.cfg.onCarrierLink != nil {
			for _, lv := range lvars {
				if lv != cv {
					s.cfg.onCarrierLink(cv, lv)
				}
			}
		}
		return false
	}
	if obj.Pkg() != nil && obj.Parent() == obj.Pkg().Scope() {
		if s.cfg.onNonCarrierPkgBind != nil {
			s.cfg.onNonCarrierPkgBind(obj, pos, composite || inPlace, allSrcs, lvars)
		}
		return false
	}
	if !syntaxutil.IsLocalVar(obj) {
		return false
	}
	if composite || inPlace {
		if s.cfg.onParamCompositeBind != nil && s.isTopParam[obj] {
			s.cfg.onParamCompositeBind(pos, allSrcs, lvars)
		}
		if s.cfg.onCarrierLink != nil && len(lvars) > 0 {
			for _, own := range s.aliased[obj].all {
				for _, lv := range lvars {
					if lv != own {
						s.cfg.onCarrierLink(own, lv)
					}
				}
			}
		}
	}
	changed := false
	if len(rootSrcs) > 0 || len(allSrcs) > 0 {
		if composite || inPlace || canAliasCarrierType(s.audited, obj.Type()) || isTypeParamType(obj.Type()) {
			var ownRoot []*types.Var
			if (!composite && !inPlace) || (derefStore && s.addrTakenBare[obj]) {
				ownRoot = rootSrcs
			}
			if s.addAliases(obj, ownRoot, allSrcs) {
				changed = true
			}
		}
	}
	if s.addLinkAliases(obj, lvars) {
		changed = true
	}
	if (composite || inPlace) && s.propagateMem(obj, pos, derefStore, rootSrcs, allSrcs, lvars) {
		changed = true
	}
	return changed
}

func (s *carrierAliasSolver) bindPlace(dst flowir.Place, rootSrcs, allSrcs, lvars []*types.Var, inPlace bool) bool {
	if len(rootSrcs) == 0 && len(allSrcs) == 0 && len(lvars) == 0 {
		return false
	}
	derefStore := !inPlace && len(dst.Projs) >= 1 && dst.Projs[len(dst.Projs)-1].Kind == flowir.ProjDeref
	if dst.Obj != nil {
		return s.bindObj(dst.Obj, dst.RootPos, !dst.IsBareVar(), inPlace, derefStore, rootSrcs, allSrcs, lvars)
	}
	if dst.Root == flowir.RootTransient && dst.Base != nil {
		changed := false
		walkTransientTargetValues(dst.Base, func(cur *flowir.Value) {
			if cur.Kind == flowir.ValPlace && cur.Place.Obj != nil {
				if s.bindObj(cur.Place.Obj, cur.Place.RootPos, true, !derefStore, derefStore, rootSrcs, allSrcs, lvars) {
					changed = true
				}
			} else if cur.Kind == flowir.ValAddrOf && cur.AddrPlace.Obj != nil {
				if s.bindObj(cur.AddrPlace.Obj, cur.AddrPlace.RootPos, true, !derefStore, derefStore, rootSrcs, allSrcs, lvars) {
					changed = true
				}
			}
		})
		return changed
	}
	return false
}

func (s *carrierAliasSolver) bindValTarget(target *flowir.Value, allSrcs, lvars []*types.Var) bool {
	if target == nil || (len(allSrcs) == 0 && len(lvars) == 0) {
		return false
	}
	if target.Kind == flowir.ValPlace {
		return s.bindPlace(target.Place, nil, allSrcs, lvars, true)
	}
	changed := false
	walkTransientTargetValues(target, func(cur *flowir.Value) {
		if cur.Kind == flowir.ValPlace && cur.Place.Obj != nil {
			if s.bindObj(cur.Place.Obj, cur.Place.RootPos, true, true, false, nil, allSrcs, lvars) {
				changed = true
			}
		} else if cur.Kind == flowir.ValAddrOf && cur.AddrPlace.Obj != nil {
			if s.bindObj(cur.AddrPlace.Obj, cur.AddrPlace.RootPos, true, true, false, nil, allSrcs, lvars) {
				changed = true
			}
		}
	})
	return changed
}

func (s *carrierAliasSolver) scanMethodValues(v *flowir.Value) {
	if s.cfg.onRHSMethodValue == nil || v == nil {
		return
	}
	var walk func(cur *flowir.Value)
	walk = func(cur *flowir.Value) {
		if cur == nil || cur.Kind == flowir.ValMakeClosure {
			return
		}
		if cur.Kind == flowir.ValCall && cur.CallKind == flowir.CallIIFE {
			for _, a := range cur.Args {
				walk(a)
			}
			flowir.ForEachIIFEReturnValue(cur, walk)
			return
		}
		if cur.Kind == flowir.ValMethodVal {
			s.cfg.onRHSMethodValue(cur, s.aliased)
		}
		cur.ForEachChildValue(func(ch *flowir.Value) bool {
			walk(ch)
			return true
		})
	}
	walk(v)
}

func (s *carrierAliasSolver) scanCallBinds(v *flowir.Value) bool {
	if v == nil || v.Kind == flowir.ValMakeClosure {
		return false
	}
	changed := false
	if v.Kind == flowir.ValCall {
		switch v.CallKind {
		case flowir.CallBuiltin:
			switch {
			case v.BuiltinName == "copy" && len(v.Args) == 2:
				_, allSrcs := s.valSources(v.Args[1])
				lvars := s.valLinks(v.Args[1])
				if s.bindValTarget(v.Args[0], allSrcs, lvars) {
					changed = true
				}
			case v.BuiltinName == "append" && len(v.Args) >= 2:
				for _, elem := range v.Args[1:] {
					_, allSrcs := s.valSources(elem)
					lvars := s.valLinks(elem)
					if s.bindValTarget(v.Args[0], allSrcs, lvars) {
						changed = true
					}
				}
			}
		case flowir.CallPlain:
			if s.cfg.onPlainCall != nil && !v.IsMethodExprCall {
				s.cfg.onPlainCall(v, s.valSources, s.valLinks)
			}
		case flowir.CallIIFE:
			for _, a := range v.Args {
				if s.scanCallBinds(a) {
					changed = true
				}
			}
			if v.IIFE != nil {
				v.ForEachArgParam(func(arg *flowir.Value, _ types.Type, _ int, paramIdx int, ok bool, packedVariadic bool) bool {
					if !ok || paramIdx < 0 || paramIdx >= len(v.IIFE.Params) || arg == nil {
						return true
					}
					pv := v.IIFE.Params[paramIdx]
					if pv == nil {
						return true
					}
					rootSrcs, allSrcs := s.valSources(arg)
					if packedVariadic {
						rootSrcs = nil
					}
					lvars := s.valLinks(arg)
					if s.bindObj(pv, pv.Pos(), packedVariadic, false, false, rootSrcs, allSrcs, lvars) {
						changed = true
					}
					return true
				})
			}
			return changed
		}
	}
	v.ForEachChildValue(func(ch *flowir.Value) bool {
		if s.scanCallBinds(ch) {
			changed = true
		}
		return true
	})
	return changed
}

func (s *carrierAliasSolver) solve() {
	s.visitOps(func(op *flowir.Op) {
		forEachOpTopValues(op, s.checkAddr)
	})
	for changed := true; changed; {
		changed = false
		s.visitOps(func(op *flowir.Op) {
			forEachOpTopValues(op, s.scanMethodValues)
			switch op.Kind {
			case flowir.OpAssign:
				op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
					rootSrcs, allSrcs := s.valSources(src)
					lvars := s.valLinks(src)
					if op.AssignKind == flowir.AssignRange {
						rootSrcs = allSrcs
					}
					if mapPlace, keyVal, isMapW := dst.AsMapWrite(); isMapW && keyVal != nil {
						_, keyAll := s.valSources(keyVal)
						keyLinks := s.valLinks(keyVal)
						mergedAll := append([]*types.Var(nil), allSrcs...)
						appendUniqueVars(&mergedAll, keyAll)
						mergedLinks := append([]*types.Var(nil), lvars...)
						appendUniqueVars(&mergedLinks, keyLinks)
						if s.bindPlace(mapPlace, nil, mergedAll, mergedLinks, true) {
							changed = true
						}
					} else if s.bindPlace(dst, rootSrcs, allSrcs, lvars, false) {
						changed = true
					}
					dst.ForEachChildValue(func(cv *flowir.Value) bool {
						if s.scanCallBinds(cv) {
							changed = true
						}
						return true
					})
					return true
				})
				for _, src := range op.Srcs {
					if s.scanCallBinds(src) {
						changed = true
					}
				}
			case flowir.OpTypeSwitchBind:
				if op.SwitchDst != nil && syntaxutil.IsLocalVar(op.SwitchDst) {
					rootSrcs, allSrcs := s.valSources(op.SwitchSrc)
					lvars := s.valLinks(op.SwitchSrc)
					var swPos token.Pos
					if op.SwitchAST != nil {
						swPos = op.SwitchAST.Pos()
					}
					if s.bindObj(op.SwitchDst, swPos, false, false, false, rootSrcs, allSrcs, lvars) {
						changed = true
					}
				}
				if s.scanCallBinds(op.SwitchSrc) {
					changed = true
				}
			case flowir.OpChanSend:
				_, sendAll := s.valSources(op.SendVal)
				sendLinks := s.valLinks(op.SendVal)
				if s.bindPlace(op.ChanPlace, nil, sendAll, sendLinks, true) {
					changed = true
				}
				op.ChanPlace.ForEachChildValue(func(cv *flowir.Value) bool {
					if s.scanCallBinds(cv) {
						changed = true
					}
					return true
				})
				if s.scanCallBinds(op.ChanVal) {
					changed = true
				}
				if s.scanCallBinds(op.SendVal) {
					changed = true
				}
			case flowir.OpReturn:
				for _, r := range op.Results {
					if s.scanCallBinds(r) {
						changed = true
					}
				}
			case flowir.OpDefer, flowir.OpGo:
				if s.scanCallBinds(op.Call) {
					changed = true
				}
			case flowir.OpExpr:
				if s.scanCallBinds(op.Expr) {
					changed = true
				}
			}
		})
	}
}
