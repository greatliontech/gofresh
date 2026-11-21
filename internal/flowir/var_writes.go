package flowir

import "go/types"

// VarWriteInfo summarizes all definitions, post-definition writes, channel
// sends, mutating container builtins, and explicit or implicit address-takes on
// a non-field *types.Var across a package's lowered declarations.
type VarWriteInfo struct {
	Defs              int
	InitVal           *Value
	HasZeroDecl       bool
	HasNonPlainDef    bool
	HasPostDefWrite   bool
	HasChanSend       bool
	HasExplicitAddr   bool
	HasAutoAddrMethod bool
	HasBuiltinMut     bool
}

// VarWriteInfos returns the lazily computed variable-write and address summary
// map across all lowered declarations in c.
func (c *PkgCache) VarWriteInfos() map[*types.Var]*VarWriteInfo {
	if c == nil {
		return nil
	}
	if c.varWritesReady {
		return c.varWrites
	}
	c.varWritesReady = true
	c.varWrites = make(map[*types.Var]*VarWriteInfo)
	var pkgScope *types.Scope
	if c.Pkg != nil {
		pkgScope = c.Pkg.Scope()
	}
	entry := func(v *types.Var) *VarWriteInfo {
		if v == nil || v.IsField() {
			return nil
		}
		st := c.varWrites[v]
		if st == nil {
			st = &VarWriteInfo{}
			c.varWrites[v] = st
		}
		return st
	}
	markPlace := func(pl Place, fn func(*VarWriteInfo)) {
		ForEachPlaceRootVar(pl, func(rv *types.Var) {
			if st := entry(rv); st != nil {
				fn(st)
			}
		})
	}
	markValue := func(val *Value, fn func(*VarWriteInfo)) {
		ForEachValueRootVar(val, func(rv *types.Var) {
			if st := entry(rv); st != nil {
				fn(st)
			}
		})
	}

	var scanBody func(b *Body, topGenDecl bool)
	scanVal := func(v *Value) {
		if v == nil {
			return
		}
		v.WalkValues(func(cur *Value) bool {
			switch cur.Kind {
			case ValAddrOf:
				markPlace(cur.AddrPlace, func(st *VarWriteInfo) { st.HasExplicitAddr = true })
			case ValMethodVal:
				if cur.AutoAddr && cur.HasRecvPlace {
					markPlace(cur.RecvPlace, func(st *VarWriteInfo) { st.HasAutoAddrMethod = true })
				}
			case ValCall:
				if cur.AutoAddrRecv && cur.HasRecvPlace {
					markPlace(cur.RecvPlace, func(st *VarWriteInfo) { st.HasAutoAddrMethod = true })
				}
				if cur.CallKind == CallBuiltin && len(cur.Args) > 0 && cur.Args[0] != nil {
					switch cur.BuiltinName {
					case "delete", "clear", "copy", "append":
						markValue(cur.Args[0], func(st *VarWriteInfo) { st.HasBuiltinMut = true })
					}
				}
				if cur.CallKind == CallIIFE && cur.IIFE != nil {
					scanBody(cur.IIFE, false)
				}
			case ValMakeClosure:
				if cur.Closure != nil {
					scanBody(cur.Closure, false)
				}
			}
			return true
		})
	}

	scanBody = func(b *Body, topGenDecl bool) {
		if b == nil {
			return
		}
		for i := range b.Ops {
			op := &b.Ops[i]
			op.ForEachValue(func(v *Value) bool {
				scanVal(v)
				return true
			})
			switch op.Kind {
			case OpAssign:
				op.ForEachAssignPair(func(_ int, dst Place, isDef bool, src *Value) bool {
					if dst.Obj == nil {
						markPlace(dst, func(st *VarWriteInfo) { st.HasPostDefWrite = true })
						return true
					}
					st := entry(dst.Obj)
					if st == nil {
						return true
					}
					isOwnScopeDef := isDef && dst.IsBareVar() &&
						((topGenDecl && pkgScope != nil && dst.Obj.Parent() == pkgScope) ||
							(!topGenDecl && (pkgScope == nil || dst.Obj.Parent() != pkgScope)))
					if isOwnScopeDef {
						switch op.AssignKind {
						case AssignPlain:
							if src != nil {
								st.Defs++
								st.InitVal = src
							} else {
								st.HasPostDefWrite = true
							}
						case AssignZeroDecl:
							st.Defs++
							st.HasZeroDecl = true
						case AssignMulti, AssignRange:
							st.Defs++
							st.HasNonPlainDef = true
						default:
							st.HasPostDefWrite = true
						}
					} else {
						st.HasPostDefWrite = true
					}
					return true
				})
				if op.AssignKind == AssignRange && op.RangeBody != nil {
					scanBody(op.RangeBody, false)
				}
			case OpTypeSwitchBind:
				if st := entry(op.SwitchDst); st != nil {
					st.Defs++
					st.HasNonPlainDef = true
				}
			case OpChanSend:
				if op.ChanVal != nil {
					markValue(op.ChanVal, func(st *VarWriteInfo) { st.HasChanSend = true })
				} else {
					markPlace(op.ChanPlace, func(st *VarWriteInfo) { st.HasChanSend = true })
				}
			}
		}
	}

	for _, gd := range c.GenDecls {
		scanBody(c.Body(gd), true)
	}
	for _, fd := range c.FuncDecls {
		scanBody(c.FuncBody(fd), false)
	}
	// Ensure all non-field variables in Info.Defs have entries so shadowed or
	// ill-typed const+var collisions fail closed.
	if c.Info != nil {
		for _, obj := range c.Info.Defs {
			if v, ok := obj.(*types.Var); ok && v != nil && !v.IsField() {
				if c.varWrites[v] == nil {
					c.varWrites[v] = &VarWriteInfo{}
				}
			}
		}
	}
	return c.varWrites
}

// SingleWritePkgGlobalInit returns (initVal, true) when gv is a package-scope
// variable defined by a single plain initializer in c.Pkg with zero subsequent
// writes, interior projection writes, mutating container builtins, channel
// sends, or explicit/implicit address-takes anywhere in c.
func (c *PkgCache) SingleWritePkgGlobalInit(gv *types.Var) (*Value, bool) {
	if c == nil || c.Pkg == nil || gv == nil || gv.Pkg() != c.Pkg || gv.Parent() != c.Pkg.Scope() {
		return nil, false
	}
	st := c.VarWriteInfos()[gv]
	if st == nil || st.Defs != 1 || st.InitVal == nil || st.HasZeroDecl || st.HasNonPlainDef ||
		st.HasPostDefWrite || st.HasChanSend || st.HasExplicitAddr || st.HasAutoAddrMethod || st.HasBuiltinMut {
		return nil, false
	}
	return st.InitVal, true
}

// SingleWriteLocalInit returns (initVal, true) when lv is a non-parameter,
// non-receiver, non-result local variable owned by fnBody and defined by a
// single plain initializer with zero subsequent writes, mutating container
// builtins, channel sends, or explicit/implicit address-takes.
func (c *PkgCache) SingleWriteLocalInit(fnBody *Body, lv *types.Var) (*Value, bool) {
	if c == nil || fnBody == nil || lv == nil || !fnBody.OwnsVar(lv) || lv == fnBody.Recv || fnBody.ResultSet[lv] {
		return nil, false
	}
	if _, isParam := fnBody.ParamIndex[lv]; isParam {
		return nil, false
	}
	st := c.VarWriteInfos()[lv]
	if st == nil || st.Defs != 1 || st.InitVal == nil || st.HasZeroDecl || st.HasNonPlainDef ||
		st.HasPostDefWrite || st.HasChanSend || st.HasExplicitAddr || st.HasAutoAddrMethod || st.HasBuiltinMut {
		return nil, false
	}
	return st.InitVal, true
}

// VarHasExplicitWriteOrAddr reports whether v (a package-scope or local
// variable) lacks a single plain/zero definition or undergoes any
// post-definition write, projection write, channel send, mutating container
// builtin (delete/clear/copy/append), or explicit/implicit address-take.
func (c *PkgCache) VarHasExplicitWriteOrAddr(v *types.Var) bool {
	if c == nil || v == nil {
		return true
	}
	st := c.VarWriteInfos()[v]
	if st == nil {
		return true
	}
	return st.Defs != 1 || st.HasNonPlainDef || st.HasPostDefWrite || st.HasChanSend ||
		st.HasExplicitAddr || st.HasAutoAddrMethod || st.HasBuiltinMut
}

// ForEachPlaceRootVar visits the root *types.Var(s) underlying pl, following
// transient base values across non-copying conversions and address-takes.
func ForEachPlaceRootVar(pl Place, fn func(*types.Var)) {
	if pl.Obj != nil {
		fn(pl.Obj)
		return
	}
	if pl.Root == RootTransient && pl.Base != nil {
		ForEachValueRootVar(pl.Base, fn)
	}
}

// ForEachValueRootVar visits the root *types.Var(s) underlying v across
// places, address-takes, and non-string-copying conversions.
func ForEachValueRootVar(v *Value, fn func(*types.Var)) {
	for v != nil {
		switch v.Kind {
		case ValConvert:
			if !v.IsTypeAssert && v.Arg != nil && v.Arg.Type != nil {
				if b, ok := v.Arg.Type.Underlying().(*types.Basic); ok && b.Info()&types.IsString != 0 {
					return
				}
			}
			v = v.Arg
		case ValPlace:
			ForEachPlaceRootVar(v.Place, fn)
			return
		case ValAddrOf:
			ForEachPlaceRootVar(v.AddrPlace, fn)
			return
		default:
			return
		}
	}
}
