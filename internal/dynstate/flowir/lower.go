package flowir

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// LowerFunc lowers a function or method declaration into a canonical Body.
func LowerFunc(info *types.Info, pkg *types.Package, fd *ast.FuncDecl) *Body {
	if info == nil || fd == nil || fd.Body == nil {
		return nil
	}
	b := newBody(fd, fd.Body, fd.Pos(), fd.End())
	l := &lowerer{info: info, pkg: pkg, body: b}
	if fd.Recv != nil && len(fd.Recv.List) == 1 {
		if names := fd.Recv.List[0].Names; len(names) == 1 && names[0] != nil && names[0].Name != "_" {
			if v, ok := info.Defs[names[0]].(*types.Var); ok {
				b.Recv = v
			}
		}
	}
	if fd.Type != nil {
		l.populateSigParamsAndResults(fd.Type)
	}
	l.lowerStmtList(fd.Body.List, true)
	return b
}

// LowerFuncLit lowers a function literal into a canonical Body.
func LowerFuncLit(info *types.Info, pkg *types.Package, lit *ast.FuncLit) *Body {
	if info == nil || lit == nil || lit.Body == nil {
		return nil
	}
	b := newBody(lit, lit.Body, lit.Pos(), lit.End())
	b.FuncLit = lit
	l := &lowerer{info: info, pkg: pkg, body: b}
	if lit.Type != nil {
		l.populateSigParamsAndResults(lit.Type)
	}
	l.lowerStmtList(lit.Body.List, true)
	return b
}

// LowerNode lowers an arbitrary AST node (*ast.FuncDecl, *ast.FuncLit,
// *ast.BlockStmt, or statement/expression subtree) into a canonical Body.
func LowerNode(info *types.Info, pkg *types.Package, node ast.Node) *Body {
	if info == nil || node == nil {
		return nil
	}
	switch n := node.(type) {
	case *ast.FuncDecl:
		return LowerFunc(info, pkg, n)
	case *ast.FuncLit:
		return LowerFuncLit(info, pkg, n)
	case *ast.BlockStmt:
		b := newBody(n, n, n.Pos(), n.End())
		l := &lowerer{info: info, pkg: pkg, body: b}
		l.lowerStmtList(n.List, true)
		return b
	default:
		b := newBody(node, nil, node.Pos(), node.End())
		l := &lowerer{info: info, pkg: pkg, body: b}
		if stmt, ok := node.(ast.Stmt); ok {
			l.lowerStmt(stmt, false)
		} else if expr, ok := node.(ast.Expr); ok {
			b.Ops = append(b.Ops, Op{
				Kind:    OpExpr,
				StmtAST: expr,
				Expr:    l.lowerValue(expr),
			})
		}
		return b
	}
}

func newBody(astNode ast.Node, blk *ast.BlockStmt, scopeStart, scopeEnd token.Pos) *Body {
	bodyStart, bodyEnd := scopeStart, scopeEnd
	if blk != nil {
		bodyStart, bodyEnd = blk.Pos(), blk.End()
	}
	return &Body{
		AST:        astNode,
		Block:      blk,
		ScopeStart: scopeStart,
		ScopeEnd:   scopeEnd,
		BodyStart:  bodyStart,
		BodyEnd:    bodyEnd,
		ParamIndex: make(map[*types.Var]int),
		ResultSet:  make(map[*types.Var]bool),
		FreeVars:   make(map[*types.Var]bool),
	}
}

type lowerer struct {
	info *types.Info
	pkg  *types.Package
	body *Body
}

func (l *lowerer) populateSigParamsAndResults(ft *ast.FuncType) {
	if ft.Params != nil {
		idx := 0
		for _, field := range ft.Params.List {
			if len(field.Names) == 0 {
				l.body.Params = append(l.body.Params, nil)
				idx++
				continue
			}
			for _, name := range field.Names {
				var v *types.Var
				if name != nil && name.Name != "_" {
					v, _ = l.info.Defs[name].(*types.Var)
				}
				l.body.Params = append(l.body.Params, v)
				if v != nil {
					l.body.ParamIndex[v] = idx
				}
				idx++
			}
		}
	}
	if ft.Results != nil {
		for _, field := range ft.Results.List {
			if len(field.Names) == 0 {
				l.body.Results = append(l.body.Results, nil)
				continue
			}
			for _, name := range field.Names {
				var v *types.Var
				if name != nil && name.Name != "_" {
					v, _ = l.info.Defs[name].(*types.Var)
				}
				l.body.Results = append(l.body.Results, v)
				if v != nil {
					l.body.ResultSet[v] = true
				}
			}
		}
	}
}

func (l *lowerer) recordFreeVar(v *types.Var) {
	if v == nil || v.IsField() || v.Pkg() == nil || v.Parent() == v.Pkg().Scope() {
		return
	}
	if !l.body.OwnsVar(v) {
		l.body.FreeVars[v] = true
	}
}

func (l *lowerer) bubbleChildFreeVars(child *Body) {
	if child == nil {
		return
	}
	for v := range child.FreeVars {
		l.recordFreeVar(v)
	}
}

func (l *lowerer) lowerStmtList(stmts []ast.Stmt, topLevel bool) {
	for _, st := range stmts {
		l.lowerStmt(st, topLevel)
	}
}

func (l *lowerer) lowerSubBlock(blk *ast.BlockStmt) *Body {
	if blk == nil {
		return nil
	}
	sub := &Body{
		AST:        blk,
		Block:      blk,
		ScopeStart: l.body.ScopeStart,
		ScopeEnd:   l.body.ScopeEnd,
		BodyStart:  blk.Pos(),
		BodyEnd:    blk.End(),
		Recv:       l.body.Recv,
		Params:     l.body.Params,
		ParamIndex: l.body.ParamIndex,
		Results:    l.body.Results,
		ResultSet:  l.body.ResultSet,
		FreeVars:   l.body.FreeVars,
	}
	subL := &lowerer{info: l.info, pkg: l.pkg, body: sub}
	subL.lowerStmtList(blk.List, false)
	return sub
}

func (l *lowerer) lowerStmt(stmt ast.Stmt, topLevel bool) {
	if stmt == nil {
		return
	}
	switch s := stmt.(type) {
	case *ast.EmptyStmt:
		return
	case *ast.LabeledStmt:
		// A labeled statement can be re-entered via goto, so it is not an
		// unconditional single-entry top-level statement.
		l.lowerStmt(s.Stmt, false)
	case *ast.BlockStmt:
		l.lowerStmtList(s.List, false)
	case *ast.DeclStmt:
		gd, ok := s.Decl.(*ast.GenDecl)
		if !ok {
			return
		}
		switch gd.Tok {
		case token.VAR:
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				dsts := make([]Place, len(vs.Names))
				defs := make([]bool, len(vs.Names))
				for i, name := range vs.Names {
					dsts[i] = l.lowerPlace(name)
					defs[i] = name != nil && name.Name != "_" && l.info.Defs[name] != nil
				}
				if len(vs.Values) == 0 {
					l.body.Ops = append(l.body.Ops, Op{
						Kind:           OpAssign,
						StmtAST:        vs,
						TopLevelInBody: topLevel,
						AssignKind:     AssignZeroDecl,
						Dsts:           dsts,
						DstDefs:        defs,
					})
					continue
				}
				srcs := l.lowerValues(vs.Values)
				kind := AssignPlain
				if len(dsts) > 1 && len(srcs) == 1 {
					kind = AssignMulti
				}
				l.body.Ops = append(l.body.Ops, Op{
					Kind:           OpAssign,
					StmtAST:        vs,
					TopLevelInBody: topLevel,
					AssignKind:     kind,
					Dsts:           dsts,
					DstDefs:        defs,
					Srcs:           srcs,
				})
			}
		case token.CONST:
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, val := range vs.Values {
					l.body.Ops = append(l.body.Ops, Op{
						Kind:    OpExpr,
						StmtAST: vs,
						Expr:    l.lowerValue(val),
					})
				}
			}
		}
	case *ast.ExprStmt:
		l.body.Ops = append(l.body.Ops, Op{
			Kind:           OpExpr,
			StmtAST:        s,
			TopLevelInBody: topLevel,
			Expr:           l.lowerValue(s.X),
		})
	case *ast.SendStmt:
		l.body.Ops = append(l.body.Ops, Op{
			Kind:           OpChanSend,
			StmtAST:        s,
			TopLevelInBody: topLevel,
			ChanPlace:      l.lowerPlace(s.Chan),
			ChanVal:        l.lowerValue(s.Chan),
			SendVal:        l.lowerValue(s.Value),
		})
	case *ast.IncDecStmt:
		l.body.Ops = append(l.body.Ops, Op{
			Kind:           OpAssign,
			StmtAST:        s,
			TopLevelInBody: topLevel,
			AssignKind:     AssignIncDec,
			Dsts:           []Place{l.lowerPlace(s.X)},
			DstDefs:        []bool{false},
			Srcs:           []*Value{l.lowerValue(s.X)},
		})
	case *ast.AssignStmt:
		isDef := s.Tok == token.DEFINE
		dsts := make([]Place, len(s.Lhs))
		defs := make([]bool, len(s.Lhs))
		for i, lhs := range s.Lhs {
			dsts[i] = l.lowerPlace(lhs)
			if isDef {
				if id, ok := syntaxutil.UnparenExpr(lhs).(*ast.Ident); ok && id.Name != "_" && l.info.Defs[id] != nil {
					defs[i] = true
				}
			}
		}
		if s.Tok != token.ASSIGN && s.Tok != token.DEFINE {
			// Compound assignment (`+=`, `|=`, etc.) reads and writes Lhs[0].
			var srcs []*Value
			if len(s.Lhs) == 1 && len(s.Rhs) == 1 {
				srcs = []*Value{{
					Kind: ValCompositeExpr,
					Type: l.info.TypeOf(s.Lhs[0]),
					Raw:  s.Rhs[0],
					Args: []*Value{l.lowerValue(s.Lhs[0]), l.lowerValue(s.Rhs[0])},
				}}
			} else {
				srcs = l.lowerValues(s.Rhs)
			}
			l.body.Ops = append(l.body.Ops, Op{
				Kind:           OpAssign,
				StmtAST:        s,
				TopLevelInBody: topLevel,
				AssignKind:     AssignCompound,
				Dsts:           dsts,
				DstDefs:        defs,
				Srcs:           srcs,
			})
			return
		}
		srcs := l.lowerValues(s.Rhs)
		kind := AssignPlain
		if len(dsts) > 1 && len(srcs) == 1 {
			kind = AssignMulti
		}
		l.body.Ops = append(l.body.Ops, Op{
			Kind:           OpAssign,
			StmtAST:        s,
			TopLevelInBody: topLevel,
			AssignKind:     kind,
			Dsts:           dsts,
			DstDefs:        defs,
			Srcs:           srcs,
		})
	case *ast.GoStmt:
		l.body.Ops = append(l.body.Ops, Op{
			Kind:           OpGo,
			StmtAST:        s,
			TopLevelInBody: topLevel,
			Call:           l.lowerValue(s.Call),
		})
	case *ast.DeferStmt:
		l.body.Ops = append(l.body.Ops, Op{
			Kind:           OpDefer,
			StmtAST:        s,
			TopLevelInBody: topLevel,
			Call:           l.lowerValue(s.Call),
		})
	case *ast.ReturnStmt:
		l.body.Ops = append(l.body.Ops, Op{
			Kind:           OpReturn,
			StmtAST:        s,
			TopLevelInBody: topLevel,
			Results:        l.lowerValues(s.Results),
			IsNaked:        len(s.Results) == 0 && len(l.body.Results) > 0,
		})
	case *ast.BranchStmt:
		l.body.Ops = append(l.body.Ops, Op{
			Kind:           OpBranch,
			StmtAST:        s,
			TopLevelInBody: topLevel,
		})
	case *ast.IfStmt:
		l.lowerStmt(s.Init, false)
		if s.Cond != nil {
			l.body.Ops = append(l.body.Ops, Op{
				Kind:    OpExpr,
				StmtAST: s,
				Expr:    l.lowerValue(s.Cond),
			})
		}
		if s.Body != nil {
			l.lowerStmtList(s.Body.List, false)
		}
		l.lowerStmt(s.Else, false)
	case *ast.SwitchStmt:
		l.lowerStmt(s.Init, false)
		if s.Tag != nil {
			l.body.Ops = append(l.body.Ops, Op{
				Kind:    OpExpr,
				StmtAST: s,
				Expr:    l.lowerValue(s.Tag),
			})
		}
		if s.Body != nil {
			for _, raw := range s.Body.List {
				cc, ok := raw.(*ast.CaseClause)
				if !ok {
					l.lowerStmt(raw, false)
					continue
				}
				for _, condExpr := range cc.List {
					l.body.Ops = append(l.body.Ops, Op{
						Kind:    OpExpr,
						StmtAST: cc,
						Expr:    l.lowerValue(condExpr),
					})
				}
				l.lowerStmtList(cc.Body, false)
			}
		}
	case *ast.TypeSwitchStmt:
		l.lowerStmt(s.Init, false)
		var switchedVal *Value
		var guardDefVar *types.Var
		switch guard := s.Assign.(type) {
		case *ast.ExprStmt:
			if ta, ok := syntaxutil.UnparenExpr(guard.X).(*ast.TypeAssertExpr); ok {
				switchedVal = l.lowerValue(ta.X)
			} else {
				switchedVal = l.lowerValue(guard.X)
			}
		case *ast.AssignStmt:
			if len(guard.Rhs) == 1 {
				if ta, ok := syntaxutil.UnparenExpr(guard.Rhs[0]).(*ast.TypeAssertExpr); ok {
					switchedVal = l.lowerValue(ta.X)
				} else {
					switchedVal = l.lowerValue(guard.Rhs[0])
				}
			}
			if len(guard.Lhs) == 1 {
				if id, ok := syntaxutil.UnparenExpr(guard.Lhs[0]).(*ast.Ident); ok && id.Name != "_" {
					guardDefVar, _ = l.info.Defs[id].(*types.Var)
				}
			}
		default:
			l.lowerStmt(s.Assign, false)
		}
		if switchedVal != nil {
			l.body.Ops = append(l.body.Ops, Op{
				Kind:      OpTypeSwitchBind,
				StmtAST:   s,
				SwitchDst: guardDefVar,
				SwitchSrc: switchedVal,
				SwitchAST: s,
			})
		}
		if s.Body != nil {
			for _, raw := range s.Body.List {
				cc, ok := raw.(*ast.CaseClause)
				if !ok {
					l.lowerStmt(raw, false)
					continue
				}
				if impVar, ok := l.info.Implicits[cc].(*types.Var); ok && impVar != nil && switchedVal != nil {
					l.body.Ops = append(l.body.Ops, Op{
						Kind:      OpTypeSwitchBind,
						StmtAST:   cc,
						SwitchDst: impVar,
						SwitchSrc: switchedVal,
						CaseAST:   cc,
						SwitchAST: s,
					})
				}
				l.lowerStmtList(cc.Body, false)
			}
		}
	case *ast.SelectStmt:
		if s.Body != nil {
			for _, raw := range s.Body.List {
				cc, ok := raw.(*ast.CommClause)
				if !ok {
					l.lowerStmt(raw, false)
					continue
				}
				l.lowerStmt(cc.Comm, false)
				l.lowerStmtList(cc.Body, false)
			}
		}
	case *ast.ForStmt:
		l.lowerStmt(s.Init, false)
		if s.Cond != nil {
			l.body.Ops = append(l.body.Ops, Op{
				Kind:    OpExpr,
				StmtAST: s,
				Expr:    l.lowerValue(s.Cond),
			})
		}
		l.lowerStmt(s.Post, false)
		if s.Body != nil {
			l.lowerStmtList(s.Body.List, false)
		}
	case *ast.RangeStmt:
		isDef := s.Tok == token.DEFINE
		var dsts []Place
		var defs []bool
		for _, bind := range []ast.Expr{s.Key, s.Value} {
			if bind == nil {
				continue
			}
			dsts = append(dsts, l.lowerPlace(bind))
			defHere := false
			if isDef {
				if id, ok := syntaxutil.UnparenExpr(bind).(*ast.Ident); ok && id.Name != "_" && l.info.Defs[id] != nil {
					defHere = true
				}
			}
			defs = append(defs, defHere)
		}
		rangeSrc := l.lowerValue(s.X)
		rangeBody := l.lowerSubBlock(s.Body)
		l.body.Ops = append(l.body.Ops, Op{
			Kind:           OpAssign,
			StmtAST:        s,
			TopLevelInBody: topLevel,
			AssignKind:     AssignRange,
			Dsts:           dsts,
			DstDefs:        defs,
			Srcs:           []*Value{rangeSrc},
			RangeBody:      rangeBody,
		})
	default:
		// Fail closed on unrecognized or malformed statement nodes (*ast.BadStmt).
		l.body.Ops = append(l.body.Ops, Op{
			Kind:           OpExpr,
			StmtAST:        s,
			TopLevelInBody: topLevel,
			Expr:           &Value{Kind: ValInvalid},
		})
	}
}

func (l *lowerer) lowerValues(exprs []ast.Expr) []*Value {
	if len(exprs) == 0 {
		return nil
	}
	out := make([]*Value, len(exprs))
	for i, e := range exprs {
		out[i] = l.lowerValue(e)
	}
	return out
}

func (l *lowerer) classifyVarRoot(v *types.Var) RootKind {
	if v == nil || v.IsField() || v.Pkg() == nil {
		return RootInvalid
	}
	if v.Parent() == v.Pkg().Scope() {
		return RootPkgGlobal
	}
	if v == l.body.Recv {
		return RootRecv
	}
	if _, ok := l.body.ParamIndex[v]; ok {
		return RootParam
	}
	if l.body.ResultSet[v] {
		return RootResult
	}
	if l.body.OwnsVar(v) {
		return RootLocal
	}
	l.recordFreeVar(v)
	return RootOuterVar
}

func (l *lowerer) tryLowerPlace(expr ast.Expr) (Place, bool) {
	if expr == nil {
		return Place{}, false
	}
	unp := syntaxutil.UnparenExpr(expr)
	switch e := unp.(type) {
	case *ast.Ident:
		if e.Name == "_" {
			return Place{
				Root: RootBlank,
				Type: l.info.TypeOf(expr),
				Raw:  expr,
			}, true
		}
		obj := syntaxutil.IdentDefOrUse(l.info, e)
		switch o := obj.(type) {
		case *types.Var:
			rk := l.classifyVarRoot(o)
			if rk == RootInvalid {
				return Place{}, false
			}
			return Place{
				Root: rk,
				Obj:  o,
				Type: l.info.TypeOf(expr),
				Raw:  expr,
			}, true
		case *types.Func:
			return Place{
				Root:    RootFunc,
				Func:    o,
				FuncPkg: pkgPathOf(o, l.pkg),
				Type:    l.info.TypeOf(expr),
				Raw:     expr,
			}, true
		case *types.Const, *types.Nil:
			return Place{
				Root:       RootConstOrNil,
				ConstOrNil: o,
				Type:       l.info.TypeOf(expr),
				Raw:        expr,
			}, true
		default:
			return Place{}, false
		}

	case *ast.SelectorExpr:
		if id, ok := syntaxutil.UnparenExpr(e.X).(*ast.Ident); ok {
			if _, isPkg := l.info.Uses[id].(*types.PkgName); isPkg {
				obj := l.info.Uses[e.Sel]
				switch o := obj.(type) {
				case *types.Var:
					return Place{
						Root: RootPkgGlobal,
						Obj:  o,
						Type: l.info.TypeOf(expr),
						Raw:  expr,
					}, true
				case *types.Func:
					return Place{
						Root:    RootFunc,
						Func:    o,
						FuncPkg: pkgPathOf(o, l.pkg),
						Type:    l.info.TypeOf(expr),
						Raw:     expr,
					}, true
				case *types.Const:
					return Place{
						Root:       RootConstOrNil,
						ConstOrNil: o,
						Type:       l.info.TypeOf(expr),
						Raw:        expr,
					}, true
				default:
					return Place{}, false
				}
			}
		}
		sel := l.info.Selections[e]
		if sel == nil {
			return Place{}, false
		}
		switch sel.Kind() {
		case types.FieldVal:
			fVar, _ := sel.Obj().(*types.Var)
			base := l.lowerPlace(e.X)
			base.Projs = append(base.Projs, Proj{
				Kind:      ProjField,
				Field:     fVar,
				Selection: sel,
				Indirect:  sel.Indirect(),
				BaseType:  l.info.TypeOf(e.X),
				Type:      l.info.TypeOf(e),
			})
			base.Type = l.info.TypeOf(expr)
			base.Raw = expr
			return base, true
		case types.MethodExpr:
			fn, _ := sel.Obj().(*types.Func)
			return Place{
				Root:         RootFunc,
				Func:         fn,
				FuncPkg:      pkgPathOf(fn, l.pkg),
				IsMethodExpr: true,
				Type:         l.info.TypeOf(expr),
				Raw:          expr,
			}, true
		default:
			return Place{}, false
		}

	case *ast.IndexExpr:
		if tv, ok := l.info.Types[syntaxutil.UnparenExpr(e.Index)]; ok && tv.IsType() {
			base, ok := l.tryLowerPlace(e.X)
			if !ok {
				return Place{}, false
			}
			base.Type = l.info.TypeOf(expr)
			base.Raw = expr
			return base, true
		}
		base := l.lowerPlace(e.X)
		base.Projs = append(base.Projs, Proj{
			Kind:     ProjIndex,
			Key:      l.lowerValue(e.Index),
			BaseType: l.info.TypeOf(e.X),
			Type:     l.info.TypeOf(e),
		})
		base.Type = l.info.TypeOf(expr)
		base.Raw = expr
		return base, true

	case *ast.IndexListExpr:
		base, ok := l.tryLowerPlace(e.X)
		if !ok {
			return Place{}, false
		}
		base.Type = l.info.TypeOf(expr)
		base.Raw = expr
		return base, true

	case *ast.SliceExpr:
		if typeMayBeValueArray(l.info.TypeOf(e.X)) {
			return Place{}, false
		}
		base := l.lowerPlace(e.X)
		var lowV, highV, maxV *Value
		if e.Low != nil {
			lowV = l.lowerValue(e.Low)
		}
		if e.High != nil {
			highV = l.lowerValue(e.High)
		}
		if e.Max != nil {
			maxV = l.lowerValue(e.Max)
		}
		base.Projs = append(base.Projs, Proj{
			Kind:     ProjSlice,
			Low:      lowV,
			High:     highV,
			Max:      maxV,
			BaseType: l.info.TypeOf(e.X),
			Type:     l.info.TypeOf(e),
		})
		base.Type = l.info.TypeOf(expr)
		base.Raw = expr
		return base, true

	case *ast.StarExpr:
		if tv, ok := l.info.Types[e]; ok && tv.IsType() {
			return Place{}, false
		}
		base := l.lowerPlace(e.X)
		base.Projs = append(base.Projs, Proj{
			Kind:     ProjDeref,
			BaseType: l.info.TypeOf(e.X),
			Type:     l.info.TypeOf(e),
		})
		base.Type = l.info.TypeOf(expr)
		base.Raw = expr
		return base, true
	}
	return Place{}, false
}

func (l *lowerer) lowerPlace(expr ast.Expr) Place {
	if p, ok := l.tryLowerPlace(expr); ok {
		return p
	}
	return Place{
		Root: RootTransient,
		Base: l.lowerValue(expr),
		Type: l.info.TypeOf(expr),
		Raw:  expr,
	}
}

func (l *lowerer) lowerValue(expr ast.Expr) *Value {
	if expr == nil {
		return nil
	}
	if tv, ok := l.info.Types[syntaxutil.UnparenExpr(expr)]; ok && tv.IsType() {
		return &Value{
			Kind: ValScalarLitOrConst,
			Type: tv.Type,
			Raw:  expr,
		}
	}
	unp := syntaxutil.UnparenExpr(expr)
	switch e := unp.(type) {
	case *ast.BasicLit:
		return &Value{
			Kind: ValScalarLitOrConst,
			Type: l.info.TypeOf(expr),
			Raw:  expr,
		}

	case *ast.FuncLit:
		child := LowerFuncLit(l.info, l.pkg, e)
		l.bubbleChildFreeVars(child)
		return &Value{
			Kind:    ValMakeClosure,
			Type:    l.info.TypeOf(expr),
			Raw:     expr,
			Lit:     e,
			Closure: child,
		}

	case *ast.CompositeLit:
		return l.lowerCompositeLit(e, expr)

	case *ast.UnaryExpr:
		switch e.Op {
		case token.AND:
			if comp, ok := syntaxutil.UnparenExpr(e.X).(*ast.CompositeLit); ok {
				return l.lowerCompositeLit(comp, expr)
			}
			return &Value{
				Kind:      ValAddrOf,
				Type:      l.info.TypeOf(expr),
				Raw:       expr,
				AddrPlace: l.lowerPlace(e.X),
			}
		case token.ARROW:
			return &Value{
				Kind: ValChanRecv,
				Type: l.info.TypeOf(expr),
				Raw:  expr,
				Chan: l.lowerValue(e.X),
			}
		default:
			return &Value{
				Kind: ValCompositeExpr,
				Type: l.info.TypeOf(expr),
				Raw:  expr,
				Args: []*Value{l.lowerValue(e.X)},
			}
		}

	case *ast.BinaryExpr:
		if e.Op == token.EQL || e.Op == token.NEQ {
			return &Value{
				Kind:      ValCompare,
				Type:      l.info.TypeOf(expr),
				Raw:       expr,
				CompareOp: e.Op,
				Left:      l.lowerValue(e.X),
				Right:     l.lowerValue(e.Y),
			}
		}
		return &Value{
			Kind: ValCompositeExpr,
			Type: l.info.TypeOf(expr),
			Raw:  expr,
			Args: []*Value{l.lowerValue(e.X), l.lowerValue(e.Y)},
		}

	case *ast.SliceExpr:
		if typeMayBeValueArray(l.info.TypeOf(e.X)) {
			var lowV, highV, maxV *Value
			if e.Low != nil {
				lowV = l.lowerValue(e.Low)
			}
			if e.High != nil {
				highV = l.lowerValue(e.High)
			}
			if e.Max != nil {
				maxV = l.lowerValue(e.Max)
			}
			return &Value{
				Kind:         ValAddrOf,
				Type:         l.info.TypeOf(expr),
				Raw:          expr,
				AddrPlace:    l.lowerPlace(e.X),
				IsArraySlice: true,
				Low:          lowV,
				High:         highV,
				Max:          maxV,
			}
		}

	case *ast.SelectorExpr:
		if sel := l.info.Selections[e]; sel != nil && sel.Kind() == types.MethodVal {
			fn, _ := sel.Obj().(*types.Func)
			rp, hasRP := l.tryLowerPlace(e.X)
			return &Value{
				Kind:         ValMethodVal,
				Type:         l.info.TypeOf(expr),
				Raw:          expr,
				Recv:         l.lowerValue(e.X),
				RecvPlace:    rp,
				HasRecvPlace: hasRP,
				Method:       fn,
				Selection:    sel,
				AutoAddr:     selectionImplicitlyAddressesRecv(l.info, e, sel),
			}
		}

	case *ast.TypeAssertExpr:
		return &Value{
			Kind:         ValConvert,
			Type:         l.info.TypeOf(expr),
			Raw:          expr,
			Arg:          l.lowerValue(e.X),
			IsTypeAssert: true,
		}

	case *ast.CallExpr:
		return l.lowerCall(e, expr)
	}

	if p, ok := l.tryLowerPlace(expr); ok {
		if p.Root == RootConstOrNil {
			return &Value{
				Kind: ValScalarLitOrConst,
				Type: l.info.TypeOf(expr),
				Raw:  expr,
			}
		}
		return &Value{
			Kind:  ValPlace,
			Type:  l.info.TypeOf(expr),
			Raw:   expr,
			Place: p,
		}
	}
	return &Value{
		Kind: ValInvalid,
		Type: l.info.TypeOf(expr),
		Raw:  expr,
	}
}

func (l *lowerer) lowerCompositeLit(lit *ast.CompositeLit, outerExpr ast.Expr) *Value {
	litT := l.info.TypeOf(lit)
	elemT := litT
	if ptr, ok := syntaxutil.UnderlyingType(elemT).(*types.Pointer); ok {
		elemT = ptr.Elem()
	}
	st, isStruct := syntaxutil.UnderlyingType(elemT).(*types.Struct)
	isMap := syntaxutil.TypeMayBeMap(elemT)

	elts := make([]CompositeElt, 0, len(lit.Elts))
	for i, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if isStruct {
				var fVar *types.Var
				if keyID, ok := kv.Key.(*ast.Ident); ok {
					fVar, _ = l.info.Uses[keyID].(*types.Var)
				}
				elts = append(elts, CompositeElt{
					Field: fVar,
					Value: l.lowerValue(kv.Value),
				})
			} else if isMap {
				elts = append(elts, CompositeElt{
					MapKey: l.lowerValue(kv.Key),
					Value:  l.lowerValue(kv.Value),
				})
			} else {
				elts = append(elts, CompositeElt{
					Index: l.lowerValue(kv.Key),
					Value: l.lowerValue(kv.Value),
				})
			}
			continue
		}
		var fVar *types.Var
		if isStruct && st != nil && i < st.NumFields() {
			fVar = st.Field(i)
		}
		elts = append(elts, CompositeElt{
			Field: fVar,
			Value: l.lowerValue(elt),
		})
	}
	return &Value{
		Kind:          ValAllocFresh,
		Type:          l.info.TypeOf(outerExpr),
		Raw:           outerExpr,
		AllocKind:     AllocCompositeLit,
		ElemType:      elemT,
		CompositeElts: elts,
	}
}

func (l *lowerer) lowerCall(call *ast.CallExpr, outerExpr ast.Expr) *Value {
	// 1. Type conversion `T(x)`
	if tv, ok := l.info.Types[syntaxutil.UnparenExpr(call.Fun)]; ok && tv.IsType() {
		if len(call.Args) == 1 && !call.Ellipsis.IsValid() {
			return &Value{
				Kind: ValConvert,
				Type: l.info.TypeOf(outerExpr),
				Raw:  outerExpr,
				Arg:  l.lowerValue(call.Args[0]),
			}
		}
		return &Value{
			Kind: ValInvalid,
			Type: l.info.TypeOf(outerExpr),
			Raw:  outerExpr,
		}
	}

	// 2. Builtin call
	if b := syntaxutil.LookupBuiltin(l.info, call.Fun); b != nil {
		switch b.Name() {
		case "make":
			var sizeArgs []*Value
			if len(call.Args) > 1 {
				sizeArgs = l.lowerValues(call.Args[1:])
			}
			return &Value{
				Kind:      ValAllocFresh,
				Type:      l.info.TypeOf(outerExpr),
				Raw:       outerExpr,
				AllocKind: AllocMake,
				Args:      sizeArgs,
			}
		case "new":
			if syntaxutil.IsBuiltinNewType(l.info, call) {
				return &Value{
					Kind:      ValAllocFresh,
					Type:      l.info.TypeOf(outerExpr),
					Raw:       outerExpr,
					AllocKind: AllocBuiltinNewType,
				}
			}
			return &Value{
				Kind:      ValAllocFresh,
				Type:      l.info.TypeOf(outerExpr),
				Raw:       outerExpr,
				AllocKind: AllocBuiltinNewExpr,
				Args:      l.lowerValues(call.Args),
				Ellipsis:  call.Ellipsis.IsValid(),
			}
		default:
			var valArgs []*Value
			for _, a := range call.Args {
				if tv, ok := l.info.Types[syntaxutil.UnparenExpr(a)]; ok && tv.IsType() {
					continue
				}
				valArgs = append(valArgs, l.lowerValue(a))
			}
			return &Value{
				Kind:        ValCall,
				Type:        l.info.TypeOf(outerExpr),
				Raw:         outerExpr,
				CallKind:    CallBuiltin,
				CallAST:     call,
				BuiltinName: b.Name(),
				Args:        valArgs,
				Ellipsis:    call.Ellipsis.IsValid(),
			}
		}
	}

	// 3. Direct IIFE `(func(...) { ... })(args...)`
	if lit, ok := syntaxutil.UnparenExpr(call.Fun).(*ast.FuncLit); ok {
		child := LowerFuncLit(l.info, l.pkg, lit)
		l.bubbleChildFreeVars(child)
		return &Value{
			Kind:      ValCall,
			Type:      l.info.TypeOf(outerExpr),
			Raw:       outerExpr,
			CallKind:  CallIIFE,
			CallAST:   call,
			CalleeSig: sigOf(l.info.TypeOf(lit)),
			IIFE:      child,
			Args:      l.lowerValues(call.Args),
			Ellipsis:  call.Ellipsis.IsValid(),
		}
	}

	// 4. Plain named function call (bare, package-qualified, or generic-instantiated)
	if fn, pkgPath, sig := l.resolvePlainCallee(call.Fun); fn != nil {
		return &Value{
			Kind:       ValCall,
			Type:       l.info.TypeOf(outerExpr),
			Raw:        outerExpr,
			CallKind:   CallPlain,
			CallAST:    call,
			CalleeFunc: fn,
			CalleePkg:  pkgPath,
			CalleeSig:  sig,
			Args:       l.lowerValues(call.Args),
			Ellipsis:   call.Ellipsis.IsValid(),
		}
	}

	// 5. Method call `x.M(args...)` or method-expression call `(*T).M(recv, args...)`
	if sel, ok := unwrapCalleeSelector(l.info, call.Fun); ok {
		if selection := l.info.Selections[sel]; selection != nil {
			switch selection.Kind() {
			case types.MethodVal:
				fn, _ := selection.Obj().(*types.Func)
				rp, hasRP := l.tryLowerPlace(sel.X)
				return &Value{
					Kind:         ValCall,
					Type:         l.info.TypeOf(outerExpr),
					Raw:          outerExpr,
					CallKind:     CallMethod,
					CallAST:      call,
					CalleeFunc:   fn,
					CalleePkg:    pkgPathOf(fn, l.pkg),
					CalleeSig:    sigOf(selection.Type()),
					Selection:    selection,
					AutoAddrRecv: selectionImplicitlyAddressesRecv(l.info, sel, selection),
					Recv:         l.lowerValue(sel.X),
					RecvPlace:    rp,
					HasRecvPlace: hasRP,
					Args:         l.lowerValues(call.Args),
					Ellipsis:     call.Ellipsis.IsValid(),
				}
			case types.MethodExpr:
				if len(call.Args) >= 1 {
					fn, _ := selection.Obj().(*types.Func)
					rp, hasRP := l.tryLowerPlace(call.Args[0])
					return &Value{
						Kind:             ValCall,
						Type:             l.info.TypeOf(outerExpr),
						Raw:              outerExpr,
						CallKind:         CallMethod,
						CallAST:          call,
						CalleeFunc:       fn,
						CalleePkg:        pkgPathOf(fn, l.pkg),
						CalleeSig:        stripMethodExprRecvParam(sigOf(selection.Type())),
						Selection:        selection,
						IsMethodExprCall: true,
						Recv:             l.lowerValue(call.Args[0]),
						RecvPlace:        rp,
						HasRecvPlace:     hasRP,
						Args:             l.lowerValues(call.Args[1:]),
						Ellipsis:         call.Ellipsis.IsValid(),
					}
				}
			}
		}
	}

	// 6. Indirect call (func var, signature struct field, dispatch-map index, etc.)
	return &Value{
		Kind:      ValCall,
		Type:      l.info.TypeOf(outerExpr),
		Raw:       outerExpr,
		CallKind:  CallIndirect,
		CallAST:   call,
		Callee:    l.lowerValue(call.Fun),
		CalleeSig: sigOf(l.info.TypeOf(call.Fun)),
		Args:      l.lowerValues(call.Args),
		Ellipsis:  call.Ellipsis.IsValid(),
	}
}

func (l *lowerer) resolvePlainCallee(fun ast.Expr) (*types.Func, string, *types.Signature) {
	instSig := sigOf(l.info.TypeOf(syntaxutil.UnparenExpr(fun)))
	cur := syntaxutil.UnparenExpr(fun)
	for {
		switch x := cur.(type) {
		case *ast.IndexListExpr:
			cur = syntaxutil.UnparenExpr(x.X)
		case *ast.IndexExpr:
			if tv, ok := l.info.Types[syntaxutil.UnparenExpr(x.Index)]; ok && tv.IsType() {
				cur = syntaxutil.UnparenExpr(x.X)
				continue
			}
			return nil, "", nil
		default:
			goto unwrapped
		}
	}
unwrapped:
	switch x := cur.(type) {
	case *ast.Ident:
		fn, ok := l.info.Uses[x].(*types.Func)
		if !ok || fn == nil {
			return nil, "", nil
		}
		fnSig := sigOf(fn.Type())
		if fnSig == nil || fnSig.Recv() != nil {
			return nil, "", nil
		}
		if instSig == nil {
			instSig = fnSig
		}
		return fn, pkgPathOf(fn, l.pkg), instSig
	case *ast.SelectorExpr:
		id, ok := syntaxutil.UnparenExpr(x.X).(*ast.Ident)
		if !ok {
			return nil, "", nil
		}
		if _, isPkg := l.info.Uses[id].(*types.PkgName); !isPkg {
			return nil, "", nil
		}
		fn, ok := l.info.Uses[x.Sel].(*types.Func)
		if !ok || fn == nil {
			return nil, "", nil
		}
		fnSig := sigOf(fn.Type())
		if fnSig == nil || fnSig.Recv() != nil {
			return nil, "", nil
		}
		if instSig == nil {
			instSig = fnSig
		}
		return fn, pkgPathOf(fn, l.pkg), instSig
	default:
		return nil, "", nil
	}
}

func unwrapCalleeSelector(info *types.Info, fun ast.Expr) (*ast.SelectorExpr, bool) {
	cur := syntaxutil.UnparenExpr(fun)
	for {
		switch x := cur.(type) {
		case *ast.IndexListExpr:
			cur = syntaxutil.UnparenExpr(x.X)
		case *ast.IndexExpr:
			if tv, ok := info.Types[syntaxutil.UnparenExpr(x.Index)]; ok && tv.IsType() {
				cur = syntaxutil.UnparenExpr(x.X)
				continue
			}
			return nil, false
		case *ast.SelectorExpr:
			return x, true
		default:
			return nil, false
		}
	}
}

func selectionImplicitlyAddressesRecv(info *types.Info, sel *ast.SelectorExpr, selection *types.Selection) bool {
	if info == nil || sel == nil || selection == nil {
		return false
	}
	fn, ok := selection.Obj().(*types.Func)
	if !ok || fn == nil {
		return false
	}
	sig := sigOf(fn.Type())
	if sig == nil || sig.Recv() == nil {
		return false
	}
	if _, wantsPtr := syntaxutil.UnderlyingType(sig.Recv().Type()).(*types.Pointer); !wantsPtr {
		return false
	}
	curT := info.TypeOf(sel.X)
	if curT == nil {
		return true
	}
	if _, isPtr := syntaxutil.UnderlyingType(curT).(*types.Pointer); isPtr {
		return false
	}
	idx := selection.Index()
	for k := 0; k < len(idx)-1; k++ {
		st, ok := syntaxutil.UnderlyingType(curT).(*types.Struct)
		if !ok || idx[k] < 0 || idx[k] >= st.NumFields() {
			return true
		}
		curT = st.Field(idx[k]).Type()
		if _, isPtr := syntaxutil.UnderlyingType(curT).(*types.Pointer); isPtr {
			return false
		}
	}
	return true
}

func stripMethodExprRecvParam(sig *types.Signature) *types.Signature {
	if sig == nil || sig.Params() == nil || sig.Params().Len() == 0 {
		return sig
	}
	n := sig.Params().Len()
	vars := make([]*types.Var, n-1)
	for i := 1; i < n; i++ {
		vars[i-1] = sig.Params().At(i)
	}
	return types.NewSignatureType(nil, nil, nil, types.NewTuple(vars...), sig.Results(), sig.Variadic())
}

func typeMayBeValueArray(t types.Type) bool {
	if t == nil {
		return false
	}
	u := types.Unalias(t)
	if tp, ok := u.(*types.TypeParam); ok {
		iface, ok := tp.Underlying().(*types.Interface)
		if !ok {
			return false
		}
		return ifaceAdmitsArray(iface, make(map[*types.Interface]bool))
	}
	_, isArr := u.Underlying().(*types.Array)
	return isArr
}

func ifaceAdmitsArray(iface *types.Interface, seen map[*types.Interface]bool) bool {
	if iface == nil || seen[iface] {
		return false
	}
	seen[iface] = true
	for i := 0; i < iface.NumEmbeddeds(); i++ {
		switch emb := types.Unalias(iface.EmbeddedType(i)).(type) {
		case *types.Union:
			for j := 0; j < emb.Len(); j++ {
				if _, isArr := syntaxutil.UnderlyingType(emb.Term(j).Type()).(*types.Array); isArr {
					return true
				}
			}
		case *types.Interface:
			if ifaceAdmitsArray(emb, seen) {
				return true
			}
		default:
			if _, isArr := syntaxutil.UnderlyingType(emb).(*types.Array); isArr {
				return true
			}
		}
	}
	return false
}

func sigOf(t types.Type) *types.Signature {
	if t == nil {
		return nil
	}
	sig, _ := syntaxutil.UnderlyingType(t).(*types.Signature)
	return sig
}

func pkgPathOf(fn *types.Func, fallback *types.Package) string {
	if fn != nil && fn.Pkg() != nil {
		return fn.Pkg().Path()
	}
	if fallback != nil {
		return fallback.Path()
	}
	return ""
}
