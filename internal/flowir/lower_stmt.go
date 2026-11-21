package flowir

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// LowerFunc lowers a function or method declaration into a canonical Body.
func LowerFunc(info *types.Info, pkg *types.Package, fd *ast.FuncDecl) *Body {
	if info == nil || fd == nil || fd.Body == nil {
		return nil
	}
	b := newBody(fd, fd.Body, fd.Pos(), fd.End())
	l := &lowerer{info: info, pkg: pkg, body: b}
	if fd.Recv != nil {
		l.scanTypeExprNestedHazards(fd.Recv)
		if len(fd.Recv.List) == 1 {
			if names := fd.Recv.List[0].Names; len(names) == 1 && names[0] != nil && names[0].Name != "_" {
				if v, ok := info.Defs[names[0]].(*types.Var); ok {
					b.Recv = v
				}
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
// *ast.GenDecl, *ast.ValueSpec, *ast.BlockStmt, or statement/expression subtree)
// into a canonical Body.
func LowerNode(info *types.Info, pkg *types.Package, node ast.Node) *Body {
	if info == nil || node == nil {
		return nil
	}
	switch n := node.(type) {
	case *ast.FuncDecl:
		return LowerFunc(info, pkg, n)
	case *ast.FuncLit:
		return LowerFuncLit(info, pkg, n)
	case *ast.GenDecl:
		b := newBody(n, nil, n.Pos(), n.End())
		l := &lowerer{info: info, pkg: pkg, body: b}
		l.lowerGenDecl(n, true)
		return b
	case *ast.ValueSpec:
		b := newBody(n, nil, n.Pos(), n.End())
		l := &lowerer{info: info, pkg: pkg, body: b}
		tok := token.VAR
		for _, nm := range n.Names {
			if nm != nil && info.Defs[nm] != nil {
				if _, isConst := info.Defs[nm].(*types.Const); isConst {
					tok = token.CONST
				}
				break
			}
		}
		l.lowerValueSpec(n, tok, true)
		return b
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
	l.scanTypeExprNestedHazards(ft)
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
			var ftType types.Type
			if field.Type != nil {
				ftType = l.info.TypeOf(field.Type)
			}
			if len(field.Names) == 0 {
				l.body.Results = append(l.body.Results, nil)
				l.body.ResultTypes = append(l.body.ResultTypes, ftType)
				continue
			}
			for _, name := range field.Names {
				var v *types.Var
				if name != nil && name.Name != "_" {
					v, _ = l.info.Defs[name].(*types.Var)
				}
				resType := ftType
				if v != nil && v.Type() != nil {
					resType = v.Type()
				}
				l.body.Results = append(l.body.Results, v)
				l.body.ResultTypes = append(l.body.ResultTypes, resType)
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

func (l *lowerer) bubbleChild(child *Body) {
	if child == nil {
		return
	}
	for v := range child.FreeVars {
		l.recordFreeVar(v)
	}
	if child.HasGoto || child.HasNestedGoto {
		l.body.HasNestedGoto = true
	}
	if child.HasGo || child.HasNestedGo {
		l.body.HasNestedGo = true
	}
}

func (l *lowerer) scanTypeExprNestedHazards(root ast.Node) {
	if (l.body.HasNestedGoto && l.body.HasNestedGo) || root == nil {
		return
	}
	ast.Inspect(root, func(n ast.Node) bool {
		if (l.body.HasNestedGoto && l.body.HasNestedGo) || n == nil {
			return false
		}
		if lit, isFL := n.(*ast.FuncLit); isFL {
			ast.Inspect(lit, func(sub ast.Node) bool {
				if (l.body.HasNestedGoto && l.body.HasNestedGo) || sub == nil {
					return false
				}
				switch x := sub.(type) {
				case *ast.BranchStmt:
					if x.Tok == token.GOTO {
						l.body.HasNestedGoto = true
					}
				case *ast.GoStmt:
					l.body.HasNestedGo = true
				}
				return true
			})
			return false
		}
		return true
	})
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
		AST:         blk,
		Block:       blk,
		ScopeStart:  l.body.ScopeStart,
		ScopeEnd:    l.body.ScopeEnd,
		BodyStart:   blk.Pos(),
		BodyEnd:     blk.End(),
		Recv:        l.body.Recv,
		Params:      l.body.Params,
		ParamIndex:  l.body.ParamIndex,
		Results:     l.body.Results,
		ResultTypes: l.body.ResultTypes,
		ResultSet:   l.body.ResultSet,
		FreeVars:    l.body.FreeVars,
	}
	subL := &lowerer{info: l.info, pkg: l.pkg, body: sub}
	subL.lowerStmtList(blk.List, false)
	if sub.HasGoto {
		l.body.HasGoto = true
	}
	if sub.HasNestedGoto {
		l.body.HasNestedGoto = true
	}
	if sub.HasLabel {
		l.body.HasLabel = true
	}
	if sub.HasFallthrough {
		l.body.HasFallthrough = true
	}
	if sub.HasLabeledBranch {
		l.body.HasLabeledBranch = true
	}
	if sub.HasDefer {
		l.body.HasDefer = true
	}
	if sub.HasGo {
		l.body.HasGo = true
	}
	if sub.HasNestedGo {
		l.body.HasNestedGo = true
	}
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
		l.body.HasLabel = true
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
		l.lowerGenDecl(gd, topLevel)
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
					Raw:  nil,
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
		l.body.HasGo = true
		l.body.Ops = append(l.body.Ops, Op{
			Kind:           OpGo,
			StmtAST:        s,
			TopLevelInBody: topLevel,
			Call:           l.lowerValue(s.Call),
		})
	case *ast.DeferStmt:
		l.body.HasDefer = true
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
		switch s.Tok {
		case token.GOTO:
			l.body.HasGoto = true
		case token.FALLTHROUGH:
			l.body.HasFallthrough = true
		}
		if s.Label != nil {
			l.body.HasLabeledBranch = true
		}
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
				for _, ce := range cc.List {
					l.scanTypeExprNestedHazards(ce)
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

func (l *lowerer) lowerGenDecl(gd *ast.GenDecl, topLevel bool) {
	if gd == nil {
		return
	}
	if gd.Tok == token.TYPE {
		l.scanTypeExprNestedHazards(gd)
		return
	}
	if gd.Tok != token.VAR && gd.Tok != token.CONST {
		return
	}
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		l.lowerValueSpec(vs, gd.Tok, topLevel)
	}
}

func (l *lowerer) lowerValueSpec(vs *ast.ValueSpec, tok token.Token, topLevel bool) {
	if vs == nil {
		return
	}
	if vs.Type != nil {
		l.scanTypeExprNestedHazards(vs.Type)
	}
	switch tok {
	case token.VAR:
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
			return
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
	case token.CONST:
		for _, val := range vs.Values {
			l.body.Ops = append(l.body.Ops, Op{
				Kind:           OpExpr,
				StmtAST:        vs,
				TopLevelInBody: topLevel,
				Expr:           l.lowerValue(val),
			})
		}
	}
}
