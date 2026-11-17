package toolchain

import (
	"go/ast"
	"go/token"
	"maps"
	"slices"
)

// WalkLexicalAST traverses node with Go's block-scoped lexical bindings,
// invoking recIdent on unshadowed identifier references, recSel on field/method
// selector names over shadowed or compound bases, and recQual on unshadowed
// `base.sel` qualified references.
func WalkLexicalAST(node ast.Node, scope map[string]bool, recIdent, recSel func(string), recQual func(base, sel string)) {
	WalkLexicalASTSkippingIdents(node, scope, nil, recIdent, recSel, recQual)
}

// WalkLexicalASTSkippingIdents behaves like WalkLexicalAST while skipping
// pre-verified struct-literal field-key identifiers in skipIdents.
func WalkLexicalASTSkippingIdents(node ast.Node, scope map[string]bool, skipIdents map[*ast.Ident]bool, recIdent, recSel func(string), recQual func(base, sel string)) {
	walk := func(subNode ast.Node, subScope map[string]bool) {
		WalkLexicalASTSkippingIdents(subNode, subScope, skipIdents, recIdent, recSel, recQual)
	}
	if node == nil {
		return
	}
	switch n := node.(type) {
	case *ast.BlockStmt:
		sub := maps.Clone(scope)
		for _, st := range n.List {
			walk(st, sub)
		}
	case *ast.IfStmt:
		sub := maps.Clone(scope)
		if n.Init != nil {
			walk(n.Init, sub)
		}
		walk(n.Cond, sub)
		walk(n.Body, sub)
		if n.Else != nil {
			walk(n.Else, sub)
		}
	case *ast.ForStmt:
		sub := maps.Clone(scope)
		if n.Init != nil {
			walk(n.Init, sub)
		}
		if n.Cond != nil {
			walk(n.Cond, sub)
		}
		if n.Post != nil {
			walk(n.Post, sub)
		}
		walk(n.Body, sub)
	case *ast.RangeStmt:
		walk(n.X, scope)
		sub := maps.Clone(scope)
		if n.Tok == token.DEFINE {
			for _, e := range []ast.Expr{n.Key, n.Value} {
				if id, ok := unwrapParens(e).(*ast.Ident); ok && id.Name != "_" && id.Name != "" {
					sub[id.Name] = true
				}
			}
		} else {
			if n.Key != nil {
				walk(n.Key, sub)
			}
			if n.Value != nil {
				walk(n.Value, sub)
			}
		}
		walk(n.Body, sub)
	case *ast.SwitchStmt:
		sub := maps.Clone(scope)
		if n.Init != nil {
			walk(n.Init, sub)
		}
		if n.Tag != nil {
			walk(n.Tag, sub)
		}
		if n.Body != nil {
			for _, st := range n.Body.List {
				walk(st, maps.Clone(sub))
			}
		}
	case *ast.TypeSwitchStmt:
		sub := maps.Clone(scope)
		if n.Init != nil {
			walk(n.Init, sub)
		}
		if as, ok := n.Assign.(*ast.AssignStmt); ok && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			walk(as.Rhs[0], sub)
			if id, okID := unwrapParens(as.Lhs[0]).(*ast.Ident); okID && id.Name != "_" && id.Name != "" {
				sub[id.Name] = true
			}
		} else if n.Assign != nil {
			walk(n.Assign, sub)
		}
		if n.Body != nil {
			for _, st := range n.Body.List {
				walk(st, maps.Clone(sub))
			}
		}
	case *ast.SelectStmt:
		if n.Body != nil {
			for _, st := range n.Body.List {
				walk(st, maps.Clone(scope))
			}
		}
	case *ast.CaseClause:
		for _, e := range n.List {
			walk(e, scope)
		}
		sub := maps.Clone(scope)
		for _, st := range n.Body {
			walk(st, sub)
		}
	case *ast.CommClause:
		sub := maps.Clone(scope)
		if n.Comm != nil {
			walk(n.Comm, sub)
		}
		for _, st := range n.Body {
			walk(st, sub)
		}
	case *ast.AssignStmt:
		for _, rhs := range n.Rhs {
			walk(rhs, scope)
		}
		if n.Tok == token.DEFINE {
			for _, lhs := range n.Lhs {
				if id, ok := unwrapParens(lhs).(*ast.Ident); ok {
					if id.Name != "_" && id.Name != "" {
						scope[id.Name] = true
					}
				} else {
					walk(lhs, scope)
				}
			}
		} else {
			for _, lhs := range n.Lhs {
				walk(lhs, scope)
			}
		}
	case *ast.DeclStmt:
		if gd, ok := n.Decl.(*ast.GenDecl); ok {
			for _, spec := range gd.Specs {
				switch sp := spec.(type) {
				case *ast.ValueSpec:
					if sp.Type != nil {
						walk(sp.Type, scope)
					}
					for _, v := range sp.Values {
						walk(v, scope)
					}
					for _, id := range sp.Names {
						if id.Name != "_" && id.Name != "" {
							scope[id.Name] = true
						}
					}
				case *ast.TypeSpec:
					if sp.Name != nil && sp.Name.Name != "_" && sp.Name.Name != "" {
						scope[sp.Name.Name] = true
					}
					sub := maps.Clone(scope)
					if sp.TypeParams != nil {
						for _, fld := range sp.TypeParams.List {
							for _, id := range fld.Names {
								if id.Name != "_" && id.Name != "" {
									sub[id.Name] = true
								}
							}
						}
					}
					walk(sp.Type, sub)
				}
			}
		}
	case *ast.FuncLit:
		sub := maps.Clone(scope)
		if n.Type != nil {
			for _, fl := range []*ast.FieldList{n.Type.Params, n.Type.Results} {
				if fl != nil {
					for _, fld := range fl.List {
						if fld.Type != nil {
							walk(fld.Type, scope)
						}
						for _, id := range fld.Names {
							if id.Name != "_" && id.Name != "" {
								sub[id.Name] = true
							}
						}
					}
				}
			}
		}
		if n.Body != nil {
			walk(n.Body, sub)
		}
	case *ast.Ident:
		if n.Name != "_" && !skipIdents[n] && !scope[n.Name] && recIdent != nil {
			recIdent(n.Name)
		}
	case *ast.SelectorExpr:
		if xID, ok := unwrapParens(n.X).(*ast.Ident); ok {
			if !scope[xID.Name] {
				if n.Sel != nil {
					if recQual != nil {
						recQual(xID.Name, n.Sel.Name)
					}
				} else if recIdent != nil {
					recIdent(xID.Name)
				}
				return
			}
		} else {
			walk(n.X, scope)
		}
		if n.Sel != nil && recSel != nil {
			recSel(n.Sel.Name)
		}
	case *ast.StructType:
		if n.Fields != nil {
			for _, fld := range n.Fields.List {
				if fld.Type != nil {
					walk(fld.Type, scope)
				}
			}
		}
	case *ast.InterfaceType:
		if n.Methods != nil {
			for _, m := range n.Methods.List {
				if m.Type != nil {
					walk(m.Type, scope)
				}
			}
		}
	case *ast.FuncType:
		for _, fl := range []*ast.FieldList{n.TypeParams, n.Params, n.Results} {
			if fl != nil {
				for _, fld := range fl.List {
					if fld.Type != nil {
						walk(fld.Type, scope)
					}
				}
			}
		}
	case *ast.LabeledStmt:
		walk(n.Stmt, scope)
	case *ast.BranchStmt:
		// Label ident is not a value/decl reference.
	default:
		ast.Inspect(node, func(ch ast.Node) bool {
			if ch == nil || ch == node {
				return true
			}
			walk(ch, scope)
			return false
		})
	}
}

func walkOffSurfaceAST(node ast.Node, scope map[string]bool, recIdent, recSel func(string), recQual func(base, sel string)) {
	WalkLexicalAST(node, scope, recIdent, recSel, recQual)
}

// walkNonSelIdents visits all non-SelectorExpr.Sel identifiers in root; when
// skipStructAndKeyLabels is true, composite-literal keys and struct/interface
// field/method names are also skipped.
func walkNonSelIdents(root ast.Node, skipStructAndKeyLabels bool, fn func(*ast.Ident) bool) bool {
	stopped := false
	var inspect func(n ast.Node) bool
	inspect = func(n ast.Node) bool {
		if stopped || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.SelectorExpr:
			ast.Inspect(node.X, inspect)
			return false
		case *ast.KeyValueExpr:
			if skipStructAndKeyLabels {
				ast.Inspect(node.Value, inspect)
				return false
			}
			return true
		case *ast.StructType:
			if skipStructAndKeyLabels {
				if node.Fields != nil {
					for _, field := range node.Fields.List {
						ast.Inspect(field.Type, inspect)
					}
				}
				return false
			}
			return true
		case *ast.InterfaceType:
			if skipStructAndKeyLabels {
				if node.Methods != nil {
					for _, field := range node.Methods.List {
						ast.Inspect(field.Type, inspect)
					}
				}
				return false
			}
			return true
		case *ast.Ident:
			if !fn(node) {
				stopped = true
			}
			return false
		default:
			return true
		}
	}
	ast.Inspect(root, inspect)
	return !stopped
}

func allNonSelPropIdentsIn(files []*ast.File, name string, allowed map[*ast.Ident]bool) bool {
	return allNonSelPropIdentsInSet(files, map[string]struct{}{name: {}}, allowed)
}

func allNonSelPropIdentsInSet[V any](files []*ast.File, names map[string]V, allowed map[*ast.Ident]bool) bool {
	if len(names) == 0 {
		return true
	}
	for _, f := range files {
		ok := walkNonSelIdents(f, false, func(id *ast.Ident) bool {
			if _, match := names[id.Name]; match && !allowed[id] {
				return false
			}
			return true
		})
		if !ok {
			return false
		}
	}
	return true
}

func filterNonSelPropIdentsInSet(files []*ast.File, allowedByName map[string]map[*ast.Ident]bool) map[string]bool {
	leaked := map[string]bool{}
	if len(allowedByName) == 0 {
		return leaked
	}
	for _, f := range files {
		walkNonSelIdents(f, false, func(id *ast.Ident) bool {
			if allowed, match := allowedByName[id.Name]; match && !allowed[id] {
				leaked[id.Name] = true
			}
			return true
		})
	}
	return leaked
}

func walkNonSelectorPropIdents(root ast.Node, fn func(*ast.Ident)) {
	walkNonSelIdents(root, true, func(id *ast.Ident) bool {
		fn(id)
		return true
	})
}

func allNonSelectorPropIdentsIn(files []*ast.File, allowedByName map[string]map[*ast.Ident]bool) bool {
	if len(allowedByName) == 0 {
		return true
	}
	for _, f := range files {
		ok := walkNonSelIdents(f, true, func(id *ast.Ident) bool {
			if allowed, match := allowedByName[id.Name]; match && !allowed[id] {
				return false
			}
			return true
		})
		if !ok {
			return false
		}
	}
	return true
}

func exprReferencesAnyIdent(expr ast.Node, names map[string]bool) bool {
	if expr == nil || len(names) == 0 {
		return false
	}
	return !walkNonSelIdents(expr, true, func(id *ast.Ident) bool {
		return !names[id.Name]
	})
}

func exprRefsIdentOutsideLen(expr ast.Expr, names map[string]bool) bool {
	if expr == nil || len(names) == 0 {
		return false
	}
	found := false
	var walk func(n ast.Node)
	walk = func(n ast.Node) {
		if found || n == nil {
			return
		}
		if call, isCall := n.(*ast.CallExpr); isCall && isOneArgLenIdentCall(call) {
			return
		}
		switch node := n.(type) {
		case *ast.SelectorExpr:
			walk(node.X)
		case *ast.KeyValueExpr:
			walk(node.Value)
		case *ast.Ident:
			if names[node.Name] {
				found = true
			}
		default:
			ast.Inspect(node, func(ch ast.Node) bool {
				if ch == node {
					return true
				}
				walk(ch)
				return false
			})
		}
	}
	walk(expr)
	return found
}

func nodeMutatesOrTakesAddrWhere(root ast.Node, match func(ast.Expr) bool) bool {
	if root == nil {
		return false
	}
	bad := false
	ast.Inspect(root, func(n ast.Node) bool {
		if bad || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if match(lhs) {
					bad = true
					return false
				}
			}
		case *ast.RangeStmt:
			if (node.Key != nil && match(node.Key)) || (node.Value != nil && match(node.Value)) {
				bad = true
				return false
			}
		case *ast.IncDecStmt:
			if match(node.X) {
				bad = true
				return false
			}
		case *ast.UnaryExpr:
			if node.Op == token.AND && match(node.X) {
				bad = true
				return false
			}
		}
		return true
	})
	return bad
}

func bodyMutatesOrTakesAddrOfAny(body *ast.BlockStmt, protected map[string]bool) bool {
	if body == nil || len(protected) == 0 {
		return false
	}
	return nodeMutatesOrTakesAddrWhere(body, func(expr ast.Expr) bool {
		id, ok := unwrapParens(expr).(*ast.Ident)
		return ok && protected[id.Name]
	})
}

func nodeMutatesOrTakesAddrOfSelector(root ast.Node, baseIdent string, fields map[string]bool) bool {
	if root == nil || len(fields) == 0 {
		return false
	}
	return nodeMutatesOrTakesAddrWhere(root, func(expr ast.Expr) bool {
		sel, ok := unwrapParens(expr).(*ast.SelectorExpr)
		if !ok || !fields[sel.Sel.Name] {
			return false
		}
		if baseIdent == "" {
			return true
		}
		id, ok := unwrapParens(sel.X).(*ast.Ident)
		return ok && id.Name == baseIdent
	})
}

func blockOnlySelectsOnIdent(body *ast.BlockStmt, ident string) bool {
	if body == nil || ident == "" {
		return true
	}
	if bodyDeclaresAnyIdent(body, map[string]bool{ident: true}) {
		return false
	}
	escaped := false
	var walk func(n ast.Node)
	walk = func(n ast.Node) {
		if escaped || n == nil {
			return
		}
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := unwrapParens(node.X).(*ast.Ident); ok && id.Name == ident {
				return
			}
			walk(node.X)
		case *ast.Ident:
			if node.Name == ident {
				escaped = true
			}
		default:
			ast.Inspect(node, func(ch ast.Node) bool {
				if ch == node {
					return true
				}
				walk(ch)
				return false
			})
		}
	}
	walk(body)
	return !escaped
}

func bodyDeclaresAnyIdent(body *ast.BlockStmt, names map[string]bool) bool {
	if body == nil || len(names) == 0 {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.ValueSpec:
			for _, id := range node.Names {
				if names[id.Name] {
					found = true
					return false
				}
			}
		case *ast.TypeSpec:
			if node.Name != nil && names[node.Name.Name] {
				found = true
				return false
			}
			if node.TypeParams != nil {
				for _, f := range node.TypeParams.List {
					for _, id := range f.Names {
						if names[id.Name] {
							found = true
							return false
						}
					}
				}
			}
		case *ast.FuncLit:
			if node.Type != nil {
				for _, fl := range []*ast.FieldList{node.Type.Params, node.Type.Results} {
					if fl == nil {
						continue
					}
					for _, f := range fl.List {
						for _, id := range f.Names {
							if names[id.Name] {
								found = true
								return false
							}
						}
					}
				}
			}
		case *ast.AssignStmt:
			if node.Tok == token.DEFINE {
				for _, lhs := range node.Lhs {
					if id, ok := unwrapParens(lhs).(*ast.Ident); ok && names[id.Name] {
						found = true
						return false
					}
				}
			}
		case *ast.RangeStmt:
			if node.Tok == token.DEFINE {
				if id, ok := unwrapParens(node.Key).(*ast.Ident); ok && names[id.Name] {
					found = true
					return false
				}
				if id, ok := unwrapParens(node.Value).(*ast.Ident); ok && names[id.Name] {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

func funcDeclaresParamOrResult(fn *ast.FuncDecl, name string) bool {
	if fn == nil || name == "" {
		return false
	}
	return funcDeclaresAnyParamOrResult(fn, map[string]bool{name: true})
}

func funcDeclaresAnyParamOrResult(fn *ast.FuncDecl, names map[string]bool) bool {
	if fn == nil || len(names) == 0 {
		return false
	}
	if recv := recvVarName(fn); recv != "" && names[recv] {
		return true
	}
	if fn.Type != nil {
		for _, fl := range []*ast.FieldList{fn.Type.TypeParams, fn.Type.Params, fn.Type.Results} {
			if fl == nil {
				continue
			}
			for _, f := range fl.List {
				for _, id := range f.Names {
					if names[id.Name] {
						return true
					}
				}
			}
		}
	}
	return false
}

func funcShadowsAnyIdent(fn *ast.FuncDecl, names map[string]bool) bool {
	if fn == nil || len(names) == 0 {
		return false
	}
	return funcDeclaresAnyParamOrResult(fn, names) || bodyDeclaresAnyIdent(fn.Body, names)
}

func funcLitShadowsAnyIdent(fl *ast.FuncLit, names map[string]bool) bool {
	if fl == nil || len(names) == 0 {
		return false
	}
	if fl.Type != nil {
		for _, flist := range []*ast.FieldList{fl.Type.Params, fl.Type.Results} {
			if flist == nil {
				continue
			}
			for _, f := range flist.List {
				for _, id := range f.Names {
					if names[id.Name] {
						return true
					}
				}
			}
		}
	}
	return bodyDeclaresAnyIdent(fl.Body, names)
}

func declOrBodyShadowsIdent(f *ast.File, fn *ast.FuncDecl, ident string) bool {
	if f != nil {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.Name == ident {
					return true
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if n.Name == ident {
								return true
							}
						}
					case *ast.TypeSpec:
						if s.Name.Name == ident {
							return true
						}
					}
				}
			}
		}
	}
	if fn == nil {
		return false
	}
	return funcShadowsAnyIdent(fn, map[string]bool{ident: true})
}

func bodyHasControlFlowOrRecoverBypass(body *ast.BlockStmt) bool {
	return body != nil && stmtHasControlFlowOrRecoverBypass(body)
}

func stmtHasControlFlowOrRecoverBypass(root ast.Node) bool {
	if root == nil {
		return false
	}
	bad := false
	ast.Inspect(root, func(n ast.Node) bool {
		if bad || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.LabeledStmt:
			bad = true
			return false
		case *ast.BranchStmt:
			if node.Tok == token.GOTO || node.Tok == token.FALLTHROUGH || node.Label != nil {
				bad = true
				return false
			}
		case *ast.CallExpr:
			if id, ok := unwrapParens(node.Fun).(*ast.Ident); ok && id.Name == "recover" {
				bad = true
				return false
			}
		}
		return true
	})
	return bad
}

func blockAlwaysReturns(stmts []ast.Stmt) bool {
	if len(stmts) == 0 {
		return false
	}
	switch last := stmts[len(stmts)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BlockStmt:
		return blockAlwaysReturns(last.List)
	case *ast.IfStmt:
		if last.Else == nil || !blockAlwaysReturns(last.Body.List) {
			return false
		}
		switch el := last.Else.(type) {
		case *ast.BlockStmt:
			return blockAlwaysReturns(el.List)
		case *ast.IfStmt:
			return blockAlwaysReturns([]ast.Stmt{el})
		default:
			return false
		}
	case *ast.ForStmt:
		if last.Init != nil || last.Cond != nil || last.Post != nil {
			return false
		}
		var hasBreak, hasReturn bool
		ast.Inspect(last.Body, func(n ast.Node) bool {
			if hasBreak || n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.ReturnStmt:
				hasReturn = true
				return false
			case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
				ast.Inspect(node, func(in ast.Node) bool {
					if hasBreak || in == nil {
						return false
					}
					switch inner := in.(type) {
					case *ast.FuncLit:
						return false
					case *ast.ReturnStmt:
						hasReturn = true
						return false
					case *ast.BranchStmt:
						if inner.Tok == token.BREAK && inner.Label != nil {
							hasBreak = true
							return false
						}
					}
					return true
				})
				return false
			case *ast.BranchStmt:
				if node.Tok == token.BREAK {
					hasBreak = true
					return false
				}
			}
			return true
		})
		return hasReturn && !hasBreak
	}
	return false
}

func stmtAlwaysTerminates(stmt ast.Stmt) bool {
	if stmt == nil {
		return false
	}
	switch s := stmt.(type) {
	case *ast.ReturnStmt, *ast.BranchStmt:
		return true
	case *ast.BlockStmt:
		return slices.ContainsFunc(s.List, stmtAlwaysTerminates)
	case *ast.ExprStmt:
		call, ok := unwrapParens(s.X).(*ast.CallExpr)
		if !ok {
			return false
		}
		if id, ok := unwrapParens(call.Fun).(*ast.Ident); ok && id.Name == "panic" {
			return true
		}
		if sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Exit" {
			if pkgID, okPkg := unwrapParens(sel.X).(*ast.Ident); okPkg && pkgID.Name == "os" {
				return true
			}
		}
		return false
	case *ast.IfStmt:
		if s.Else == nil || !stmtAlwaysTerminates(s.Body) {
			return false
		}
		return stmtAlwaysTerminates(s.Else)
	case *ast.ForStmt:
		if s.Cond != nil {
			return false
		}
		hasBreak := false
		ast.Inspect(s.Body, func(n ast.Node) bool {
			if hasBreak || n == nil {
				return false
			}
			switch br := n.(type) {
			case *ast.FuncLit, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
				return false
			case *ast.BranchStmt:
				if br.Tok == token.BREAK {
					hasBreak = true
					return false
				}
			}
			return true
		})
		return !hasBreak
	default:
		return false
	}
}

func findEnclosingFuncAndAncestors(f *ast.File, target ast.Node) (*ast.FuncDecl, []ast.Node) {
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		var stack, found []ast.Node
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if found != nil {
				return false
			}
			if n == nil {
				stack = stack[:len(stack)-1]
				return false
			}
			stack = append(stack, n)
			if n == target {
				found = slices.Clone(stack)
				return false
			}
			return true
		})
		if found != nil {
			return fn, found
		}
	}
	return nil, nil
}
