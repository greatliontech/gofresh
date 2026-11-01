package closure

import (
	"go/ast"
	"go/token"
	"maps"
	"slices"
)

func walkOffSurfaceAST(node ast.Node, scope map[string]bool, recIdent, recSel func(string), recQual func(base, sel string)) {
	if node == nil {
		return
	}
	switch n := node.(type) {
	case *ast.BlockStmt:
		sub := maps.Clone(scope)
		for _, st := range n.List {
			walkOffSurfaceAST(st, sub, recIdent, recSel, recQual)
		}
	case *ast.IfStmt:
		sub := maps.Clone(scope)
		if n.Init != nil {
			walkOffSurfaceAST(n.Init, sub, recIdent, recSel, recQual)
		}
		walkOffSurfaceAST(n.Cond, sub, recIdent, recSel, recQual)
		walkOffSurfaceAST(n.Body, sub, recIdent, recSel, recQual)
		if n.Else != nil {
			walkOffSurfaceAST(n.Else, sub, recIdent, recSel, recQual)
		}
	case *ast.ForStmt:
		sub := maps.Clone(scope)
		if n.Init != nil {
			walkOffSurfaceAST(n.Init, sub, recIdent, recSel, recQual)
		}
		if n.Cond != nil {
			walkOffSurfaceAST(n.Cond, sub, recIdent, recSel, recQual)
		}
		if n.Post != nil {
			walkOffSurfaceAST(n.Post, sub, recIdent, recSel, recQual)
		}
		walkOffSurfaceAST(n.Body, sub, recIdent, recSel, recQual)
	case *ast.RangeStmt:
		walkOffSurfaceAST(n.X, scope, recIdent, recSel, recQual)
		sub := maps.Clone(scope)
		if n.Tok == token.DEFINE {
			for _, e := range []ast.Expr{n.Key, n.Value} {
				if id, ok := unwrapParens(e).(*ast.Ident); ok && id.Name != "_" && id.Name != "" {
					sub[id.Name] = true
				}
			}
		} else {
			if n.Key != nil {
				walkOffSurfaceAST(n.Key, sub, recIdent, recSel, recQual)
			}
			if n.Value != nil {
				walkOffSurfaceAST(n.Value, sub, recIdent, recSel, recQual)
			}
		}
		walkOffSurfaceAST(n.Body, sub, recIdent, recSel, recQual)
	case *ast.SwitchStmt:
		sub := maps.Clone(scope)
		if n.Init != nil {
			walkOffSurfaceAST(n.Init, sub, recIdent, recSel, recQual)
		}
		if n.Tag != nil {
			walkOffSurfaceAST(n.Tag, sub, recIdent, recSel, recQual)
		}
		if n.Body != nil {
			for _, st := range n.Body.List {
				walkOffSurfaceAST(st, maps.Clone(sub), recIdent, recSel, recQual)
			}
		}
	case *ast.TypeSwitchStmt:
		sub := maps.Clone(scope)
		if n.Init != nil {
			walkOffSurfaceAST(n.Init, sub, recIdent, recSel, recQual)
		}
		if as, ok := n.Assign.(*ast.AssignStmt); ok && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			walkOffSurfaceAST(as.Rhs[0], sub, recIdent, recSel, recQual)
			if id, okID := unwrapParens(as.Lhs[0]).(*ast.Ident); okID && id.Name != "_" && id.Name != "" {
				sub[id.Name] = true
			}
		} else if n.Assign != nil {
			walkOffSurfaceAST(n.Assign, sub, recIdent, recSel, recQual)
		}
		if n.Body != nil {
			for _, st := range n.Body.List {
				walkOffSurfaceAST(st, maps.Clone(sub), recIdent, recSel, recQual)
			}
		}
	case *ast.SelectStmt:
		if n.Body != nil {
			for _, st := range n.Body.List {
				walkOffSurfaceAST(st, maps.Clone(scope), recIdent, recSel, recQual)
			}
		}
	case *ast.CaseClause:
		for _, e := range n.List {
			walkOffSurfaceAST(e, scope, recIdent, recSel, recQual)
		}
		sub := maps.Clone(scope)
		for _, st := range n.Body {
			walkOffSurfaceAST(st, sub, recIdent, recSel, recQual)
		}
	case *ast.CommClause:
		sub := maps.Clone(scope)
		if n.Comm != nil {
			walkOffSurfaceAST(n.Comm, sub, recIdent, recSel, recQual)
		}
		for _, st := range n.Body {
			walkOffSurfaceAST(st, sub, recIdent, recSel, recQual)
		}
	case *ast.AssignStmt:
		for _, rhs := range n.Rhs {
			walkOffSurfaceAST(rhs, scope, recIdent, recSel, recQual)
		}
		if n.Tok == token.DEFINE {
			for _, lhs := range n.Lhs {
				if id, ok := unwrapParens(lhs).(*ast.Ident); ok {
					if id.Name != "_" && id.Name != "" {
						scope[id.Name] = true
					}
				} else {
					walkOffSurfaceAST(lhs, scope, recIdent, recSel, recQual)
				}
			}
		} else {
			for _, lhs := range n.Lhs {
				walkOffSurfaceAST(lhs, scope, recIdent, recSel, recQual)
			}
		}
	case *ast.DeclStmt:
		if gd, ok := n.Decl.(*ast.GenDecl); ok {
			for _, spec := range gd.Specs {
				switch sp := spec.(type) {
				case *ast.ValueSpec:
					if sp.Type != nil {
						walkOffSurfaceAST(sp.Type, scope, recIdent, recSel, recQual)
					}
					for _, v := range sp.Values {
						walkOffSurfaceAST(v, scope, recIdent, recSel, recQual)
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
					walkOffSurfaceAST(sp.Type, sub, recIdent, recSel, recQual)
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
							walkOffSurfaceAST(fld.Type, scope, recIdent, recSel, recQual)
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
			walkOffSurfaceAST(n.Body, sub, recIdent, recSel, recQual)
		}
	case *ast.Ident:
		if n.Name != "_" && !scope[n.Name] {
			recIdent(n.Name)
		}
	case *ast.SelectorExpr:
		if xID, ok := unwrapParens(n.X).(*ast.Ident); ok {
			if !scope[xID.Name] {
				if n.Sel != nil {
					recQual(xID.Name, n.Sel.Name)
				} else {
					recIdent(xID.Name)
				}
				return
			}
		} else {
			walkOffSurfaceAST(n.X, scope, recIdent, recSel, recQual)
		}
		if n.Sel != nil {
			recSel(n.Sel.Name)
		}
	case *ast.StructType:
		if n.Fields != nil {
			for _, fld := range n.Fields.List {
				if fld.Type != nil {
					walkOffSurfaceAST(fld.Type, scope, recIdent, recSel, recQual)
				}
			}
		}
	case *ast.InterfaceType:
		if n.Methods != nil {
			for _, m := range n.Methods.List {
				if m.Type != nil {
					walkOffSurfaceAST(m.Type, scope, recIdent, recSel, recQual)
				}
			}
		}
	case *ast.FuncType:
		for _, fl := range []*ast.FieldList{n.TypeParams, n.Params, n.Results} {
			if fl != nil {
				for _, fld := range fl.List {
					if fld.Type != nil {
						walkOffSurfaceAST(fld.Type, scope, recIdent, recSel, recQual)
					}
				}
			}
		}
	case *ast.LabeledStmt:
		walkOffSurfaceAST(n.Stmt, scope, recIdent, recSel, recQual)
	case *ast.BranchStmt:
		// Label ident is not a value/decl reference.
	default:
		ast.Inspect(node, func(ch ast.Node) bool {
			if ch == nil || ch == node {
				return true
			}
			walkOffSurfaceAST(ch, scope, recIdent, recSel, recQual)
			return false
		})
	}
}

func allNonSelPropIdentsIn(files []*ast.File, name string, allowed map[*ast.Ident]bool) bool {
	return allNonSelPropIdentsInSet(files, map[string]struct{}{name: {}}, allowed)
}

func allNonSelPropIdentsInSet[V any](files []*ast.File, names map[string]V, allowed map[*ast.Ident]bool) bool {
	if len(names) == 0 {
		return true
	}
	ok := true
	var inspect func(n ast.Node) bool
	inspect = func(n ast.Node) bool {
		if !ok || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.SelectorExpr:
			ast.Inspect(node.X, inspect)
			return false
		case *ast.Ident:
			if _, match := names[node.Name]; match && !allowed[node] {
				ok = false
			}
			return false
		default:
			return true
		}
	}
	for _, f := range files {
		ast.Inspect(f, inspect)
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
	var inspect func(n ast.Node) bool
	inspect = func(n ast.Node) bool {
		if n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.SelectorExpr:
			ast.Inspect(node.X, inspect)
			return false
		case *ast.Ident:
			if allowed, match := allowedByName[node.Name]; match && !allowed[node] {
				leaked[node.Name] = true
			}
			return false
		default:
			return true
		}
	}
	for _, f := range files {
		ast.Inspect(f, inspect)
	}
	return leaked
}

func walkNonSelectorPropIdents(root ast.Node, fn func(*ast.Ident)) {
	var inspect func(n ast.Node) bool
	inspect = func(n ast.Node) bool {
		if n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.SelectorExpr:
			ast.Inspect(node.X, inspect)
			return false
		case *ast.KeyValueExpr:
			ast.Inspect(node.Value, inspect)
			return false
		case *ast.StructType:
			if node.Fields != nil {
				for _, field := range node.Fields.List {
					ast.Inspect(field.Type, inspect)
				}
			}
			return false
		case *ast.InterfaceType:
			if node.Methods != nil {
				for _, field := range node.Methods.List {
					ast.Inspect(field.Type, inspect)
				}
			}
			return false
		case *ast.Ident:
			fn(node)
			return false
		default:
			return true
		}
	}
	ast.Inspect(root, inspect)
}

func allNonSelectorPropIdentsIn(files []*ast.File, allowedByName map[string]map[*ast.Ident]bool) bool {
	if len(allowedByName) == 0 {
		return true
	}
	ok := true
	for _, f := range files {
		walkNonSelectorPropIdents(f, func(id *ast.Ident) {
			if allowed, match := allowedByName[id.Name]; match && !allowed[id] {
				ok = false
			}
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
	found := false
	var walk func(n ast.Node)
	walk = func(n ast.Node) {
		if found || n == nil {
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

func bodyMutatesOrTakesAddrOfAny(body *ast.BlockStmt, protected map[string]bool) bool {
	if body == nil || len(protected) == 0 {
		return false
	}
	bad := false
	ast.Inspect(body, func(n ast.Node) bool {
		if bad || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if id, ok := unwrapParens(lhs).(*ast.Ident); ok && protected[id.Name] {
					bad = true
					return false
				}
			}
		case *ast.RangeStmt:
			for _, lhs := range []ast.Expr{node.Key, node.Value} {
				if lhs != nil {
					if id, ok := unwrapParens(lhs).(*ast.Ident); ok && protected[id.Name] {
						bad = true
						return false
					}
				}
			}
		case *ast.IncDecStmt:
			if id, ok := unwrapParens(node.X).(*ast.Ident); ok && protected[id.Name] {
				bad = true
				return false
			}
		case *ast.UnaryExpr:
			if node.Op == token.AND {
				if id, ok := unwrapParens(node.X).(*ast.Ident); ok && protected[id.Name] {
					bad = true
					return false
				}
			}
		}
		return true
	})
	return bad
}

func nodeMutatesOrTakesAddrOfSelector(root ast.Node, baseIdent string, fields map[string]bool) bool {
	if root == nil || len(fields) == 0 {
		return false
	}
	matchSel := func(expr ast.Expr) bool {
		if expr == nil {
			return false
		}
		sel, ok := unwrapParens(expr).(*ast.SelectorExpr)
		if !ok || !fields[sel.Sel.Name] {
			return false
		}
		if baseIdent == "" {
			return true
		}
		id, ok := unwrapParens(sel.X).(*ast.Ident)
		return ok && id.Name == baseIdent
	}
	bad := false
	ast.Inspect(root, func(n ast.Node) bool {
		if bad || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if matchSel(lhs) {
					bad = true
					return false
				}
			}
		case *ast.RangeStmt:
			if matchSel(node.Key) || matchSel(node.Value) {
				bad = true
				return false
			}
		case *ast.IncDecStmt:
			if matchSel(node.X) {
				bad = true
				return false
			}
		case *ast.UnaryExpr:
			if node.Op == token.AND && matchSel(node.X) {
				bad = true
				return false
			}
		}
		return true
	})
	return bad
}

func blockOnlySelectsOnIdent(body *ast.BlockStmt, ident string) bool {
	if body == nil || ident == "" {
		return true
	}
	var shadowed, escaped bool
	var walk func(n ast.Node)
	walk = func(n ast.Node) {
		if shadowed || escaped || n == nil {
			return
		}
		switch node := n.(type) {
		case *ast.ValueSpec:
			for _, nameID := range node.Names {
				if nameID.Name == ident {
					shadowed = true
					return
				}
			}
			if node.Type != nil {
				walk(node.Type)
			}
			for _, v := range node.Values {
				walk(v)
			}
		case *ast.AssignStmt:
			if node.Tok == token.DEFINE {
				for _, lhs := range node.Lhs {
					if id, ok := unwrapParens(lhs).(*ast.Ident); ok && id.Name == ident {
						shadowed = true
						return
					}
				}
			}
			for _, lhs := range node.Lhs {
				walk(lhs)
			}
			for _, rhs := range node.Rhs {
				walk(rhs)
			}
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
	return !shadowed && !escaped
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
	if recvVarName(fn) == name {
		return true
	}
	if fn.Type != nil {
		for _, fl := range []*ast.FieldList{fn.Type.TypeParams, fn.Type.Params, fn.Type.Results} {
			if fl == nil {
				continue
			}
			for _, f := range fl.List {
				for _, id := range f.Names {
					if id.Name == name {
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
	for name := range names {
		if funcDeclaresParamOrResult(fn, name) {
			return true
		}
	}
	return bodyDeclaresAnyIdent(fn.Body, names)
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
	for _, list := range []*ast.FieldList{fn.Recv, fn.Type.Params, fn.Type.Results} {
		if list == nil {
			continue
		}
		for _, field := range list.List {
			for _, n := range field.Names {
				if n.Name == ident {
					return true
				}
			}
		}
	}
	shadowed := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if shadowed || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.AssignStmt:
			if node.Tok == token.DEFINE {
				for _, lhs := range node.Lhs {
					if id, ok := unwrapParens(lhs).(*ast.Ident); ok && id.Name == ident {
						shadowed = true
						return false
					}
				}
			}
		case *ast.ValueSpec:
			for _, id := range node.Names {
				if id.Name == ident {
					shadowed = true
					return false
				}
			}
		case *ast.TypeSpec:
			if node.Name.Name == ident {
				shadowed = true
				return false
			}
		}
		return true
	})
	return shadowed
}

func bodyHasControlFlowOrRecoverBypass(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	bad := false
	ast.Inspect(body, func(n ast.Node) bool {
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
			return true
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
