package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// environmentFreeFuncLit reports whether a function literal registered into
// a carrier is provably environment-free: every variable it references from
// an enclosing function scope proves leak-free under the use-shape engine.
func environmentFreeFuncLit(audited bool, p *packages.Package, lit *ast.FuncLit, enclosing ast.Node) bool {
	return environmentFreeFuncLitJudged(audited, p, lit, enclosing, nil, nil)
}

// environmentFreeFuncLitJudged additionally collects parameter and
// method wants when the caller supplies sinks, instead of refusing the
// deferrable shapes outright.
func environmentFreeFuncLitJudged(audited bool, p *packages.Package, lit *ast.FuncLit, enclosing ast.Node, wants map[syntaxutil.ParamKey]bool, methodWants map[syntaxutil.FuncKey]bool) bool {
	if p == nil || p.TypesInfo == nil || lit == nil || lit.Body == nil {
		return false
	}
	freeVars := func(body ast.Node, bound ast.Node) map[types.Object]bool {
		roots := map[types.Object]bool{}
		ast.Inspect(body, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			obj, ok := p.TypesInfo.Uses[ident]
			if !ok {
				return true
			}
			v, ok := obj.(*types.Var)
			if !ok || v.IsField() || v.Pkg() == nil {
				return true
			}
			if v.Parent() == v.Pkg().Scope() {
				return true
			}
			if v.Pos() >= bound.Pos() && v.Pos() <= bound.End() {
				return true
			}
			roots[v] = true
			return true
		})
		return roots
	}
	roots := freeVars(lit.Body, lit)
	if len(roots) == 0 {
		return true
	}
	if enclosing != nil {
		var edges [][2]types.Object
		aliasEdges := func(target ast.Expr, sources ast.Expr) {
			target = syntaxutil.UnparenExpr(target)
			ident, ok := target.(*ast.Ident)
			if !ok {
				return
			}
			obj := syntaxutil.IdentDefOrUse(p.TypesInfo, ident)
			v, ok := obj.(*types.Var)
			if !ok || v.Pkg() == nil || v.Parent() == v.Pkg().Scope() {
				return
			}
			if !refconfine.TypeHandsOutMutableReach(v.Type()) {
				return
			}
			ast.Inspect(sources, func(n ast.Node) bool {
				if src, ok := n.(*ast.Ident); ok {
					if o, ok := p.TypesInfo.Uses[src].(*types.Var); ok && o.Pkg() != nil && o.Parent() != o.Pkg().Scope() && !o.IsField() {
						if refconfine.TypeHandsOutMutableReach(o.Type()) {
							edges = append(edges, [2]types.Object{v, o})
						}
					}
				}
				return true
			})
		}
		ast.Inspect(enclosing, func(n ast.Node) bool {
			syntaxutil.EachLocalBinding(p.TypesInfo, n, aliasEdges)
			return true
		})
		for changed := true; changed; {
			changed = false
			for _, e := range edges {
				if roots[e[0]] != roots[e[1]] {
					roots[e[0]], roots[e[1]] = true, true
					changed = true
				}
			}
		}
	}
	if !boundValueLeakFreeJudged(audited, p, roots, lit.Body, wants, nil, methodWants, nil, nil) {
		return false
	}
	if enclosing == nil {
		return true
	}
	sound := true
	ast.Inspect(enclosing, func(n ast.Node) bool {
		if !sound {
			return false
		}
		switch n := n.(type) {
		case *ast.FuncLit:
			if n == lit {
				return false
			}
			shared := false
			for v := range freeVars(n.Body, n) {
				if roots[v] {
					shared = true
					break
				}
			}
			if shared && !boundValueLeakFreeJudged(audited, p, roots, n.Body, wants, nil, methodWants, nil, nil) {
				sound = false
			}
			return false
		case *ast.GoStmt:
			ast.Inspect(n.Call, func(inner ast.Node) bool {
				if _, isLit := inner.(*ast.FuncLit); isLit {
					return false
				}
				if ident, ok := inner.(*ast.Ident); ok {
					if obj, ok := p.TypesInfo.Uses[ident]; ok && roots[obj] {
						sound = false
					}
				}
				return sound
			})
		}
		return sound
	})
	return sound
}

// fieldRegMark is one registered-population disposition for a
// func-signature struct field a carrier can hand out: class 'd' defers the
// field position to a parameter's leak-free fact, class 'p' poisons it. A
// poison with field "" covers the whole population, idx -1 every index.
type fieldRegMark struct {
	class byte
	field string
	idx   int
	param syntaxutil.ParamKey
}

// classifyFieldRegistrants derives the registered-population marks of one
// admitted registration store.
func classifyFieldRegistrants(audited bool, p *packages.Package, lhs, rhs ast.Expr, emit func(fieldRegMark)) {
	if sel, ok := syntaxutil.UnparenExpr(lhs).(*ast.SelectorExpr); ok {
		if selection, ok := p.TypesInfo.Selections[sel]; ok && selection.Kind() == types.FieldVal {
			if _, isSig := types.Unalias(selection.Type()).Underlying().(*types.Signature); isSig {
				classifyFieldRegistrantValue(audited, p, sel.Sel.Name, rhs, emit)
				return
			}
		}
	}
	classifyRegistrantFlow(audited, p, rhs, emit)
}

func classifyRegistrantFlow(audited bool, p *packages.Package, expr ast.Expr, emit func(fieldRegMark)) {
	switch e := syntaxutil.UnparenExpr(expr).(type) {
	case *ast.CompositeLit:
		classifyRegistrantComposite(audited, p, e, emit)
		return
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			classifyRegistrantFlow(audited, p, e.X, emit)
			return
		}
	case *ast.FuncLit:
		classifyLiteralRegistrant(audited, p, syntaxutil.ElemPositionField, e, emit)
		return
	case *ast.BasicLit:
		return
	case *ast.CallExpr:
		if ident, ok := syntaxutil.UnparenExpr(e.Fun).(*ast.Ident); ok {
			if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && (ident.Name == "make" || ident.Name == "new") {
				return
			}
		}
		for _, arg := range e.Args {
			classifyRegistrantFlow(audited, p, arg, emit)
		}
		return
	case *ast.Ident:
		if obj := syntaxutil.IdentDefOrUse(p.TypesInfo, e); obj != nil {
			switch obj.(type) {
			case *types.Func:
				classifyFieldRegistrantValue(audited, p, syntaxutil.ElemPositionField, e, emit)
				return
			case *types.Nil:
				return
			}
		}
	case *ast.SelectorExpr:
		if obj, ok := p.TypesInfo.Uses[e.Sel]; ok {
			if _, isFunc := obj.(*types.Func); isFunc {
				classifyFieldRegistrantValue(audited, p, syntaxutil.ElemPositionField, e, emit)
				return
			}
		}
	case *ast.IndexExpr, *ast.IndexListExpr:
		if fn, _ := syntaxutil.PlainCalleeFunc(p, e); fn != nil {
			classifyFieldRegistrantValue(audited, p, syntaxutil.ElemPositionField, e, emit)
			return
		}
	}
	if refconfine.TypeCarriesSignature(p.TypesInfo.TypeOf(syntaxutil.UnparenExpr(expr))) {
		emit(fieldRegMark{class: 'p', idx: -1})
	}
}

func classifyRegistrantComposite(audited bool, p *packages.Package, lit *ast.CompositeLit, emit func(fieldRegMark)) {
	t := p.TypesInfo.TypeOf(lit)
	if t == nil {
		emit(fieldRegMark{class: 'p', idx: -1})
		return
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Struct:
		for i, elt := range lit.Elts {
			var field *types.Var
			value := elt
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				value = kv.Value
				if key, ok := kv.Key.(*ast.Ident); ok {
					for j := 0; j < u.NumFields(); j++ {
						if u.Field(j).Name() == key.Name {
							field = u.Field(j)
							break
						}
					}
				}
			} else if i < u.NumFields() {
				field = u.Field(i)
			}
			if field == nil {
				emit(fieldRegMark{class: 'p', idx: -1})
				continue
			}
			if _, isSig := types.Unalias(field.Type()).Underlying().(*types.Signature); isSig {
				classifyFieldRegistrantValue(audited, p, field.Name(), value, emit)
				continue
			}
			classifyRegistrantFlow(audited, p, value, emit)
		}
	case *types.Map, *types.Slice, *types.Array:
		syntaxutil.EachCompositeLitValue(lit, func(value ast.Expr) bool {
			classifyRegistrantFlow(audited, p, value, emit)
			return true
		})
	default:
		emit(fieldRegMark{class: 'p', idx: -1})
	}
}

func classifyFieldRegistrantValue(audited bool, p *packages.Package, field string, value ast.Expr, emit func(fieldRegMark)) {
	deferNamed := func(fn *types.Func) bool {
		if fn == nil || fn.Pkg() == nil {
			return false
		}
		fn = fn.Origin()
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() != nil {
			return false
		}
		fk := syntaxutil.FuncKey{Pkg: fn.Pkg().Path(), Name: fn.Name()}
		for idx := 0; idx < sig.Params().Len(); idx++ {
			emit(fieldRegMark{class: 'd', field: field, idx: idx, param: syntaxutil.ParamKey{Func: fk, Index: idx}})
		}
		return true
	}
	switch v := syntaxutil.UnparenExpr(value).(type) {
	case *ast.FuncLit:
		classifyLiteralRegistrant(audited, p, field, v, emit)
		return
	case *ast.Ident:
		if obj := syntaxutil.IdentDefOrUse(p.TypesInfo, v); obj != nil {
			if _, isNil := obj.(*types.Nil); isNil {
				return
			}
			if fn, ok := obj.(*types.Func); ok && deferNamed(fn) {
				return
			}
		}
	case *ast.SelectorExpr:
		if _, isSelection := p.TypesInfo.Selections[v]; !isSelection {
			if x, ok := v.X.(*ast.Ident); ok {
				if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
					if fn, ok := p.TypesInfo.Uses[v.Sel].(*types.Func); ok && deferNamed(fn) {
						return
					}
				}
			}
		}
	case *ast.IndexExpr, *ast.IndexListExpr:
		if fn, _ := syntaxutil.PlainCalleeFunc(p, v); fn != nil && deferNamed(fn) {
			return
		}
	}
	emit(fieldRegMark{class: 'p', field: field, idx: -1})
}

func classifyLiteralRegistrant(audited bool, p *packages.Package, field string, lit *ast.FuncLit, emit func(fieldRegMark)) {
	if lit.Type == nil || lit.Body == nil {
		emit(fieldRegMark{class: 'p', field: field, idx: -1})
		return
	}
	idx := 0
	if lit.Type.Params != nil {
		for _, group := range lit.Type.Params.List {
			names := group.Names
			if len(names) == 0 {
				idx++
				continue
			}
			for _, name := range names {
				if name.Name == "_" {
					idx++
					continue
				}
				obj := p.TypesInfo.Defs[name]
				if obj == nil {
					emit(fieldRegMark{class: 'p', field: field, idx: idx})
					idx++
					continue
				}
				wants := map[syntaxutil.ParamKey]bool{}
				if boundValueLeakFreeJudged(audited, p, map[types.Object]bool{obj: true}, lit.Body, wants, nil, nil, nil, nil) {
					for want := range wants {
						emit(fieldRegMark{class: 'd', field: field, idx: idx, param: want})
					}
				} else {
					emit(fieldRegMark{class: 'p', field: field, idx: idx})
				}
				idx++
			}
		}
	}
}

// recordEnvCarryingRegistrations records, per dynamic-capable package
// variable (own or foreign), whether this package's direct code stores a
// function-carrying value into it that is not provably environment-free.
func recordEnvCarryingRegistrations(
	audited bool,
	p *packages.Package,
	exemptSeamNodes map[ast.Node]bool,
	envCarrying map[string]bool,
	envCalls map[string]map[syntaxutil.FuncKey]bool,
	fieldDefer map[syntaxutil.FieldPosKey]map[syntaxutil.ParamKey]bool,
	fieldPoison map[string]map[syntaxutil.FieldParamPoison]bool,
	hooks *syntaxutil.ExplainHookSet,
) {
	if p == nil || p.TypesInfo == nil {
		return
	}
	resolve := func(ident *ast.Ident) (types.Object, bool) {
		if obj, ok := p.TypesInfo.Uses[ident]; ok {
			return obj, true
		}
		if obj, ok := p.TypesInfo.Defs[ident]; ok && obj != nil {
			return obj, true
		}
		return nil, false
	}
	carrierVar := func(obj types.Object) (*types.Var, bool) {
		variable, ok := obj.(*types.Var)
		if !ok || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
			return nil, false
		}
		if !refconfine.TypeMayCarryUnknownDynamic(audited, variable.Type()) {
			return nil, false
		}
		return variable, true
	}
	var localAliases map[types.Object][]*types.Var
	collectCarrierVars := func(expr ast.Expr, aliases map[types.Object][]*types.Var, skipFuncLit bool) []*types.Var {
		var vars []*types.Var
		ast.Inspect(expr, func(n ast.Node) bool {
			if skipFuncLit {
				if _, isLit := n.(*ast.FuncLit); isLit {
					return false
				}
			}
			if ident, ok := n.(*ast.Ident); ok {
				if obj, ok := resolve(ident); ok {
					if variable, ok := carrierVar(obj); ok {
						vars = append(vars, variable)
					} else {
						vars = append(vars, aliases[obj]...)
					}
				}
			}
			return true
		})
		return vars
	}
	targetVars := func(expr ast.Expr) []*types.Var {
		return collectCarrierVars(expr, localAliases, false)
	}
	computeLocalAliases := func(body ast.Node) map[types.Object][]*types.Var {
		aliased := map[types.Object][]*types.Var{}
		sourceVars := func(expr ast.Expr) []*types.Var {
			return collectCarrierVars(expr, aliased, true)
		}
		bind := func(target ast.Expr, sources []*types.Var) bool {
			if len(sources) == 0 {
				return false
			}
			ident, ok := syntaxutil.UnparenExpr(target).(*ast.Ident)
			if !ok {
				return false
			}
			obj, ok := resolve(ident)
			if !ok {
				return false
			}
			if _, pkg := carrierVar(obj); pkg {
				return false
			}
			if !refconfine.TypeHandsOutDynamicAlias(audited, obj.Type()) {
				return false
			}
			have := map[*types.Var]bool{}
			for _, v := range aliased[obj] {
				have[v] = true
			}
			changed := false
			for _, v := range sources {
				if !have[v] {
					aliased[obj] = append(aliased[obj], v)
					have[v] = true
					changed = true
				}
			}
			return changed
		}
		for changed := true; changed; {
			changed = false
			ast.Inspect(body, func(n ast.Node) bool {
				switch n.(type) {
				case *ast.FuncLit, *ast.GoStmt:
					return false
				}
				syntaxutil.EachLocalBinding(p.TypesInfo, n, func(lhs, rhs ast.Expr) {
					if bind(lhs, sourceVars(rhs)) {
						changed = true
					}
				})
				return true
			})
		}
		return aliased
	}
	var enclosingBody ast.Node
	var pendingEnvCalls map[syntaxutil.FuncKey]bool
	var carrying func(expr ast.Expr) bool
	carrying = func(expr ast.Expr) bool {
		switch e := syntaxutil.UnparenExpr(expr).(type) {
		case *ast.CompositeLit:
			return !syntaxutil.EachCompositeLitValue(e, func(value ast.Expr) bool {
				return !carrying(value)
			})
		case *ast.UnaryExpr:
			if e.Op == token.AND {
				return carrying(e.X)
			}
		case *ast.FuncLit:
			return !environmentFreeFuncLit(audited, p, e, enclosingBody)
		case *ast.BasicLit:
			return false
		case *ast.CallExpr:
			if ident, ok := syntaxutil.UnparenExpr(e.Fun).(*ast.Ident); ok {
				if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && (ident.Name == "make" || ident.Name == "new") {
					return false
				}
			}
			if pendingEnvCalls != nil && refconfine.TypeCarriesSignature(p.TypesInfo.TypeOf(syntaxutil.UnparenExpr(expr))) {
				if fn, pkgPath := syntaxutil.PlainCalleeFunc(p, e.Fun); fn != nil {
					for _, arg := range e.Args {
						if carrying(arg) {
							return true
						}
					}
					pendingEnvCalls[syntaxutil.FuncKey{Pkg: pkgPath, Name: fn.Name()}] = true
					return false
				}
			}
		case *ast.Ident:
			if obj, ok := resolve(e); ok {
				switch obj.(type) {
				case *types.Func:
					return false
				case *types.Nil:
					return false
				}
			}
		case *ast.SelectorExpr:
			if selection, ok := p.TypesInfo.Selections[e]; ok {
				switch selection.Kind() {
				case types.MethodExpr:
					return false
				case types.MethodVal:
					return true
				}
				break
			}
			if obj, ok := p.TypesInfo.Uses[e.Sel]; ok {
				if _, isFunc := obj.(*types.Func); isFunc {
					return false
				}
			}
		case *ast.IndexExpr, *ast.IndexListExpr:
			if fn, _ := syntaxutil.PlainCalleeFunc(p, e); fn != nil {
				return false
			}
		}
		return refconfine.TypeCarriesSignature(p.TypesInfo.TypeOf(syntaxutil.UnparenExpr(expr)))
	}
	handleStore := func(lhs, rhs ast.Expr, rebindable bool) {
		if rebindable {
			if ident, ok := syntaxutil.UnparenExpr(lhs).(*ast.Ident); ok {
				if obj, ok := resolve(ident); ok {
					if _, isCarrier := carrierVar(obj); !isCarrier {
						return
					}
				}
			}
		}
		targets := targetVars(lhs)
		if len(targets) == 0 {
			return
		}
		flows := []ast.Expr{rhs}
		if call, ok := syntaxutil.UnparenExpr(rhs).(*ast.CallExpr); ok && len(call.Args) > 0 {
			if ident, ok := syntaxutil.UnparenExpr(call.Fun).(*ast.Ident); ok {
				if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && ident.Name == "append" {
					var baseIdent *ast.Ident
					switch base := syntaxutil.UnparenExpr(call.Args[0]).(type) {
					case *ast.Ident:
						baseIdent = base
					case *ast.SelectorExpr:
						if x, ok := base.X.(*ast.Ident); ok {
							if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
								baseIdent = base.Sel
							}
						}
					}
					if baseIdent != nil {
						if obj, ok := resolve(baseIdent); ok {
							if variable, ok := carrierVar(obj); ok && len(targets) == 1 && variable == targets[0] {
								flows = call.Args[1:]
							}
						}
					}
				}
			}
		}
		poison := false
		pendingEnvCalls = map[syntaxutil.FuncKey]bool{}
		var poisonAt token.Pos
		for _, flow := range flows {
			if carrying(flow) {
				poison = true
				poisonAt = flow.Pos()
				break
			}
		}
		if poison {
			for _, variable := range targets {
				syntaxutil.ExplainStoreMark(hooks, p, syntaxutil.DynamicVarKey(variable), poisonAt)
				envCarrying[syntaxutil.DynamicVarKey(variable)] = true
			}
		} else if envCalls != nil {
			for callee := range pendingEnvCalls {
				for _, variable := range targets {
					key := syntaxutil.DynamicVarKey(variable)
					if envCalls[key] == nil {
						envCalls[key] = map[syntaxutil.FuncKey]bool{}
					}
					envCalls[key][callee] = true
				}
			}
			if fieldDefer != nil {
				var marks []fieldRegMark
				for _, flow := range flows {
					classifyFieldRegistrants(audited, p, lhs, flow, func(m fieldRegMark) {
						marks = append(marks, m)
					})
				}
				for _, variable := range targets {
					key := syntaxutil.DynamicVarKey(variable)
					for _, m := range marks {
						switch m.class {
						case 'd':
							pos := syntaxutil.FieldPosKey{Owner: key, Field: m.field, Index: m.idx}
							if fieldDefer[pos] == nil {
								fieldDefer[pos] = map[syntaxutil.ParamKey]bool{}
							}
							fieldDefer[pos][m.param] = true
						case 'p':
							if fieldPoison[key] == nil {
								fieldPoison[key] = map[syntaxutil.FieldParamPoison]bool{}
							}
							if m.field == "" {
								fieldPoison[key][syntaxutil.FieldParamPoison{Owner: key}] = true
							} else {
								fieldPoison[key][syntaxutil.FieldParamPoison{Owner: key, HasPos: true, Field: m.field, Index: m.idx}] = true
							}
						}
					}
				}
			}
		}
		pendingEnvCalls = nil
	}
	walkStores := func(body ast.Node) {
		localAliases = computeLocalAliases(body)
		defer func() { localAliases = nil }()
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit, *ast.GoStmt:
				return false
			case *ast.CallExpr:
				if ident, ok := syntaxutil.UnparenExpr(n.Fun).(*ast.Ident); ok {
					if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
						switch {
						case ident.Name == "copy" && len(n.Args) == 2:
							handleStore(n.Args[0], n.Args[1], false)
						case ident.Name == "append" && len(n.Args) > 1:
							for _, flow := range n.Args[1:] {
								handleStore(n.Args[0], flow, false)
							}
						}
					}
				}
			case *ast.AssignStmt:
				if len(n.Lhs) == len(n.Rhs) {
					for i, lhs := range n.Lhs {
						if exemptSeamNodes[lhs] {
							continue
						}
						handleStore(lhs, n.Rhs[i], true)
					}
				} else if len(n.Rhs) == 1 {
					for _, lhs := range n.Lhs {
						if exemptSeamNodes[lhs] {
							continue
						}
						handleStore(lhs, n.Rhs[0], true)
					}
				}
			case *ast.RangeStmt:
				for _, bind := range []ast.Expr{n.Key, n.Value} {
					if bind != nil && n.Tok == token.ASSIGN {
						handleStore(bind, n.X, true)
					}
				}
			case *ast.SendStmt:
				handleStore(n.Chan, n.Value, false)
			}
			return true
		})
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if decl.Body != nil {
					enclosingBody = decl.Body
					walkStores(decl.Body)
					enclosingBody = nil
				}
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					if len(vs.Names) == len(vs.Values) {
						for i, name := range vs.Names {
							handleStore(name, vs.Values[i], true)
						}
					} else if len(vs.Values) == 1 {
						for _, name := range vs.Names {
							handleStore(name, vs.Values[0], true)
						}
					}
				}
			}
		}
	}
}

// auditedValuePlane names the standard value-plane helpers whose
// results carry exactly their arguments' values - clone and
// concatenation shapes with no environment of their own. A closed
// set: absence keeps the refusal.
var auditedValuePlane = map[syntaxutil.FuncKey]bool{
	{Pkg: "slices", Name: "Clone"}:  true,
	{Pkg: "slices", Name: "Concat"}: true,
	{Pkg: "maps", Name: "Clone"}:    true,
}

// returnEnvFreeFunctions proves, per plain named function of the
// package, that every value its return expressions can carry into a
// carrier is environment-free provided the call's arguments are - the
// constructor-result admission of the environment-free registration
// audit.
func returnEnvFreeFunctions(
	audited bool,
	p *packages.Package,
	paramLeakFree map[syntaxutil.ParamKey]bool,
	readOnly map[string]bool,
	hooks *syntaxutil.ExplainHookSet,
) (
	map[string]bool,
	map[string]map[syntaxutil.FuncKey]bool,
	map[string]map[syntaxutil.ReturnFieldParamDefer]bool,
	map[string]map[syntaxutil.ReturnFieldParamPoison]bool,
	map[syntaxutil.ParamKey]bool,
	map[syntaxutil.ParamKey]map[syntaxutil.EnvAuditTarget]bool,
	map[string]map[syntaxutil.EnvAuditTarget]bool,
) {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return nil, nil, nil, nil, nil, nil, nil
	}
	ownPath := p.Types.Path()
	carries := func(t types.Type) bool {
		return refconfine.TypeCarriesSignature(t)
	}
	unparen := syntaxutil.UnparenExpr
	wantsResolve := func(wants map[syntaxutil.ParamKey]bool, methodWants map[syntaxutil.FuncKey]bool) bool {
		for want := range wants {
			if want.Func.Pkg != ownPath || !paramLeakFree[want] {
				return false
			}
		}
		for want := range methodWants {
			if want.Pkg != ownPath || !readOnly[want.Name] {
				return false
			}
		}
		return true
	}
	proven := map[string]bool{}
	deps := map[string]map[syntaxutil.FuncKey]bool{}
	retDefer := map[string]map[syntaxutil.ReturnFieldParamDefer]bool{}
	retPoison := map[string]map[syntaxutil.ReturnFieldParamPoison]bool{}
	insFree := map[syntaxutil.ParamKey]bool{}
	insDeps := map[syntaxutil.ParamKey]map[syntaxutil.EnvAuditTarget]bool{}
	callerInsDeps := map[string]map[syntaxutil.EnvAuditTarget]bool{}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name == nil || fd.Body == nil || fd.Name.Name == "init" {
				continue
			}
			fnKey := fd.Name.Name
			ownFuncKey := syntaxutil.FuncKey{Pkg: ownPath, Name: fnKey}
			params := map[types.Object]bool{}
			paramIndex := map[types.Object]int{}
			paramCount := 0
			if fd.Type.Params != nil {
				for _, field := range fd.Type.Params.List {
					if len(field.Names) == 0 {
						insFree[syntaxutil.ParamKey{Func: ownFuncKey, Index: paramCount}] = true
						paramCount++
						continue
					}
					for _, name := range field.Names {
						if obj := p.TypesInfo.Defs[name]; obj != nil && name.Name != "_" {
							params[obj] = true
							paramIndex[obj] = paramCount
						} else {
							insFree[syntaxutil.ParamKey{Func: ownFuncKey, Index: paramCount}] = true
						}
						paramCount++
					}
				}
			}
			localSources := map[types.Object][]ast.Expr{}
			writeSources := map[types.Object][]ast.Expr{}
			insertionWrites := map[types.Object][]ast.Expr{}
			localBroken := map[types.Object]bool{}
			captureBroken := map[types.Object]bool{}
			var aliasPairs [][2]types.Object
			var heldPairs [][2]types.Object
			stmtCallDeps := map[syntaxutil.FuncKey]bool{}
			trackedVar := func(obj types.Object) (*types.Var, bool) {
				v, ok := obj.(*types.Var)
				if !ok || v.Pkg() == nil || v.Parent() == v.Pkg().Scope() || !carries(v.Type()) {
					return nil, false
				}
				return v, true
			}
			breakIdents := func(expr ast.Expr, capture bool, gate func(types.Object) bool) {
				ast.Inspect(expr, func(n ast.Node) bool {
					if ident, ok := n.(*ast.Ident); ok {
						obj := p.TypesInfo.Uses[ident]
						if obj == nil {
							obj = p.TypesInfo.Defs[ident]
						}
						if obj != nil {
							if _, ok := trackedVar(obj); (ok || params[obj]) && (gate == nil || gate(obj)) {
								localBroken[obj] = true
								if capture {
									captureBroken[obj] = true
								}
							}
						}
					}
					return true
				})
			}
			breakTargets := func(expr ast.Expr) {
				breakIdents(expr, true, nil)
			}
			chainRoot := func(target ast.Expr) ast.Expr {
				base := unparen(target)
				for {
					switch b := base.(type) {
					case *ast.SelectorExpr:
						base = unparen(b.X)
					case *ast.IndexExpr:
						base = unparen(b.X)
					case *ast.SliceExpr:
						base = unparen(b.X)
					case *ast.StarExpr:
						base = unparen(b.X)
					default:
						return base
					}
				}
			}
			breakBase := func(target ast.Expr) {
				breakTargets(chainRoot(target))
			}
			sharesHeader := func(t types.Type) bool {
				if t == nil {
					return true
				}
				switch types.Unalias(t).Underlying().(type) {
				case *types.Struct, *types.Array, *types.Basic:
					return false
				}
				return true
			}
			pairLink := func(obj, sobj types.Object, shares bool) {
				if v, ok := sobj.(*types.Var); ok && v.IsField() {
					return
				}
				_, tracked := trackedVar(sobj)
				if !tracked || !refconfine.TypeHandsOutMutableReach(sobj.Type()) {
					return
				}
				if shares {
					aliasPairs = append(aliasPairs, [2]types.Object{obj, sobj})
				} else {
					heldPairs = append(heldPairs, [2]types.Object{obj, sobj})
				}
			}
			var linkBacking func(obj types.Object, source ast.Expr)
			linkValue := func(obj types.Object, e ast.Expr, shares bool) {
				if ident, ok := chainRoot(e).(*ast.Ident); ok {
					sobj := p.TypesInfo.Uses[ident]
					if sobj == nil {
						sobj = p.TypesInfo.Defs[ident]
					}
					if sobj != nil {
						pairLink(obj, sobj, shares)
						return
					}
				}
				ast.Inspect(e, func(m ast.Node) bool {
					if id, ok := m.(*ast.Ident); ok {
						if sobj := p.TypesInfo.Uses[id]; sobj != nil {
							pairLink(obj, sobj, true)
						}
					}
					return true
				})
			}
			linkBacking = func(obj types.Object, source ast.Expr) {
				e := unparen(source)
				switch v := e.(type) {
				case *ast.Ident, *ast.SelectorExpr, *ast.IndexExpr, *ast.StarExpr, *ast.SliceExpr:
					linkValue(obj, e, sharesHeader(p.TypesInfo.TypeOf(e)))
				case *ast.CompositeLit:
					syntaxutil.EachCompositeLitValue(v, func(value ast.Expr) bool {
						linkBacking(obj, value)
						return true
					})
				case *ast.UnaryExpr:
					if v.Op == token.AND {
						linkBacking(obj, v.X)
						return
					}
					linkValue(obj, e, true)
				case *ast.CallExpr:
					if fnIdent, ok := unparen(v.Fun).(*ast.Ident); ok {
						if _, builtin := p.TypesInfo.Uses[fnIdent].(*types.Builtin); builtin {
							switch fnIdent.Name {
							case "make", "new":
								return
							case "append":
								if len(v.Args) > 0 {
									linkValue(obj, v.Args[0], true)
									for _, arg := range v.Args[1:] {
										linkBacking(obj, arg)
									}
								}
								return
							}
						}
					}
					if tv, ok := p.TypesInfo.Types[v.Fun]; ok && tv.IsType() && len(v.Args) == 1 {
						linkBacking(obj, v.Args[0])
						return
					}
					ast.Inspect(v.Fun, func(m ast.Node) bool {
						if id, ok := m.(*ast.Ident); ok {
							if sobj := p.TypesInfo.Uses[id]; sobj != nil {
								pairLink(obj, sobj, true)
							}
						}
						return true
					})
					for _, arg := range v.Args {
						linkBacking(obj, arg)
					}
				case *ast.BasicLit, *ast.FuncLit:
				default:
					linkValue(obj, e, true)
				}
			}
			type pendingStore struct {
				robj   types.Object
				root   *ast.Ident
				target ast.Expr
				source ast.Expr
			}
			var pendingStores []pendingStore
			type insertionUse struct {
				root        types.Object
				calleeParam syntaxutil.ParamKey
				args        []ast.Expr
			}
			var pendingInsertionUses []insertionUse
			bindLocal := func(target ast.Expr, source ast.Expr, broken bool) {
				ident, ok := unparen(target).(*ast.Ident)
				if !ok {
					if source != nil && !broken {
						if rootIdent, ok := chainRoot(target).(*ast.Ident); ok {
							robj := p.TypesInfo.Uses[rootIdent]
							if robj == nil {
								robj = p.TypesInfo.Defs[rootIdent]
							}
							if robj != nil {
								if _, tracked := trackedVar(robj); tracked {
									pendingStores = append(pendingStores, pendingStore{robj, rootIdent, target, source})
									return
								}
							}
						}
					}
					breakBase(target)
					return
				}
				obj := p.TypesInfo.Defs[ident]
				if obj == nil {
					obj = p.TypesInfo.Uses[ident]
				}
				if obj != nil && params[obj] {
					localBroken[obj] = true
					return
				}
				if _, ok := trackedVar(obj); !ok {
					return
				}
				if broken || source == nil {
					localBroken[obj] = true
					return
				}
				if call, ok := unparen(source).(*ast.CallExpr); ok {
					if fnIdent, ok := unparen(call.Fun).(*ast.Ident); ok {
						if _, builtin := p.TypesInfo.Uses[fnIdent].(*types.Builtin); builtin && fnIdent.Name == "append" && len(call.Args) > 0 {
							if base, ok := unparen(call.Args[0]).(*ast.Ident); ok {
								if p.TypesInfo.Uses[base] == obj {
									linkBacking(obj, source)
									localSources[obj] = append(localSources[obj], call.Args[1:]...)
									return
								}
							}
						}
					}
				}
				linkBacking(obj, source)
				localSources[obj] = append(localSources[obj], source)
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.UnaryExpr:
					if n.Op == token.AND {
						switch root := chainRoot(n.X).(type) {
						case *ast.Ident:
							breakTargets(root)
						case *ast.CallExpr:
							breakTargets(n.X)
						}
					}
				case *ast.AssignStmt:
					if len(n.Lhs) == len(n.Rhs) {
						for i, lhs := range n.Lhs {
							bindLocal(lhs, n.Rhs[i], false)
						}
					} else if len(n.Rhs) == 1 {
						for _, lhs := range n.Lhs {
							bindLocal(lhs, n.Rhs[0], false)
						}
					} else {
						for _, lhs := range n.Lhs {
							bindLocal(lhs, nil, true)
						}
					}
				case *ast.ValueSpec:
					if len(n.Names) == len(n.Values) {
						for i, name := range n.Names {
							bindLocal(name, n.Values[i], false)
						}
					} else if len(n.Values) == 1 {
						for _, name := range n.Names {
							bindLocal(name, n.Values[0], false)
						}
					}
				case *ast.RangeStmt:
					container := false
					if t := p.TypesInfo.TypeOf(n.X); t != nil {
						switch u := types.Unalias(t).Underlying().(type) {
						case *types.Slice, *types.Array, *types.Map, *types.Basic:
							container = true
						case *types.Pointer:
							_, isArr := types.Unalias(u.Elem()).Underlying().(*types.Array)
							container = isArr
						}
					}
					for _, bind := range []ast.Expr{n.Key, n.Value} {
						if bind != nil {
							if container {
								bindLocal(bind, n.X, false)
							} else {
								bindLocal(bind, nil, true)
							}
						}
					}
				case *ast.SelectorExpr:
					if selection, ok := p.TypesInfo.Selections[n]; ok && selection.Kind() == types.MethodVal {
						if fn, ok := selection.Obj().(*types.Func); ok {
							if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
								_, ptr := types.Unalias(sig.Recv().Type()).(*types.Pointer)
								if ptr || sharesHeader(sig.Recv().Type()) || refconfine.TypeHandsOutMutableReach(sig.Recv().Type()) {
									mk := syntaxutil.MethodFactKey(fn)
									if mk.Pkg != ownPath || !readOnly[mk.Name] {
										breakBase(n.X)
									}
								}
							}
						}
					}
				case *ast.CallExpr:
					if ident, ok := unparen(n.Fun).(*ast.Ident); ok {
						if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
							if ident.Name == "copy" && len(n.Args) == 2 {
								bindLocal(n.Args[0], nil, true)
							}
							return true
						}
					}
					if tv, ok := p.TypesInfo.Types[n.Fun]; ok && tv.IsType() {
						return true
					}
					if fn, pkgPath := syntaxutil.PlainCalleeFunc(p, n.Fun); fn != nil {
						calleeFK := syntaxutil.FuncKey{Pkg: pkgPath, Name: fn.Name()}
						if !auditedValuePlane[calleeFK] {
							reaches := refconfine.TypeCarriesSignature(p.TypesInfo.TypeOf(n))
							for _, arg := range n.Args {
								ast.Inspect(arg, func(inner ast.Node) bool {
									if ident, ok := inner.(*ast.Ident); ok {
										obj := p.TypesInfo.Uses[ident]
										if obj == nil {
											obj = p.TypesInfo.Defs[ident]
										}
										if obj != nil {
											if _, ok := trackedVar(obj); ok || params[obj] {
												reaches = true
											}
										}
									}
									return !reaches
								})
								if reaches {
									break
								}
							}
							if reaches {
								stmtCallDeps[calleeFK] = true
							}
							sig, _ := fn.Type().(*types.Signature)
							breakReachIn := func(e ast.Expr) {
								breakIdents(e, true, func(obj types.Object) bool {
									return refconfine.TypeHandsOutMutableReach(obj.Type())
								})
							}
							var classifyLit func(lit *ast.CompositeLit)
							classifyLit = func(lit *ast.CompositeLit) {
								syntaxutil.EachCompositeLitValue(lit, func(value ast.Expr) bool {
									value = unparen(value)
									if t := p.TypesInfo.TypeOf(value); t != nil && !refconfine.TypeHandsOutMutableReach(t) {
										return true
									}
									switch v := value.(type) {
									case *ast.CompositeLit:
										classifyLit(v)
									case *ast.UnaryExpr:
										if v.Op == token.AND {
											if inner, ok := unparen(v.X).(*ast.CompositeLit); ok {
												classifyLit(inner)
												return true
											}
										}
										breakReachIn(value)
									case *ast.BasicLit, *ast.FuncLit:
									default:
										breakReachIn(value)
									}
									return true
								})
							}
							elemReach := func(t types.Type) bool {
								if t == nil {
									return true
								}
								switch u := types.Unalias(t).Underlying().(type) {
								case *types.Slice:
									return refconfine.TypeHandsOutMutableReach(u.Elem())
								case *types.Array:
									return refconfine.TypeHandsOutMutableReach(u.Elem())
								case *types.Map:
									return refconfine.TypeHandsOutMutableReach(u.Key()) || refconfine.TypeHandsOutMutableReach(u.Elem())
								}
								return true
							}
							var classifyArg func(e ast.Expr, calleeParam syntaxutil.ParamKey, callArgs []ast.Expr)
							classifyArg = func(e ast.Expr, calleeParam syntaxutil.ParamKey, callArgs []ast.Expr) {
								e = unparen(e)
								if t := p.TypesInfo.TypeOf(e); t != nil && !refconfine.TypeHandsOutMutableReach(t) {
									return
								}
								switch v := e.(type) {
								case *ast.Ident, *ast.SelectorExpr, *ast.IndexExpr, *ast.StarExpr, *ast.SliceExpr:
									if ident, ok := chainRoot(e).(*ast.Ident); ok {
										obj := p.TypesInfo.Uses[ident]
										if obj == nil {
											obj = p.TypesInfo.Defs[ident]
										}
										if obj != nil {
											_, tracked := trackedVar(obj)
											if (tracked || params[obj]) && refconfine.TypeHandsOutMutableReach(obj.Type()) {
												pendingInsertionUses = append(pendingInsertionUses, insertionUse{root: obj, calleeParam: calleeParam, args: callArgs})
											}
										}
										return
									}
									breakReachIn(e)
								case *ast.CompositeLit:
									classifyLit(v)
								case *ast.UnaryExpr:
									if v.Op == token.AND {
										if lit, ok := unparen(v.X).(*ast.CompositeLit); ok {
											classifyLit(lit)
											return
										}
										return
									}
									breakReachIn(e)
								case *ast.BasicLit, *ast.FuncLit:
								case *ast.CallExpr:
									if fnIdent, ok := unparen(v.Fun).(*ast.Ident); ok {
										if _, builtin := p.TypesInfo.Uses[fnIdent].(*types.Builtin); builtin {
											switch fnIdent.Name {
											case "make", "new":
												return
											case "append":
												for ai, a := range v.Args {
													if ai == len(v.Args)-1 && v.Ellipsis.IsValid() {
														if t := p.TypesInfo.TypeOf(a); t != nil {
															if sl, ok := types.Unalias(t).Underlying().(*types.Slice); ok && !refconfine.TypeHandsOutMutableReach(sl.Elem()) {
																continue
															}
														}
													}
													classifyArg(a, calleeParam, callArgs)
												}
												return
											}
											breakReachIn(e)
											return
										}
									}
									if tv, ok := p.TypesInfo.Types[v.Fun]; ok && tv.IsType() && len(v.Args) == 1 {
										classifyArg(v.Args[0], calleeParam, callArgs)
										return
									}
									if inner, innerPkg := syntaxutil.PlainCalleeFunc(p, v.Fun); inner != nil && auditedValuePlane[syntaxutil.FuncKey{Pkg: innerPkg, Name: inner.Name()}] {
										if !elemReach(p.TypesInfo.TypeOf(e)) {
											return
										}
									}
									breakReachIn(e)
								default:
									breakReachIn(e)
								}
							}
							for j, arg := range n.Args {
								idx := j
								if sig != nil && sig.Variadic() && sig.Params().Len() > 0 && idx >= sig.Params().Len()-1 {
									idx = sig.Params().Len() - 1
								}
								classifyArg(arg, syntaxutil.ParamKey{Func: calleeFK, Index: idx}, n.Args)
							}
						}
						return true
					}
					for _, arg := range n.Args {
						breakTargets(arg)
					}
					if sel, ok := unparen(n.Fun).(*ast.SelectorExpr); !ok || func() bool {
						selection, ok := p.TypesInfo.Selections[sel]
						return !ok || selection.Kind() != types.MethodVal
					}() {
						breakTargets(n.Fun)
					}
				}
				return true
			})
			freshObj := map[types.Object]bool{}
			var srcFresh func(e ast.Expr) bool
			srcFresh = func(e ast.Expr) bool {
				e = unparen(e)
				switch v := e.(type) {
				case *ast.CompositeLit:
					return true
				case *ast.UnaryExpr:
					return v.Op == token.AND && srcFresh(v.X)
				case *ast.CallExpr:
					if fnIdent, ok := unparen(v.Fun).(*ast.Ident); ok {
						if _, builtin := p.TypesInfo.Uses[fnIdent].(*types.Builtin); builtin {
							switch fnIdent.Name {
							case "make", "new":
								return true
							case "append":
								return len(v.Args) > 0 && srcFresh(v.Args[0])
							}
							return false
						}
					}
					if tv, ok := p.TypesInfo.Types[v.Fun]; ok && tv.IsType() && len(v.Args) == 1 {
						return srcFresh(v.Args[0])
					}
					return false
				case *ast.Ident, *ast.IndexExpr, *ast.SliceExpr, *ast.StarExpr, *ast.SelectorExpr:
					if ident, ok := chainRoot(e).(*ast.Ident); ok {
						obj := p.TypesInfo.Uses[ident]
						if obj == nil {
							obj = p.TypesInfo.Defs[ident]
						}
						return obj != nil && freshObj[obj]
					}
				}
				return false
			}
			for changed := true; changed; {
				changed = false
				for obj, srcs := range localSources {
					if freshObj[obj] || len(srcs) == 0 {
						continue
					}
					all := true
					for _, s := range srcs {
						if !srcFresh(s) {
							all = false
							break
						}
					}
					if all {
						freshObj[obj] = true
						changed = true
					}
				}
			}
			deepWrite := func(target ast.Expr, fresh bool) bool {
				var steps []ast.Expr
				e := unparen(target)
			flatten:
				for {
					switch s := e.(type) {
					case *ast.SelectorExpr:
						steps = append(steps, s)
						e = unparen(s.X)
					case *ast.IndexExpr:
						steps = append(steps, s)
						e = unparen(s.X)
					case *ast.SliceExpr:
						steps = append(steps, s)
						e = unparen(s.X)
					case *ast.StarExpr:
						steps = append(steps, s)
						e = unparen(s.X)
					default:
						break flatten
					}
				}
				selectorSeen := false
				for i := len(steps) - 1; i >= 0; i-- {
					atRoot := i == len(steps)-1
					final := i == 0
					switch st := steps[i].(type) {
					case *ast.StarExpr:
						if !atRoot || !fresh {
							return true
						}
					case *ast.SelectorExpr:
						if t := p.TypesInfo.TypeOf(st.X); t != nil {
							if _, ptr := types.Unalias(t).Underlying().(*types.Pointer); ptr {
								if !atRoot || !fresh {
									return true
								}
							}
						}
						selectorSeen = true
					case *ast.IndexExpr:
						if !final || !fresh || selectorSeen {
							return true
						}
					case *ast.SliceExpr:
						if !fresh || selectorSeen {
							return true
						}
					}
				}
				return false
			}
			for _, ps := range pendingStores {
				if deepWrite(ps.target, freshObj[ps.robj]) {
					breakIdents(ps.root, false, nil)
					insertionWrites[ps.robj] = append(insertionWrites[ps.robj], ps.source)
					linkBacking(ps.robj, ps.source)
					continue
				}
				writeSources[ps.robj] = append(writeSources[ps.robj], ps.source)
				linkBacking(ps.robj, ps.source)
			}
			for changed := true; changed; {
				changed = false
				for _, pairs := range [][][2]types.Object{aliasPairs, heldPairs} {
					for _, pair := range pairs {
						if localBroken[pair[0]] != localBroken[pair[1]] {
							localBroken[pair[0]], localBroken[pair[1]] = true, true
							changed = true
						}
						if captureBroken[pair[0]] != captureBroken[pair[1]] {
							captureBroken[pair[0]], captureBroken[pair[1]] = true, true
							changed = true
						}
					}
				}
			}
			aliasRoot := map[types.Object]types.Object{}
			var aliasFind func(types.Object) types.Object
			aliasFind = func(x types.Object) types.Object {
				r, ok := aliasRoot[x]
				if !ok || r == x {
					return x
				}
				root := aliasFind(r)
				aliasRoot[x] = root
				return root
			}
			for _, pair := range aliasPairs {
				a, b := aliasFind(pair[0]), aliasFind(pair[1])
				if a != b {
					aliasRoot[a] = b
				}
			}
			sharedWrites := map[types.Object][]ast.Expr{}
			for obj, stores := range writeSources {
				root := aliasFind(obj)
				sharedWrites[root] = append(sharedWrites[root], stores...)
			}
			sharedInsertionWrites := map[types.Object][]ast.Expr{}
			for obj, stores := range insertionWrites {
				root := aliasFind(obj)
				sharedInsertionWrites[root] = append(sharedInsertionWrites[root], stores...)
			}
			resolvedUses := map[types.Object]map[syntaxutil.EnvAuditTarget]bool{}
			usePoison := map[types.Object]bool{}
			componentMembers := map[types.Object][]types.Object{}
			memberSeen := map[types.Object]bool{}
			collectMember := func(o types.Object) {
				if !memberSeen[o] {
					memberSeen[o] = true
					componentMembers[aliasFind(o)] = append(componentMembers[aliasFind(o)], o)
				}
			}
			for _, pair := range aliasPairs {
				collectMember(pair[0])
				collectMember(pair[1])
			}
			for obj := range writeSources {
				collectMember(obj)
			}
			for obj := range params {
				collectMember(obj)
			}
			for root, ms := range componentMembers {
				if len(sharedWrites[root]) == 0 {
					continue
				}
				hasParam := false
				for _, m := range ms {
					if params[m] {
						hasParam = true
						break
					}
				}
				if hasParam {
					for _, m := range ms {
						localBroken[m] = true
					}
				}
			}
			fnDeps := map[syntaxutil.FuncKey]bool{}
			for callee := range stmtCallDeps {
				fnDeps[callee] = true
			}
			insCallDeps := map[syntaxutil.EnvAuditTarget]bool{}
			useFold := &insCallDeps
			recordFnDep := func(callee syntaxutil.FuncKey) {
				fnDeps[callee] = true
			}
			var free func(expr ast.Expr) bool
			localFree := map[types.Object]int{} // 0 unknown, 1 proving, 2 free, 3 refused
			var judgeLocal func(obj types.Object) bool
			judgeLocal = func(obj types.Object) bool {
				if usePoison[aliasFind(obj)] {
					localFree[obj] = 3
					return false
				}
				for use := range resolvedUses[aliasFind(obj)] {
					(*useFold)[use] = true
				}
				switch localFree[obj] {
				case 2:
					return true
				case 3:
					return false
				case 1:
					return true
				}
				if localBroken[obj] {
					localFree[obj] = 3
					return false
				}
				localFree[obj] = 1
				for _, src := range localSources[obj] {
					if !free(src) {
						localFree[obj] = 3
						return false
					}
				}
				for _, stored := range sharedWrites[aliasFind(obj)] {
					if !free(stored) {
						localFree[obj] = 3
						return false
					}
				}
				localFree[obj] = 2
				return true
			}
			free = func(expr ast.Expr) bool {
				e := unparen(expr)
				if t := p.TypesInfo.TypeOf(e); t != nil && !carries(t) {
					return true
				}
				switch e := e.(type) {
				case *ast.BasicLit:
					return true
				case *ast.CompositeLit:
					return syntaxutil.EachCompositeLitValue(e, free)
				case *ast.UnaryExpr:
					if e.Op == token.AND {
						return free(e.X)
					}
				case *ast.FuncLit:
					wants := map[syntaxutil.ParamKey]bool{}
					methodWants := map[syntaxutil.FuncKey]bool{}
					if !environmentFreeFuncLitJudged(audited, p, e, fd.Body, wants, methodWants) {
						return false
					}
					return wantsResolve(wants, methodWants)
				case *ast.Ident:
					obj := p.TypesInfo.Uses[e]
					switch obj := obj.(type) {
					case *types.Func:
						return true
					case *types.Nil:
						return true
					case *types.Var:
						if params[obj] {
							if localBroken[obj] {
								return false
							}
							if usePoison[aliasFind(obj)] {
								return false
							}
							for use := range resolvedUses[aliasFind(obj)] {
								(*useFold)[use] = true
							}
							return true
						}
						if obj.Parent() != nil && obj.Pkg() != nil && obj.Parent() != obj.Pkg().Scope() && !obj.IsField() {
							return judgeLocal(obj)
						}
					}
					return false
				case *ast.SelectorExpr:
					if selection, ok := p.TypesInfo.Selections[e]; ok {
						switch selection.Kind() {
						case types.MethodExpr:
							return true
						case types.MethodVal:
							return false
						}
						return free(e.X)
					}
					if obj, ok := p.TypesInfo.Uses[e.Sel]; ok {
						if _, isFunc := obj.(*types.Func); isFunc {
							return true
						}
					}
					return false
				case *ast.IndexExpr:
					switch x := unparen(e.X).(type) {
					case *ast.Ident:
						if _, isFunc := p.TypesInfo.Uses[x].(*types.Func); isFunc {
							return true
						}
					case *ast.SelectorExpr:
						if _, isFunc := p.TypesInfo.Uses[x.Sel].(*types.Func); isFunc {
							return true
						}
					}
					if t := p.TypesInfo.TypeOf(e.X); t != nil {
						switch u := types.Unalias(t).Underlying().(type) {
						case *types.Map, *types.Slice, *types.Array, *types.Basic:
							return free(e.X)
						case *types.Pointer:
							if _, isArr := types.Unalias(u.Elem()).Underlying().(*types.Array); isArr {
								return free(e.X)
							}
						}
					}
					return false
				case *ast.IndexListExpr:
					switch x := unparen(e.X).(type) {
					case *ast.Ident:
						if _, isFunc := p.TypesInfo.Uses[x].(*types.Func); isFunc {
							return true
						}
					case *ast.SelectorExpr:
						if _, isFunc := p.TypesInfo.Uses[x.Sel].(*types.Func); isFunc {
							return true
						}
					}
					return false
				case *ast.CallExpr:
					if ident, ok := unparen(e.Fun).(*ast.Ident); ok {
						if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
							switch ident.Name {
							case "make", "new":
								return true
							case "append":
								for _, arg := range e.Args {
									if !free(arg) {
										return false
									}
								}
								return true
							}
							return false
						}
					}
					if tv, ok := p.TypesInfo.Types[e.Fun]; ok && tv.IsType() {
						return len(e.Args) == 1 && free(e.Args[0])
					}
					if fn, pkgPath := syntaxutil.PlainCalleeFunc(p, e.Fun); fn != nil {
						for _, arg := range e.Args {
							if !free(arg) {
								return false
							}
						}
						calleeFK := syntaxutil.FuncKey{Pkg: pkgPath, Name: fn.Name()}
						if auditedValuePlane[calleeFK] {
							return true
						}
						recordFnDep(calleeFK)
						return true
					}
					return false
				}
				return false
			}
			resolveUses := func(record bool) bool {
				changed := false
				for _, use := range pendingInsertionUses {
					root := aliasFind(use.root)
					if usePoison[root] {
						continue
					}
					allFree := true
					for _, a := range use.args {
						if !free(a) {
							allFree = false
							break
						}
					}
					if !allFree {
						usePoison[root] = true
						changed = true
						continue
					}
					if record {
						if resolvedUses[root] == nil {
							resolvedUses[root] = map[syntaxutil.EnvAuditTarget]bool{}
						}
						resolvedUses[root][syntaxutil.ParamAuditTarget(use.calleeParam)] = true
					}
				}
				return changed
			}
			propagateUses := func() bool {
				changed := false
				for _, pairs := range [][][2]types.Object{aliasPairs, heldPairs} {
					for _, pair := range pairs {
						a, b := aliasFind(pair[0]), aliasFind(pair[1])
						if a == b {
							continue
						}
						if usePoison[a] != usePoison[b] {
							usePoison[a], usePoison[b] = true, true
							changed = true
						}
						for use := range resolvedUses[a] {
							if !resolvedUses[b][use] {
								if resolvedUses[b] == nil {
									resolvedUses[b] = map[syntaxutil.EnvAuditTarget]bool{}
								}
								resolvedUses[b][use] = true
								changed = true
							}
						}
						for use := range resolvedUses[b] {
							if !resolvedUses[a][use] {
								if resolvedUses[a] == nil {
									resolvedUses[a] = map[syntaxutil.EnvAuditTarget]bool{}
								}
								resolvedUses[a][use] = true
								changed = true
							}
						}
					}
				}
				return changed
			}
			scratchFnDeps := map[syntaxutil.FuncKey]bool{}
			scratchUseDeps := map[syntaxutil.EnvAuditTarget]bool{}
			savedRecordFnDep, savedFold := recordFnDep, useFold
			recordFnDep = func(callee syntaxutil.FuncKey) { scratchFnDeps[callee] = true }
			useFold = &scratchUseDeps
			for {
				changed := resolveUses(false)
				if propagateUses() {
					changed = true
				}
				if !changed {
					break
				}
				for k := range localFree {
					delete(localFree, k)
				}
			}
			recordFnDep, useFold = savedRecordFnDep, savedFold
			for k := range localFree {
				delete(localFree, k)
			}
			resolveUses(true)
			for propagateUses() {
			}
			for k := range localFree {
				delete(localFree, k)
			}
			for obj, idx := range paramIndex {
				key := syntaxutil.ParamKey{Func: ownFuncKey, Index: idx}
				root := aliasFind(obj)
				if captureBroken[obj] || usePoison[root] {
					continue
				}
				collected := map[syntaxutil.EnvAuditTarget]bool{}
				savedRec, savedFold := recordFnDep, useFold
				recordFnDep = func(callee syntaxutil.FuncKey) { collected[syntaxutil.FuncAuditTarget(callee)] = true }
				useFold = &collected
				okIns := true
				for _, stored := range append(append([]ast.Expr{}, sharedWrites[root]...), sharedInsertionWrites[root]...) {
					if ident, isIdent := unparen(stored).(*ast.Ident); isIdent {
						if sobj := p.TypesInfo.Uses[ident]; sobj != nil && params[sobj] &&
							!localBroken[sobj] && !captureBroken[sobj] {
							continue
						}
					}
					if !free(stored) {
						okIns = false
						break
					}
				}
				recordFnDep, useFold = savedRec, savedFold
				if !okIns {
					continue
				}
				for use := range resolvedUses[root] {
					collected[use] = true
				}
				insFree[key] = true
				if len(collected) > 0 {
					insDeps[key] = collected
				}
			}
			if hooks != nil && hooks.Refusal != nil {
				inner := free
				free = func(e ast.Expr) bool {
					r := inner(e)
					if !r {
						clause := "an unrecognized return shape"
						switch e := unparen(e).(type) {
						case *ast.Ident:
							obj := p.TypesInfo.Uses[e]
							if obj == nil {
								obj = p.TypesInfo.Defs[e]
							}
							switch {
							case obj != nil && localBroken[obj]:
								clause = "write or capture broke the binding"
							case obj != nil && usePoison[aliasFind(obj)]:
								clause = "an unjudgeable argument to a deferring call poisoned the storage"
							case obj != nil && len(sharedWrites[aliasFind(obj)]) > 0:
								clause = "a stored value refused"
							default:
								clause = "a binding source refused"
							}
						case *ast.CallExpr:
							clause = "callee outside the audited set and dependency channel"
						case *ast.CompositeLit:
							clause = "a literal element refused"
						case *ast.SelectorExpr, *ast.IndexExpr, *ast.SliceExpr:
							clause = "an unadmitted derivation shape"
						}
						syntaxutil.ExplainRefusalMark(hooks, p, fd.Name.Name, e, clause)
					}
					return r
				}
			}
			ok = true
			results := 0
			if fd.Type.Results != nil {
				results = fd.Type.Results.NumFields()
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if !ok {
					return false
				}
				if _, isLit := n.(*ast.FuncLit); isLit {
					return false
				}
				ret, isRet := n.(*ast.ReturnStmt)
				if !isRet {
					return true
				}
				if len(ret.Results) == 0 && results > 0 {
					ok = false
					return false
				}
				for _, result := range ret.Results {
					if !free(result) {
						ok = false
						return false
					}
				}
				return true
			})
			if !ok {
				continue
			}
			proven[fnKey] = true
			if len(fnDeps) > 0 {
				deps[fnKey] = fnDeps
			}
			if len(insCallDeps) > 0 {
				callerInsDeps[fnKey] = insCallDeps
			}
			recordReturnFieldRegistrants(audited, p, fnKey, fd.Body, retDefer, retPoison)
		}
	}
	return proven, deps, retDefer, retPoison, insFree, insDeps, callerInsDeps
}

func recordReturnFieldRegistrants(
	audited bool,
	p *packages.Package,
	fnKey string,
	body ast.Node,
	retDefer map[string]map[syntaxutil.ReturnFieldParamDefer]bool,
	retPoison map[string]map[syntaxutil.ReturnFieldParamPoison]bool,
) {
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
	fieldWrite := func(lhs, rhs ast.Expr) {
		if sel, ok := syntaxutil.UnparenExpr(lhs).(*ast.SelectorExpr); ok {
			if selection, ok := p.TypesInfo.Selections[sel]; ok && selection.Kind() == types.FieldVal {
				if _, isSig := types.Unalias(selection.Type()).Underlying().(*types.Signature); isSig {
					classifyFieldRegistrantValue(audited, p, sel.Sel.Name, rhs, emit)
				}
			}
		}
	}
	funPositions := map[ast.Node]bool{}
	writePositions := map[ast.Node]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
		funLoop:
			for cur := syntaxutil.UnparenExpr(n.Fun); ; {
				funPositions[cur] = true
				switch x := cur.(type) {
				case *ast.IndexExpr:
					cur = syntaxutil.UnparenExpr(x.X)
				case *ast.IndexListExpr:
					cur = syntaxutil.UnparenExpr(x.X)
				case *ast.SelectorExpr:
					funPositions[x.Sel] = true
					break funLoop
				default:
					break funLoop
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range n.Lhs {
				writePositions[syntaxutil.UnparenExpr(lhs)] = true
			}
		case *ast.IncDecStmt:
			writePositions[syntaxutil.UnparenExpr(n.X)] = true
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			classifyRegistrantComposite(audited, p, n, emit)
			return false
		case *ast.AssignStmt:
			if len(n.Lhs) == len(n.Rhs) {
				for i, lhs := range n.Lhs {
					fieldWrite(lhs, n.Rhs[i])
				}
			} else if len(n.Rhs) == 1 {
				for _, lhs := range n.Lhs {
					fieldWrite(lhs, n.Rhs[0])
				}
			}
		case *ast.FuncLit:
			if !funPositions[n] {
				classifyLiteralRegistrant(audited, p, syntaxutil.ElemPositionField, n, emit)
			}
		case *ast.CallExpr:
			if tv, ok := p.TypesInfo.Types[n.Fun]; ok && tv.IsType() {
				break
			}
			if ident, ok := syntaxutil.UnparenExpr(n.Fun).(*ast.Ident); ok {
				if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
					break
				}
			}
			if fn, _ := syntaxutil.PlainCalleeFunc(p, n.Fun); fn != nil {
				break
			}
			if refconfine.TypeCarriesSignature(p.TypesInfo.TypeOf(n)) {
				emit(fieldRegMark{class: 'p', field: syntaxutil.ElemPositionField, idx: -1})
			}
		case *ast.SelectorExpr:
			if funPositions[n] || writePositions[n] {
				break
			}
			if _, isFunc := p.TypesInfo.Uses[n.Sel].(*types.Func); isFunc {
				classifyFieldRegistrantValue(audited, p, syntaxutil.ElemPositionField, n, emit)
				break
			}
			if refconfine.TypeCarriesSignature(p.TypesInfo.TypeOf(n)) {
				emit(fieldRegMark{class: 'p', field: syntaxutil.ElemPositionField, idx: -1})
			}
		case *ast.IndexExpr, *ast.IndexListExpr:
			expr := n.(ast.Expr)
			if funPositions[n] || writePositions[n] {
				break
			}
			if fn, _ := syntaxutil.PlainCalleeFunc(p, expr); fn != nil {
				classifyFieldRegistrantValue(audited, p, syntaxutil.ElemPositionField, expr, emit)
				break
			}
			if refconfine.TypeCarriesSignature(p.TypesInfo.TypeOf(expr)) {
				emit(fieldRegMark{class: 'p', field: syntaxutil.ElemPositionField, idx: -1})
			}
		case *ast.Ident:
			if funPositions[n] {
				break
			}
			if _, isFunc := p.TypesInfo.Uses[n].(*types.Func); isFunc {
				classifyFieldRegistrantValue(audited, p, syntaxutil.ElemPositionField, n, emit)
				break
			}
			if v, ok := p.TypesInfo.Uses[n].(*types.Var); ok && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() && refconfine.TypeCarriesSignature(v.Type()) {
				emit(fieldRegMark{class: 'p', idx: -1})
			}
		}
		return true
	})
}
