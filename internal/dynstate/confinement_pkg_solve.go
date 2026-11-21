package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type packageConfinementSummary struct {
	readOnly          map[string]bool
	condReadOnly      map[string]bool
	readOnlyDeps      map[string]map[syntaxutil.FuncKey]bool
	readOnlyParamDeps map[string]map[syntaxutil.ParamKey]bool
	retentionMethods  map[string]bool
	paramLeakFree     map[syntaxutil.ParamKey]bool
	condParam         map[syntaxutil.ParamKey]bool
	paramDeps         map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool
	paramMethodDeps   map[syntaxutil.ParamKey]map[syntaxutil.FuncKey]bool
	paramRetention    map[syntaxutil.ParamKey]bool
	paramRetDeps      map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool
}

func (c *packageConfinementSummary) classifyParam(ownPath string, pk syntaxutil.ParamKey) (provenLocal, conditional bool) {
	if c == nil || !pk.Valid() {
		return false, false
	}
	if pk.Func.Pkg != ownPath {
		return false, true
	}
	if c.paramLeakFree[pk] {
		return true, false
	}
	if c.condParam[pk] {
		return false, true
	}
	return false, false
}

func (c *packageConfinementSummary) classifyMethod(ownPath string, mk syntaxutil.FuncKey) (provenLocal, conditional bool) {
	if c == nil || !mk.Valid() || mk.Pkg == "sync" {
		return false, false
	}
	if mk.Pkg != ownPath {
		return false, true
	}
	if c.readOnly[mk.Name] {
		return true, false
	}
	if c.condReadOnly[mk.Name] {
		return false, true
	}
	return false, false
}

func (c *packageConfinementSummary) resolveWants(
	ownPath string,
	wants map[syntaxutil.ParamKey]bool,
	methodWants map[syntaxutil.FuncKey]bool,
	paramOut map[syntaxutil.ParamKey]bool,
	methodOut map[syntaxutil.FuncKey]bool,
) bool {
	for want := range wants {
		provenLocal, conditional := c.classifyParam(ownPath, want)
		if !provenLocal && (!conditional || paramOut == nil) {
			return false
		}
	}
	for want := range methodWants {
		provenLocal, conditional := c.classifyMethod(ownPath, want)
		if !provenLocal && (!conditional || methodOut == nil) {
			return false
		}
	}
	for want := range wants {
		if provenLocal, _ := c.classifyParam(ownPath, want); !provenLocal {
			paramOut[want] = true
		}
	}
	for want := range methodWants {
		if provenLocal, _ := c.classifyMethod(ownPath, want); !provenLocal {
			methodOut[want] = true
		}
	}
	return true
}

func resolveLocalParamDeps(ownPath string, proven map[syntaxutil.ParamKey]bool, allWants map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool, satisfied func(syntaxutil.ParamKey) bool) map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool {
	conditional := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	for key, wants := range allWants {
		crossPackage := false
		for want := range wants {
			if want.Func.Pkg != ownPath {
				crossPackage = true
				break
			}
		}
		if !crossPackage {
			conditional[key] = wants
		}
	}
	syntaxutil.SolveLeastFixedPoint(proven, conditional, satisfied)
	return syntaxutil.PruneUnsatisfiedDeps(allWants, satisfied, satisfied)
}

func receiverRetentionFreeMethods(audited bool, p *packages.Package, fc *pkgFlowCache, readOnlyLocal map[string]bool) map[string]bool {
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	proven := map[string]bool{}
	pending := map[string]map[string]bool{}
	ownPath := ""
	if p.Types != nil {
		ownPath = p.Types.Path()
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Name == nil || fd.Body == nil || len(fd.Recv.List) != 1 {
				continue
			}
			recvName := syntaxutil.RecvTypeName(fd)
			if recvName == "" {
				continue
			}
			key := recvName + "." + fd.Name.Name
			if readOnlyLocal[key] {
				proven[key] = true
				continue
			}
			var recvIdent *ast.Ident
			if names := fd.Recv.List[0].Names; len(names) == 1 && names[0].Name != "_" {
				recvIdent = names[0]
			}
			if recvIdent == nil {
				if recvField := fd.Recv.List[0]; recvField != nil && refconfine.TypeReachesSyncNoCopyByValue(p.TypesInfo.TypeOf(recvField.Type)) {
					continue
				}
				proven[key] = true
				continue
			}
			recvObj := p.TypesInfo.Defs[recvIdent]
			if recvObj == nil {
				continue
			}
			wants := map[syntaxutil.ParamKey]bool{}
			methodWants := map[syntaxutil.FuncKey]bool{}
			if !boundValueRetentionFreeJudged(audited, p, fc, map[types.Object]bool{recvObj: true}, fd.Body, wants, methodWants) {
				continue
			}
			if len(wants) != 0 {
				continue
			}
			needs := map[string]bool{}
			sound := true
			for want := range methodWants {
				if want.Pkg != ownPath {
					sound = false
					break
				}
				if !readOnlyLocal[want.Name] {
					needs[want.Name] = true
				}
			}
			if !sound {
				continue
			}
			if len(needs) == 0 {
				proven[key] = true
				continue
			}
			pending[key] = needs
		}
	}
	syntaxutil.SolveLeastFixedPoint(proven, pending, func(need string) bool {
		return proven[need] || readOnlyLocal[need]
	})
	return proven
}

func closedInterfaceFields(p *packages.Package, callIdx *refconfine.CallSiteIndex) map[*types.Var][]string {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return nil
	}
	info := p.TypesInfo
	candidateField := func(field *types.Var) bool {
		if field == nil || !field.IsField() || field.Exported() || field.Pkg() != p.Types {
			return false
		}
		_, isIface := types.Unalias(field.Type()).Underlying().(*types.Interface)
		return isIface
	}
	any := false
	for _, name := range p.Types.Scope().Names() {
		typeName, ok := p.Types.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		st, ok := typeName.Type().Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := 0; i < st.NumFields() && !any; i++ {
			any = candidateField(st.Field(i))
		}
	}
	if !any {
		return nil
	}
	if callIdx == nil {
		callIdx = refconfine.BuildCallSiteIndex(p)
	}
	memberTypes := func(expr ast.Expr) ([]string, bool) {
		var members []string
		ok := callIdx.JudgeExpr(expr, func(t types.Type) (bool, bool) {
			if _, isIface := types.Unalias(t).Underlying().(*types.Interface); isIface {
				return false, false
			}
			concrete := types.Unalias(t)
			if ptr, ok := concrete.(*types.Pointer); ok {
				concrete = types.Unalias(ptr.Elem())
			}
			named, ok := concrete.(*types.Named)
			if !ok || named.Obj() == nil || named.Obj().Pkg() != p.Types {
				return true, false
			}
			members = append(members, named.Obj().Name())
			return true, true
		})
		return members, ok
	}
	fieldOf := func(structType types.Type, index int) *types.Var {
		if ptr, ok := types.Unalias(structType).(*types.Pointer); ok {
			structType = ptr.Elem()
		}
		st, ok := types.Unalias(structType).Underlying().(*types.Struct)
		if !ok || index < 0 || index >= st.NumFields() {
			return nil
		}
		if field := st.Field(index); candidateField(field) {
			return field
		}
		return nil
	}
	members := map[*types.Var][]string{}
	open := map[*types.Var]bool{}
	store := func(field *types.Var, value ast.Expr) {
		if !candidateField(field) || open[field] {
			return
		}
		more, ok := memberTypes(value)
		if !ok {
			open[field] = true
			delete(members, field)
			return
		}
		members[field] = append(members[field], more...)
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CompositeLit:
				t := info.TypeOf(n)
				if t == nil {
					return true
				}
				if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
					t = ptr.Elem()
				}
				for i, elt := range n.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						if key, ok := ast.Unparen(kv.Key).(*ast.Ident); ok {
							if field, ok := info.Uses[key].(*types.Var); ok {
								store(field, kv.Value)
							}
						}
						continue
					}
					store(fieldOf(t, i), elt)
				}
			case *ast.AssignStmt:
				if len(n.Lhs) != len(n.Rhs) {
					for _, lhs := range n.Lhs {
						if sel, ok := ast.Unparen(lhs).(*ast.SelectorExpr); ok {
							if selection, ok := info.Selections[sel]; ok && selection.Kind() == types.FieldVal {
								if field, ok := selection.Obj().(*types.Var); ok {
									open[field] = true
									delete(members, field)
								}
							}
						}
					}
					return true
				}
				for i, lhs := range n.Lhs {
					sel, ok := ast.Unparen(lhs).(*ast.SelectorExpr)
					if !ok {
						continue
					}
					selection, ok := info.Selections[sel]
					if !ok || selection.Kind() != types.FieldVal {
						continue
					}
					if field, ok := selection.Obj().(*types.Var); ok {
						store(field, n.Rhs[i])
					}
				}
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					if sel, ok := ast.Unparen(n.X).(*ast.SelectorExpr); ok {
						if selection, ok := info.Selections[sel]; ok && selection.Kind() == types.FieldVal {
							if field, ok := selection.Obj().(*types.Var); ok {
								open[field] = true
								delete(members, field)
							}
						}
					}
				}
			case *ast.CallExpr:
				tv, ok := info.Types[ast.Unparen(n.Fun)]
				if !ok || !tv.IsType() || len(n.Args) != 1 {
					return true
				}
				to := info.TypeOf(n)
				if to == nil {
					return true
				}
				if ptr, ok := types.Unalias(to).(*types.Pointer); ok {
					to = ptr.Elem()
				}
				st, ok := types.Unalias(to).Underlying().(*types.Struct)
				if !ok || types.Identical(info.TypeOf(n.Args[0]), to) {
					return true
				}
				for i := 0; i < st.NumFields(); i++ {
					if field := fieldOf(to, i); field != nil {
						open[field] = true
						delete(members, field)
					}
				}
			}
			return true
		})
	}
	closed := map[*types.Var][]string{}
	for field, names := range members {
		if open[field] || len(names) == 0 {
			continue
		}
		sort.Strings(names)
		closed[field] = slices.Compact(names)
	}
	return closed
}

func closedFieldDispatchTargets(info *types.Info, recvObj types.Object, sel *ast.SelectorExpr, name string, closed map[*types.Var][]string, declared map[string]bool) ([]string, bool) {
	fieldSel, ok := ast.Unparen(sel.X).(*ast.SelectorExpr)
	if !ok {
		return nil, false
	}
	ident, ok := ast.Unparen(fieldSel.X).(*ast.Ident)
	if !ok || info.Uses[ident] != recvObj {
		return nil, false
	}
	selection, ok := info.Selections[fieldSel]
	if !ok || selection.Kind() != types.FieldVal || len(selection.Index()) != 1 {
		return nil, false
	}
	field, ok := selection.Obj().(*types.Var)
	if !ok {
		return nil, false
	}
	members, ok := closed[field]
	if !ok {
		return nil, false
	}
	targets := make([]string, 0, len(members))
	for _, member := range members {
		target := member + "." + name
		if !declared[target] {
			return nil, false
		}
		targets = append(targets, target)
	}
	return targets, true
}

func unexportedDispatchTargets(p *packages.Package, selection *types.Selection, fn *types.Func, declaredByName map[string][]string, bodyless map[string]bool) ([]string, bool) {
	if p.Types == nil || fn.Exported() || fn.Pkg() != p.Types || selection.Recv() == nil || bodyless[fn.Name()] {
		return nil, false
	}
	recv := types.Unalias(selection.Recv())
	if ptr, ok := recv.(*types.Pointer); ok {
		recv = types.Unalias(ptr.Elem())
	}
	if _, ok := recv.Underlying().(*types.Interface); !ok {
		return nil, false
	}
	targets := append([]string(nil), declaredByName[fn.Name()]...)
	return targets, len(targets) > 0
}

func solvePackageConfinement(audited bool, p *packages.Package, fc *pkgFlowCache, callIdx *refconfine.CallSiteIndex) packageConfinementSummary {
	var out packageConfinementSummary
	if p == nil || p.TypesInfo == nil {
		return out
	}
	ownPath := ""
	if p.Types != nil {
		ownPath = p.Types.Path()
	}

	methods := map[string]methodBodyEntry{}
	bodyless := map[string]bool{}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if ok && fd.Recv != nil && fd.Name != nil && fd.Body == nil {
				bodyless[fd.Name.Name] = true
			}
			if !ok || fd.Recv == nil || fd.Name == nil || fd.Body == nil || len(fd.Recv.List) != 1 {
				continue
			}
			recvName := syntaxutil.RecvTypeName(fd)
			if recvName == "" {
				continue
			}
			var recvIdent *ast.Ident
			if names := fd.Recv.List[0].Names; len(names) == 1 && names[0].Name != "_" {
				recvIdent = names[0]
			}
			methods[recvName+"."+fd.Name.Name] = methodBodyEntry{decl: fd, recv: recvIdent}
		}
	}

	disqualified := map[string]bool{}
	chains := map[string]map[string]bool{}
	mParamWants := map[string]map[syntaxutil.ParamKey]bool{}
	mForeignMethodWants := map[string]map[syntaxutil.FuncKey]bool{}

	if len(methods) > 0 {
		onceSites, fieldRefIdents, disqualifiedOnceFields, aliasedInitOnceFields := collectPackageOnceFieldUsage(audited, p, fc)
		declaredByName := map[string][]string{}
		declared := map[string]bool{}
		for key := range methods {
			declared[key] = true
			if dot := strings.LastIndex(key, "."); dot >= 0 {
				declaredByName[key[dot+1:]] = append(declaredByName[key[dot+1:]], key)
			}
		}
		closedFields := closedInterfaceFields(p, callIdx)
		for _, keys := range declaredByName {
			sort.Strings(keys)
		}
		for key, m := range methods {
			if m.recv == nil {
				if recvField := m.decl.Recv.List[0]; recvField != nil && refconfine.TypeReachesSyncNoCopyByValue(p.TypesInfo.TypeOf(recvField.Type)) {
					disqualified[key] = true
				}
				continue
			}
			recvObj := p.TypesInfo.Defs[m.recv]
			if recvObj == nil || refconfine.TypeReachesSyncNoCopyByValue(recvObj.Type()) {
				disqualified[key] = true
				continue
			}
			lowered := fc.funcBody(p, m.decl)
			if lowered == nil {
				disqualified[key] = true
				continue
			}
			admittedOnceDo := findAdmittedReceiverOnceDo(audited, p, fc, m.decl, lowered, recvObj, onceSites, fieldRefIdents, disqualifiedOnceFields, aliasedInitOnceFields)
			wants := map[syntaxutil.ParamKey]bool{}
			methodWants := map[syntaxutil.FuncKey]bool{}
			eng := &confinementEngine{
				mode:           confinementModeReceiver,
				audited:        audited,
				p:              p,
				fc:             fc,
				rootBody:       lowered,
				roots:          map[types.Object]bool{recvObj: true},
				tainted:        map[types.Object]bool{},
				wants:          wants,
				methodWants:    methodWants,
				recvObj:        recvObj,
				methods:        methods,
				declared:       declared,
				declaredByName: declaredByName,
				bodyless:       bodyless,
				closedFields:   closedFields,
				admittedOnceDo: admittedOnceDo,
				recordMethodChain: func(target string) {
					if chains[key] == nil {
						chains[key] = map[string]bool{}
					}
					chains[key][target] = true
				},
			}
			if !eng.run() {
				disqualified[key] = true
				continue
			}
			if len(wants) > 0 {
				mParamWants[key] = wants
			}
			if len(methodWants) > 0 {
				mForeignMethodWants[key] = methodWants
			}
		}
		syntaxutil.SolveReachFixedPoint(disqualified, chains, func(d string) bool { return disqualified[d] })
		for changed := true; changed; {
			changed = false
			for caller, targets := range chains {
				if disqualified[caller] {
					continue
				}
				for callee := range targets {
					if disqualified[callee] {
						continue
					}
					for pk := range mParamWants[callee] {
						if mParamWants[caller] == nil {
							mParamWants[caller] = map[syntaxutil.ParamKey]bool{}
						}
						if !mParamWants[caller][pk] {
							mParamWants[caller][pk] = true
							changed = true
						}
					}
					for fk := range mForeignMethodWants[callee] {
						if mForeignMethodWants[caller] == nil {
							mForeignMethodWants[caller] = map[syntaxutil.FuncKey]bool{}
						}
						if !mForeignMethodWants[caller][fk] {
							mForeignMethodWants[caller][fk] = true
							changed = true
						}
					}
				}
			}
		}
	}

	type retainCandidate struct {
		obj  types.Object
		body ast.Node
		key  syntaxutil.ParamKey
	}
	var retainInputs []retainCandidate
	paramProven := map[syntaxutil.ParamKey]bool{}
	pCandidate := map[syntaxutil.ParamKey]bool{}
	pParamWants := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	pMethodWants := map[syntaxutil.ParamKey]map[syntaxutil.FuncKey]bool{}

	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name == nil || fd.Body == nil || fd.Type.Params == nil {
				continue
			}
			ownFunc := syntaxutil.FuncKey{Pkg: ownPath, Name: fd.Name.Name}
			index := 0
			for _, field := range fd.Type.Params.List {
				names := field.Names
				if len(names) == 0 {
					names = []*ast.Ident{nil}
				}
				for _, name := range names {
					idx := index
					index++
					key := syntaxutil.ParamKey{Func: ownFunc, Index: idx}
					if name == nil || name.Name == "_" {
						paramProven[key] = true
						continue
					}
					obj := p.TypesInfo.Defs[name]
					if obj == nil || (!refconfine.TypeHandsOutMutableReach(obj.Type()) && !syntaxutil.ContainsUintptr(obj.Type())) {
						continue
					}
					retainInputs = append(retainInputs, retainCandidate{obj: obj, body: fd.Body, key: key})
					wants := map[syntaxutil.ParamKey]bool{}
					methodWants := map[syntaxutil.FuncKey]bool{}
					if !boundValueLeakFreeJudged(audited, p, fc, map[types.Object]bool{obj: true}, fd.Body, wants, nil, methodWants, nil, nil) {
						continue
					}
					pCandidate[key] = true
					if len(wants) > 0 {
						pParamWants[key] = wants
					}
					if len(methodWants) > 0 {
						pMethodWants[key] = methodWants
					}
				}
			}
		}
	}

	readOnlyLocal := map[string]bool{}
	for key := range methods {
		if !disqualified[key] && len(mParamWants[key]) == 0 && len(mForeignMethodWants[key]) == 0 {
			readOnlyLocal[key] = true
		}
	}
	for key := range pCandidate {
		if len(pParamWants[key]) == 0 && len(pMethodWants[key]) == 0 {
			paramProven[key] = true
		}
	}

	// Solve intra-package (readOnlyLocal, paramProven) jointly to a single
	// least fixed point so mutual recursion across Param <-> Method refuses
	// while acyclic intra-package chains prove unconditionally at fact time.
	methodCandidates := make(map[string]bool, len(methods))
	for key := range methods {
		if !disqualified[key] && len(mForeignMethodWants[key]) == 0 {
			methodCandidates[key] = true
		}
	}
	syntaxutil.SolveBipartiteLFP(
		readOnlyLocal,
		methodCandidates,
		func(key string) bool {
			for pk := range mParamWants[key] {
				if !paramProven[pk] {
					return false
				}
			}
			return true
		},
		paramProven,
		pCandidate,
		func(key syntaxutil.ParamKey) bool {
			for pk := range pParamWants[key] {
				if !paramProven[pk] {
					return false
				}
			}
			for mk := range pMethodWants[key] {
				if mk.Pkg != ownPath || !readOnlyLocal[mk.Name] {
					return false
				}
			}
			return true
		},
	)

	// Prune methods whose intra-package parameter prerequisites failed
	// outright (so dead intra-package method candidates emit no spurious
	// conditional edges), while retaining unsatisfied ParamDepEdges for
	// explain chain traversal.
	for changed := true; changed; {
		changed = false
		for key := range methods {
			if disqualified[key] || readOnlyLocal[key] {
				continue
			}
			for callee := range chains[key] {
				if disqualified[callee] {
					disqualified[key] = true
					changed = true
					break
				}
			}
			if disqualified[key] {
				continue
			}
			for pk := range mParamWants[key] {
				if pk.Func.Pkg == ownPath && !paramProven[pk] && !pCandidate[pk] {
					disqualified[key] = true
					changed = true
					break
				}
			}
		}
		for key := range pCandidate {
			if paramProven[key] {
				continue
			}
			for mk := range pMethodWants[key] {
				if mk.Pkg == ownPath {
					if _, exists := methods[mk.Name]; !exists || disqualified[mk.Name] {
						delete(pCandidate, key)
						changed = true
						break
					}
				}
			}
		}
	}

	readOnlyDeps := map[string]map[syntaxutil.FuncKey]bool{}
	readOnlyParamDeps := map[string]map[syntaxutil.ParamKey]bool{}
	for key := range methods {
		if disqualified[key] || readOnlyLocal[key] {
			continue
		}
		for fk := range mForeignMethodWants[key] {
			if readOnlyDeps[key] == nil {
				readOnlyDeps[key] = map[syntaxutil.FuncKey]bool{}
			}
			readOnlyDeps[key][fk] = true
		}
		for pk := range mParamWants[key] {
			if !paramProven[pk] {
				if readOnlyParamDeps[key] == nil {
					readOnlyParamDeps[key] = map[syntaxutil.ParamKey]bool{}
				}
				readOnlyParamDeps[key][pk] = true
			}
		}
	}

	paramDeps := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	paramMethodDeps := map[syntaxutil.ParamKey]map[syntaxutil.FuncKey]bool{}
	for key := range pCandidate {
		if paramProven[key] {
			continue
		}
		for pk := range pParamWants[key] {
			if !paramProven[pk] {
				if paramDeps[key] == nil {
					paramDeps[key] = map[syntaxutil.ParamKey]bool{}
				}
				paramDeps[key][pk] = true
			}
		}
		for mk := range pMethodWants[key] {
			if mk.Pkg != ownPath || !readOnlyLocal[mk.Name] {
				if paramMethodDeps[key] == nil {
					paramMethodDeps[key] = map[syntaxutil.FuncKey]bool{}
				}
				paramMethodDeps[key][mk] = true
			}
		}
	}
	// Preserve unsatisfied intra-package parameter edges even when a same-package
	// method prerequisite failed, matching legacy explain chain behavior for
	// pure parameter-to-parameter chains.
	for _, rc := range retainInputs {
		if paramProven[rc.key] || pCandidate[rc.key] {
			continue
		}
		if len(pMethodWants[rc.key]) == 0 && len(pParamWants[rc.key]) > 0 {
			for pk := range pParamWants[rc.key] {
				if !paramProven[pk] {
					if paramDeps[rc.key] == nil {
						paramDeps[rc.key] = map[syntaxutil.ParamKey]bool{}
					}
					paramDeps[rc.key][pk] = true
				}
			}
		}
	}

	retentionMethods := receiverRetentionFreeMethods(audited, p, fc, readOnlyLocal)
	paramRetention := map[syntaxutil.ParamKey]bool{}
	allRetentionWants := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	for _, rc := range retainInputs {
		if paramProven[rc.key] {
			continue
		}
		wants := map[syntaxutil.ParamKey]bool{}
		methodWants := map[syntaxutil.FuncKey]bool{}
		if !boundValueRetentionFreeJudged(audited, p, fc, map[types.Object]bool{rc.obj: true}, rc.body, wants, methodWants) {
			continue
		}
		ok := true
		for want := range methodWants {
			if want.Pkg != ownPath || (!retentionMethods[want.Name] && !readOnlyLocal[want.Name]) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if len(wants) == 0 {
			paramRetention[rc.key] = true
			continue
		}
		allRetentionWants[rc.key] = wants
	}
	paramRetDeps := resolveLocalParamDeps(ownPath, paramRetention, allRetentionWants, func(need syntaxutil.ParamKey) bool {
		return paramRetention[need] || paramProven[need]
	})
	for key := range paramProven {
		delete(paramRetDeps, key)
	}

	condReadOnly := map[string]bool{}
	for k := range readOnlyLocal {
		condReadOnly[k] = true
	}
	condParam := map[syntaxutil.ParamKey]bool{}
	for k := range paramProven {
		condParam[k] = true
	}
	condMethodCandidates := make(map[string]bool, len(methods))
	for key := range methods {
		if !disqualified[key] {
			condMethodCandidates[key] = true
		}
	}
	syntaxutil.SolveBipartiteLFP(
		condReadOnly,
		condMethodCandidates,
		func(key string) bool {
			for fk := range mForeignMethodWants[key] {
				if fk.Pkg == ownPath && !condReadOnly[fk.Name] {
					return false
				}
			}
			for pk := range mParamWants[key] {
				if pk.Func.Pkg == ownPath && !condParam[pk] {
					return false
				}
			}
			return true
		},
		condParam,
		pCandidate,
		func(key syntaxutil.ParamKey) bool {
			for pk := range pParamWants[key] {
				if pk.Func.Pkg == ownPath && !condParam[pk] {
					return false
				}
			}
			for mk := range pMethodWants[key] {
				if mk.Pkg == ownPath && !condReadOnly[mk.Name] {
					return false
				}
			}
			return true
		},
	)

	out.readOnly = readOnlyLocal
	out.condReadOnly = condReadOnly
	out.readOnlyDeps = readOnlyDeps
	out.readOnlyParamDeps = readOnlyParamDeps
	out.retentionMethods = retentionMethods
	out.paramLeakFree = paramProven
	out.condParam = condParam
	out.paramDeps = paramDeps
	out.paramMethodDeps = paramMethodDeps
	out.paramRetention = paramRetention
	out.paramRetDeps = paramRetDeps
	return out
}
