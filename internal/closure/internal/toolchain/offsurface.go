package toolchain

import (
	"go/ast"
	"go/token"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/internal/closure/internal/cprep"
)

// OffSurfaceCrossEdge names a cross-package symbol reference from an off-surface
// standard-library package.
type OffSurfaceCrossEdge struct {
	Pkg string `json:"pkg"`
	Sym string `json:"sym"`
}

// OffSurfaceUnaliasedSel records an unaliased selector whose base identifier may
// resolve to one of Candidates.
type OffSurfaceUnaliasedSel struct {
	Ident      string   `json:"ident"`
	Sel        string   `json:"sel"`
	Candidates []string `json:"candidates"`
}

// OffSurfaceVerdict summarizes an off-surface standard-library package's
// declaration graph, startup seeds, and runtime linkname pulls.
type OffSurfaceVerdict struct {
	PackageName        string                              `json:"packageName,omitempty"`
	DirectRuntimePulls []string                            `json:"directRuntimePulls,omitempty"`
	RuntimePullByDecl  map[string]string                   `json:"runtimePullByDecl,omitempty"`
	LocalEdges         map[string][]string                 `json:"localEdges,omitempty"`
	LocalSels          map[string][]string                 `json:"localSels,omitempty"`
	MethodsByType      map[string][]string                 `json:"methodsByType,omitempty"`
	CrossEdges         map[string][]OffSurfaceCrossEdge    `json:"crossEdges,omitempty"`
	UnaliasedSels      map[string][]OffSurfaceUnaliasedSel `json:"unaliasedSels,omitempty"`
	DotImports         []string                            `json:"dotImports,omitempty"`
	DotImportIdents    map[string][]string                 `json:"dotImportIdents,omitempty"`
	SeedDecls          []string                            `json:"seedDecls,omitempty"`
	SeedSels           []string                            `json:"seedSels,omitempty"`
	SeedCrossEdges     []OffSurfaceCrossEdge               `json:"seedCrossEdges,omitempty"`
	SeedUnaliasedSels  []OffSurfaceUnaliasedSel            `json:"seedUnaliasedSels,omitempty"`
	SeedDotIdents      []string                            `json:"seedDotIdents,omitempty"`
	DeclaredNames      []string                            `json:"declaredNames,omitempty"`
}

// OffSurfaceLinkDirective represents a two-argument //go:linkname directive in
// an off-surface package.
type OffSurfaceLinkDirective struct {
	LocalSym string
	Target   string
}

// BuildOffSurfaceGraph constructs an OffSurfaceVerdict from parsed Go files,
// two-arg linkname directives, and direct runtime/cross-package symbol refs.
func BuildOffSurfaceGraph(importPath string, parsed []*ast.File, linkDirectives []OffSurfaceLinkDirective, directRuntime map[string]bool, seedCrossMap map[OffSurfaceCrossEdge]bool) OffSurfaceVerdict {
	if directRuntime == nil {
		directRuntime = map[string]bool{}
	}
	if seedCrossMap == nil {
		seedCrossMap = map[OffSurfaceCrossEdge]bool{}
	}
	out := OffSurfaceVerdict{
		RuntimePullByDecl: map[string]string{},
		LocalEdges:        map[string][]string{},
		LocalSels:         map[string][]string{},
		MethodsByType:     map[string][]string{},
		CrossEdges:        map[string][]OffSurfaceCrossEdge{},
		UnaliasedSels:     map[string][]OffSurfaceUnaliasedSel{},
		DotImportIdents:   map[string][]string{},
	}
	declaredSet := map[string]bool{}
	bodylessFuncs := map[string]bool{}
	concreteFuncs := map[string]bool{}
	varDecls := map[string]bool{}
	methodsSet := map[string]map[string]bool{}

	for _, f := range parsed {
		if out.PackageName == "" && f.Name != nil {
			out.PackageName = f.Name.Name
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.ValueSpec:
						for _, id := range sp.Names {
							if id.Name != "_" && id.Name != "" {
								declaredSet[id.Name] = true
								if d.Tok == token.VAR {
									varDecls[id.Name] = true
								}
							}
						}
					case *ast.TypeSpec:
						if sp.Name != nil && sp.Name.Name != "_" && sp.Name.Name != "" {
							declaredSet[sp.Name.Name] = true
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name != nil && d.Name.Name != "init" && d.Name.Name != "_" {
					declaredSet[d.Name.Name] = true
					if d.Body == nil {
						bodylessFuncs[d.Name.Name] = true
					} else {
						concreteFuncs[d.Name.Name] = true
					}
				} else if d.Recv != nil && len(d.Recv.List) == 1 && d.Name != nil && d.Name.Name != "_" {
					rBase := RecvBaseTypeName(d.Recv.List[0].Type)
					if rBase != "" {
						if methodsSet[rBase] == nil {
							methodsSet[rBase] = map[string]bool{}
						}
						methodsSet[rBase][d.Name.Name] = true
					}
				}
			}
		}
	}
	for rBase, mSet := range methodsSet {
		out.MethodsByType[rBase] = sortedKeys(mSet)
	}
	out.DeclaredNames = sortedKeys(declaredSet)

	seedDeclSet := map[string]bool{}
	for _, ld := range linkDirectives {
		tPkg, tSym, ok := cprep.SplitLinknameTarget(ld.Target)
		if !ok {
			if strings.HasPrefix(ld.Target, "runtime") {
				directRuntime["runtime.*"] = true
			}
			continue
		}
		isPureBodylessPull := bodylessFuncs[ld.LocalSym] && !concreteFuncs[ld.LocalSym] && !varDecls[ld.LocalSym]
		if tPkg == "runtime" {
			if isPureBodylessPull {
				if prev, exists := out.RuntimePullByDecl[ld.LocalSym]; exists && prev != "runtime."+tSym {
					directRuntime["runtime."+prev[len("runtime."):]] = true
					directRuntime["runtime."+tSym] = true
				} else {
					out.RuntimePullByDecl[ld.LocalSym] = "runtime." + tSym
				}
			} else {
				directRuntime["runtime."+tSym] = true
				if declaredSet[ld.LocalSym] {
					seedDeclSet[ld.LocalSym] = true
				}
			}
			continue
		}
		if tPkg != importPath {
			if isPureBodylessPull {
				out.CrossEdges[ld.LocalSym] = append(out.CrossEdges[ld.LocalSym], OffSurfaceCrossEdge{Pkg: tPkg, Sym: tSym})
			} else {
				if declaredSet[ld.LocalSym] {
					seedDeclSet[ld.LocalSym] = true
				}
				if varDecls[ld.LocalSym] {
					seedCrossMap[OffSurfaceCrossEdge{Pkg: tPkg, Sym: tSym}] = true
				}
			}
		}
	}

	localEdgeMap := map[string]map[string]bool{}
	localSelMap := map[string]map[string]bool{}
	crossEdgeMap := map[string]map[OffSurfaceCrossEdge]bool{}
	unaliasedMap := map[string][]OffSurfaceUnaliasedSel{}
	dotIdentsMap := map[string]map[string]bool{}
	dotImportsSet := map[string]bool{}

	seedSelsSet := map[string]bool{}
	var seedUnaliased []OffSurfaceUnaliasedSel
	seedDotIdents := map[string]bool{}

	for k, list := range out.CrossEdges {
		if crossEdgeMap[k] == nil {
			crossEdgeMap[k] = map[OffSurfaceCrossEdge]bool{}
		}
		for _, e := range list {
			crossEdgeMap[k][e] = true
		}
	}

	for _, f := range parsed {
		explicitImports := map[string]string{}
		var unaliasedImports []string
		var fileDotImports []string
		for _, imp := range f.Imports {
			if imp.Path == nil {
				continue
			}
			impPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil || impPath == "C" || impPath == "unsafe" {
				continue
			}
			if imp.Name != nil {
				switch imp.Name.Name {
				case "_":
					continue
				case ".":
					fileDotImports = append(fileDotImports, impPath)
					dotImportsSet[impPath] = true
				default:
					explicitImports[imp.Name.Name] = impPath
				}
			} else {
				unaliasedImports = append(unaliasedImports, impPath)
			}
		}

		walkOwner := func(owner string, isSeed bool, initScope map[string]bool, nodes ...ast.Node) {
			recIdent := func(name string) {
				if name == "" || name == "_" {
					return
				}
				if pkgPath, okE := explicitImports[name]; okE {
					_ = pkgPath
					return
				}
				if declaredSet[name] {
					if isSeed {
						seedDeclSet[name] = true
					} else if owner != "" {
						if localEdgeMap[owner] == nil {
							localEdgeMap[owner] = map[string]bool{}
						}
						localEdgeMap[owner][name] = true
					}
				} else if len(fileDotImports) > 0 {
					if isSeed {
						seedDotIdents[name] = true
					} else if owner != "" {
						if dotIdentsMap[owner] == nil {
							dotIdentsMap[owner] = map[string]bool{}
						}
						dotIdentsMap[owner][name] = true
					}
				}
			}
			recSel := func(sel string) {
				if sel == "" || sel == "_" {
					return
				}
				if isSeed {
					seedSelsSet[sel] = true
				} else if owner != "" {
					if localSelMap[owner] == nil {
						localSelMap[owner] = map[string]bool{}
					}
					localSelMap[owner][sel] = true
				}
			}
			recQual := func(base, sel string) {
				if pkgPath, okE := explicitImports[base]; okE {
					ce := OffSurfaceCrossEdge{Pkg: pkgPath, Sym: sel}
					if isSeed {
						seedCrossMap[ce] = true
					} else if owner != "" {
						if crossEdgeMap[owner] == nil {
							crossEdgeMap[owner] = map[OffSurfaceCrossEdge]bool{}
						}
						crossEdgeMap[owner][ce] = true
					}
					return
				}
				recIdent(base)
				recSel(sel)
				if len(unaliasedImports) > 0 {
					u := OffSurfaceUnaliasedSel{Ident: base, Sel: sel, Candidates: slices.Clone(unaliasedImports)}
					if isSeed {
						seedUnaliased = append(seedUnaliased, u)
					} else if owner != "" {
						unaliasedMap[owner] = append(unaliasedMap[owner], u)
					}
				}
			}
			scope := maps.Clone(initScope)
			if scope == nil {
				scope = map[string]bool{}
			}
			for _, nd := range nodes {
				if nd != nil {
					walkOffSurfaceAST(nd, scope, recIdent, recSel, recQual)
				}
			}
		}

		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.ValueSpec:
						if d.Tok == token.VAR && len(sp.Values) > 0 {
							for _, id := range sp.Names {
								if id.Name != "_" && id.Name != "" {
									seedDeclSet[id.Name] = true
								}
							}
							var nodes []ast.Node
							if sp.Type != nil {
								nodes = append(nodes, sp.Type)
							}
							for _, v := range sp.Values {
								nodes = append(nodes, v)
							}
							walkOwner("", true, nil, nodes...)
						}
						for idx, id := range sp.Names {
							if id.Name == "_" || id.Name == "" {
								continue
							}
							var nodes []ast.Node
							if sp.Type != nil {
								nodes = append(nodes, sp.Type)
							}
							if idx < len(sp.Values) {
								nodes = append(nodes, sp.Values[idx])
							} else if len(sp.Values) == 1 {
								nodes = append(nodes, sp.Values[0])
							}
							walkOwner(id.Name, false, nil, nodes...)
						}
					case *ast.TypeSpec:
						if sp.Name != nil && sp.Name.Name != "_" && sp.Name.Name != "" {
							tScope := map[string]bool{}
							if sp.TypeParams != nil {
								for _, fld := range sp.TypeParams.List {
									for _, id := range fld.Names {
										if id.Name != "_" && id.Name != "" {
											tScope[id.Name] = true
										}
									}
								}
							}
							walkOwner(sp.Name.Name, false, tScope, sp.Type)
						}
					}
				}
			case *ast.FuncDecl:
				if d.Name == nil {
					continue
				}
				fnScope := map[string]bool{}
				addFieldNames := func(fl *ast.FieldList) {
					if fl == nil {
						return
					}
					for _, fld := range fl.List {
						for _, id := range fld.Names {
							if id.Name != "_" && id.Name != "" {
								fnScope[id.Name] = true
							}
						}
					}
				}
				isInit := d.Recv == nil && d.Name.Name == "init"
				owner := ""
				if !isInit {
					if d.Recv == nil {
						if d.Name.Name == "_" {
							continue
						}
						owner = d.Name.Name
					} else if len(d.Recv.List) == 1 && d.Name.Name != "_" {
						rBase := RecvBaseTypeName(d.Recv.List[0].Type)
						if rBase == "" {
							continue
						}
						owner = "method:" + rBase + "." + d.Name.Name
					} else {
						continue
					}
				}
				// Walk signature types before binding parameter/result names so type names resolve at package scope.
				typeScope := map[string]bool{}
				if d.Type != nil && d.Type.TypeParams != nil {
					for _, fld := range d.Type.TypeParams.List {
						for _, id := range fld.Names {
							if id.Name != "_" && id.Name != "" {
								typeScope[id.Name] = true
							}
						}
					}
				}
				var sigNodes []ast.Node
				for _, fl := range []*ast.FieldList{d.Recv, d.Type.Params, d.Type.Results} {
					if fl != nil {
						for _, fld := range fl.List {
							if fld.Type != nil {
								sigNodes = append(sigNodes, fld.Type)
							}
						}
					}
				}
				walkOwner(owner, isInit, typeScope, sigNodes...)
				maps.Copy(fnScope, typeScope)
				addFieldNames(d.Recv)
				addFieldNames(d.Type.Params)
				addFieldNames(d.Type.Results)
				if d.Body != nil {
					walkOwner(owner, isInit, fnScope, d.Body)
				}
			}
		}
	}

	if len(directRuntime) > 0 {
		out.DirectRuntimePulls = sortedKeys(directRuntime)
	}
	for k, m := range localEdgeMap {
		out.LocalEdges[k] = sortedKeys(m)
	}
	for k, m := range localSelMap {
		out.LocalSels[k] = sortedKeys(m)
	}
	out.CrossEdges = map[string][]OffSurfaceCrossEdge{}
	for k, m := range crossEdgeMap {
		list := make([]OffSurfaceCrossEdge, 0, len(m))
		for e := range m {
			list = append(list, e)
		}
		slices.SortFunc(list, func(a, b OffSurfaceCrossEdge) int {
			if c := strings.Compare(a.Pkg, b.Pkg); c != 0 {
				return c
			}
			return strings.Compare(a.Sym, b.Sym)
		})
		out.CrossEdges[k] = list
	}
	out.UnaliasedSels = unaliasedMap
	if len(dotImportsSet) > 0 {
		out.DotImports = sortedKeys(dotImportsSet)
	}
	for k, m := range dotIdentsMap {
		out.DotImportIdents[k] = sortedKeys(m)
	}
	if len(seedDeclSet) > 0 {
		out.SeedDecls = sortedKeys(seedDeclSet)
	}
	if len(seedSelsSet) > 0 {
		out.SeedSels = sortedKeys(seedSelsSet)
	}
	if len(seedCrossMap) > 0 {
		list := make([]OffSurfaceCrossEdge, 0, len(seedCrossMap))
		for e := range seedCrossMap {
			list = append(list, e)
		}
		slices.SortFunc(list, func(a, b OffSurfaceCrossEdge) int {
			if c := strings.Compare(a.Pkg, b.Pkg); c != 0 {
				return c
			}
			return strings.Compare(a.Sym, b.Sym)
		})
		out.SeedCrossEdges = list
	}
	out.SeedUnaliasedSels = seedUnaliased
	if len(seedDotIdents) > 0 {
		out.SeedDotIdents = sortedKeys(seedDotIdents)
	}
	return out
}

// PropagateOffSurfaceRuntimePulls runs the worklist propagation across offVerdicts
// and externalSeeds, recording reachable runtime.* linkname targets in
// pulledRuntimeTargets.
func PropagateOffSurfaceRuntimePulls(
	invKeys []string,
	offVerdicts map[string]OffSurfaceVerdict,
	resolveImport func(raw string) (string, bool),
	externalSeeds []OffSurfaceCrossEdge,
	pulledRuntimeTargets map[string]bool,
) {
	type workItem struct {
		pkg  string
		decl string
	}
	type pkgSel struct {
		pkg string
		sel string
	}
	visited := map[workItem]bool{}
	var queue []workItem
	pkgReachedTypes := map[string]map[string]bool{}
	pkgReachedSels := map[string]map[string]bool{}
	globalExportedSels := map[string]bool{}
	pendingByPkgSel := map[pkgSel][]string{}
	pendingByExportedSel := map[string][]workItem{}

	enqueue := func(pkg, decl string) {
		if pkg == "" || decl == "" {
			return
		}
		if _, ok := offVerdicts[pkg]; !ok {
			return
		}
		wi := workItem{pkg: pkg, decl: decl}
		if visited[wi] {
			return
		}
		visited[wi] = true
		queue = append(queue, wi)
	}

	addSel := func(pkg, sel string) {
		if sel == "" {
			return
		}
		if pkg != "" {
			if pkgReachedSels[pkg] == nil {
				pkgReachedSels[pkg] = map[string]bool{}
			}
			if !pkgReachedSels[pkg][sel] {
				pkgReachedSels[pkg][sel] = true
				ps := pkgSel{pkg: pkg, sel: sel}
				for _, mDecl := range pendingByPkgSel[ps] {
					enqueue(pkg, mDecl)
				}
				delete(pendingByPkgSel, ps)
			}
		}
		if ast.IsExported(sel) && !globalExportedSels[sel] {
			globalExportedSels[sel] = true
			for _, wi := range pendingByExportedSel[sel] {
				enqueue(wi.pkg, wi.decl)
			}
			delete(pendingByExportedSel, sel)
		}
	}

	enqueueCross := func(rawPkg, sym string) {
		if rawPkg == "runtime" {
			if base := cprep.LeadingASCIIIdent(sym); base != "" {
				pulledRuntimeTargets["runtime."+base] = true
			} else {
				pulledRuntimeTargets["runtime."+sym] = true
			}
			return
		}
		if resolved, ok := resolveImport(rawPkg); ok {
			enqueue(resolved, sym)
			if typePart, methodPart, hasDot := strings.Cut(sym, "."); hasDot {
				tBase := strings.TrimSuffix(strings.TrimPrefix(typePart, "(*"), ")")
				tBase = strings.TrimPrefix(tBase, "*")
				mBase := cprep.LeadingASCIIIdent(methodPart)
				if tBase != "" && mBase != "" {
					enqueue(resolved, tBase)
					enqueue(resolved, "method:"+tBase+"."+mBase)
				}
			}
		}
	}

	enqueueUnaliased := func(u OffSurfaceUnaliasedSel) {
		for _, cand := range u.Candidates {
			resolved, ok := resolveImport(cand)
			if !ok {
				continue
			}
			if ov, isOff := offVerdicts[resolved]; isOff {
				if ov.PackageName == "" || ov.PackageName == u.Ident {
					enqueue(resolved, u.Sel)
				}
			}
		}
	}

	enqueueDot := func(dotImports []string, ident string) {
		for _, cand := range dotImports {
			if resolved, ok := resolveImport(cand); ok {
				enqueue(resolved, ident)
			}
		}
	}

	for _, seed := range externalSeeds {
		enqueueCross(seed.Pkg, seed.Sym)
	}
	for _, pkg := range invKeys {
		ov := offVerdicts[pkg]
		for _, sd := range ov.SeedDecls {
			enqueue(pkg, sd)
		}
		for _, sel := range ov.SeedSels {
			addSel(pkg, sel)
		}
		for _, ce := range ov.SeedCrossEdges {
			enqueueCross(ce.Pkg, ce.Sym)
		}
		for _, u := range ov.SeedUnaliasedSels {
			enqueueUnaliased(u)
		}
		for _, di := range ov.SeedDotIdents {
			enqueueDot(ov.DotImports, di)
		}
	}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		ov := offVerdicts[item.pkg]
		if rt := ov.RuntimePullByDecl[item.decl]; rt != "" {
			pulledRuntimeTargets[rt] = true
			if pulledRuntimeTargets["runtime.*"] {
				return
			}
		}
		if methods := ov.MethodsByType[item.decl]; len(methods) > 0 {
			if pkgReachedTypes[item.pkg] == nil {
				pkgReachedTypes[item.pkg] = map[string]bool{}
			}
			if !pkgReachedTypes[item.pkg][item.decl] {
				pkgReachedTypes[item.pkg][item.decl] = true
				for _, m := range methods {
					mDecl := "method:" + item.decl + "." + m
					if pkgReachedSels[item.pkg][m] || (ast.IsExported(m) && globalExportedSels[m]) {
						enqueue(item.pkg, mDecl)
						continue
					}
					ps := pkgSel{pkg: item.pkg, sel: m}
					pendingByPkgSel[ps] = append(pendingByPkgSel[ps], mDecl)
					if ast.IsExported(m) {
						pendingByExportedSel[m] = append(pendingByExportedSel[m], workItem{pkg: item.pkg, decl: mDecl})
					}
				}
			}
		}
		for _, sel := range ov.LocalSels[item.decl] {
			addSel(item.pkg, sel)
		}
		for _, loc := range ov.LocalEdges[item.decl] {
			enqueue(item.pkg, loc)
		}
		for _, ce := range ov.CrossEdges[item.decl] {
			enqueueCross(ce.Pkg, ce.Sym)
		}
		for _, u := range ov.UnaliasedSels[item.decl] {
			enqueueUnaliased(u)
		}
		for _, di := range ov.DotImportIdents[item.decl] {
			enqueueDot(ov.DotImports, di)
		}
	}
}
