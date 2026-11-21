package observability

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/asmverify"
)

type cachedNodeRefs struct {
	objs  []types.Object
	types []types.Type
	hasIf bool
}

type pkgIndex struct {
	pkg            *packages.Package
	ssa            *ssa.Package
	meta           *listPkg
	id             string
	path           string
	std            bool
	testMain       bool
	cache          bool
	mutable        bool
	decls          map[types.Object]ast.Node
	nodeRefs       map[ast.Node]*cachedNodeRefs
	vars           []ast.Node
	inits          []ast.Node
	wasmImport     bool
	linknames      map[types.Object]string
	linknameByName map[string]string
	funcKeys       map[types.Object]funcDeclKey
}

// tier2Base is the immutable package/source index shared by every subject in
// one package analysis view.
type tier2Base struct {
	h                      *Hasher
	buildFlags             []string
	prog                   *program
	metas                  []listPkg
	metaByPath             map[string]*listPkg
	idxByTypes             map[*types.Package]*pkgIndex
	objByName              map[string]types.Object
	objsByLinkTarget       map[string][]types.Object
	flagBacked             map[*ssa.Global]bool
	flagUntraceable        map[string]string
	flagProven             map[ssa.Value]flagSetKind
	baseStartupResultDone  [2]bool
	baseStartupResult      [2]tier2Result
	baseStartupZeroDone    bool
	baseStartupZeroGlobals map[*ssa.Global]bool
	baseStartupAsyncDone   bool
	baseStartupAsyncOrDyn  map[*ssa.Function]bool
	baseStartupObjsDone    [2]bool
	baseStartupObjs        [2]map[types.Object]bool
	wholeZeroDone          bool
	wholeZeroGlobals       map[*ssa.Global]bool
	verifiedAsm            map[string]*asmverify.VerifiedPackage
	unsafeValueType        map[types.Type]bool
	unsafeElemType         map[types.Type]bool
	ifaceMethodDone        map[types.Type]bool
	ifaceMethodObjs        map[types.Type][]*types.Func
	goASTSealedMemo        map[*types.Named]bool
	goASTUnsealedReason    map[*types.Named]string
	binaryUnsafeDone       bool
	binaryUnsafeReason     string
	pkgUnsafeKnown         map[string]bool
	pkgUnsafeHazard        map[string]bool
	binaryChdirDone        bool
	binaryChdirSafe        bool
}

type tier2Analyzer struct {
	base                     *tier2Base
	h                        *Hasher
	buildFlags               []string
	prog                     *program
	metas                    []listPkg
	metaByPath               map[string]*listPkg
	flagBacked               map[*ssa.Global]bool
	flagProven               map[ssa.Value]flagSetKind
	skipOriginScan           map[*ssa.Function]bool
	idxByTypes               map[*types.Package]*pkgIndex
	objByName                map[string]types.Object
	objsByLinkTarget         map[string][]types.Object
	seenObjects              map[types.Object]bool
	objectQueue              []types.Object
	seenTypes                map[types.Type]bool
	filePkgs                 map[*pkgIndex]bool
	rtaReach                 map[*ssa.Function]bool
	rtaResolved              map[ssa.CallInstruction]bool
	subjectDeterminedInvokes map[ssa.CallInstruction]bool
	fresh                    *freshParamAnalysis
	enumeratedTypes          []types.Type
	initBoxedTypes           []types.Type
	harnessRecvBoxClosed     map[*types.Named]bool
	subjectRoots             map[*ssa.Function]bool
	startupOnly              map[*ssa.Function]bool
	zeroGlobals              map[*ssa.Global]bool
	zeroGlobalDecls          map[pkgVarKey]bool
	openWorld                bool
	scanned                  map[*ssa.Function]bool
	scannedNodes             map[ast.Node]bool
	seenIfaceBoxTypes        map[types.Type]bool
	effects                  []externalEffect

	widen        bool
	widenReason  string
	unverifiable bool
	selected     externalEffect
}

func newTier2Base(h *Hasher, prog *program, metas []listPkg) *tier2Base {
	bindProgramHasher(h, prog)
	a := &tier2Analyzer{
		h:                h,
		buildFlags:       append([]string(nil), h.BuildFlags()...),
		prog:             prog,
		metas:            metas,
		metaByPath:       map[string]*listPkg{},
		idxByTypes:       map[*types.Package]*pkgIndex{},
		objByName:        map[string]types.Object{},
		objsByLinkTarget: map[string][]types.Object{},
	}
	for i := range metas {
		m := &metas[i]
		a.metaByPath[m.ImportPath] = m
	}
	for _, p := range prog.Pkgs {
		idx := a.buildIndex(p)
		if idx == nil {
			continue
		}
		if p.Types != nil {
			a.idxByTypes[p.Types] = idx
		}
		for obj := range idx.decls {
			if obj == nil || obj.Pkg() == nil || obj.Name() == "" {
				continue
			}
			a.objByName[obj.Pkg().Path()+"."+obj.Name()] = obj
		}
		for obj, target := range idx.linknames {
			a.addReverseLinkname(target, obj)
		}
		if idx.pkg != nil && idx.pkg.Types != nil {
			for name, target := range idx.linknameByName {
				if obj := idx.pkg.Types.Scope().Lookup(name); obj != nil {
					a.addReverseLinkname(target, obj)
				}
			}
		}
	}
	return &tier2Base{
		h:                h,
		buildFlags:       a.buildFlags,
		prog:             prog,
		metas:            metas,
		metaByPath:       a.metaByPath,
		idxByTypes:       a.idxByTypes,
		objByName:        a.objByName,
		objsByLinkTarget: a.objsByLinkTarget,
		unsafeValueType:  map[types.Type]bool{},
		unsafeElemType:   map[types.Type]bool{},
		ifaceMethodDone:  map[types.Type]bool{},
		ifaceMethodObjs:  map[types.Type][]*types.Func{},
	}
}

func (b *tier2Base) analyzer() *tier2Analyzer {
	flagBacked, _ := b.flagRegistrationFacts()
	return &tier2Analyzer{
		base:                     b,
		flagProven:               b.flagProven,
		h:                        b.h,
		buildFlags:               b.buildFlags,
		prog:                     b.prog,
		metas:                    b.metas,
		metaByPath:               b.metaByPath,
		idxByTypes:               b.idxByTypes,
		objByName:                b.objByName,
		objsByLinkTarget:         b.objsByLinkTarget,
		flagBacked:               flagBacked,
		seenObjects:              map[types.Object]bool{},
		seenTypes:                map[types.Type]bool{},
		filePkgs:                 map[*pkgIndex]bool{},
		rtaReach:                 map[*ssa.Function]bool{},
		rtaResolved:              map[ssa.CallInstruction]bool{},
		subjectDeterminedInvokes: map[ssa.CallInstruction]bool{},
		scanned:                  map[*ssa.Function]bool{},
		scannedNodes:             map[ast.Node]bool{},
		seenIfaceBoxTypes:        map[types.Type]bool{},
	}
}

func (a *tier2Analyzer) addReverseLinkname(target string, obj types.Object) {
	if target == "" || obj == nil {
		return
	}
	for _, existing := range a.objsByLinkTarget[target] {
		if existing == obj {
			return
		}
	}
	a.objsByLinkTarget[target] = append(a.objsByLinkTarget[target], obj)
}

func (a *tier2Analyzer) buildIndex(p *packages.Package) *pkgIndex {
	if p == nil || p.Types == nil {
		return nil
	}
	meta := a.metaForPackage(p)
	path := p.Types.Path()
	std := p.Module == nil && isStdImportPath(path)
	if meta != nil {
		std = meta.Standard
	}
	idx := &pkgIndex{
		pkg:            p,
		ssa:            a.prog.Prog.Package(p.Types),
		meta:           meta,
		id:             p.ID,
		path:           path,
		std:            std,
		testMain:       isGeneratedTestMainLoadedPkg(p) || (p.Name == "main" && path == a.prog.PkgPath+".test"),
		decls:          map[types.Object]ast.Node{},
		nodeRefs:       map[ast.Node]*cachedNodeRefs{},
		linknames:      map[types.Object]string{},
		linknameByName: map[string]string{},
		funcKeys:       map[types.Object]funcDeclKey{},
	}
	if meta != nil {
		idx.cache = meta.Module != nil && !meta.Module.Main && a.h.UnderCache(meta.Dir)
	} else if p.Module != nil {
		idx.cache = !p.Module.Main && a.h.UnderCache(p.Dir)
	}
	idx.mutable = !idx.std && !idx.testMain && !idx.cache
	if idx.id == "" {
		idx.id = path
	}

	for _, f := range p.Syntax {
		fileDir := filepath.Clean(p.Dir)
		if p.Fset != nil {
			if tf := p.Fset.File(f.Pos()); tf != nil && tf.Name() != "" {
				fileDir = filepath.Clean(filepath.Dir(tf.Name()))
			}
		}
		pkgClause := ""
		if f.Name != nil {
			pkgClause = f.Name.Name
		}
		forEachGoLinknameDirective(f.Comments, func(local, target string, valid bool) {
			if !valid || local == "" || target == "" {
				return
			}
			if prev := idx.linknameByName[local]; prev != "" && prev != target {
				idx.linknameByName[local] = "<conflict>"
			} else {
				idx.linknameByName[local] = target
			}
		})
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if strings.Contains(c.Text, "go:wasmimport") && isWasmImportComment(c.Text) {
					idx.wasmImport = true
				}
			}
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Name.Name == "init" {
					idx.inits = append(idx.inits, d)
				}
				if obj := p.TypesInfo.Defs[d.Name]; obj != nil {
					idx.decls[obj] = d
					if key, ok := funcDeclKeyForAST(fileDir, pkgClause, d); ok {
						idx.funcKeys[obj] = key
					}
				}
				for local, target := range linknamesFromDoc(d.Doc) {
					if obj := p.Types.Scope().Lookup(local); obj != nil {
						idx.linknames[obj] = target
					}
				}
			case *ast.GenDecl:
				genLinknames := linknamesFromDoc(d.Doc)
				for local, target := range genLinknames {
					if obj := p.Types.Scope().Lookup(local); obj != nil {
						idx.linknames[obj] = target
					}
				}
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.ValueSpec:
						specLinknames := linknamesFromDoc(s.Doc)
						for local, target := range specLinknames {
							if obj := p.Types.Scope().Lookup(local); obj != nil {
								idx.linknames[obj] = target
							}
						}
						node := ast.Node(s)
						if d.Tok == token.CONST {
							node = d
						}
						if d.Tok == token.VAR {
							idx.vars = append(idx.vars, s)
							if len(genLinknames) > 0 {
								node = d
							}
						}
						for _, name := range s.Names {
							if obj := p.TypesInfo.Defs[name]; obj != nil {
								idx.decls[obj] = node
								if d.Tok == token.CONST && name.Name != "" && name.Name != "_" {
									idx.funcKeys[obj] = funcDeclKey{
										Dir:       fileDir,
										PkgClause: pkgClause,
										Name:      name.Name,
									}
								}
							}
						}
					case *ast.TypeSpec:
						if obj := p.TypesInfo.Defs[s.Name]; obj != nil {
							addTypeDeclaration(idx, obj, s)
							if s.Name != nil && s.Name.Name != "" && s.Name.Name != "_" {
								key := funcDeclKey{
									Dir:       fileDir,
									PkgClause: pkgClause,
									Name:      s.Name.Name,
								}
								idx.funcKeys[obj] = key
								if iface, ok := obj.Type().Underlying().(*types.Interface); ok {
									iface.Complete()
									for i := 0; i < iface.NumExplicitMethods(); i++ {
										idx.funcKeys[iface.ExplicitMethod(i)] = key
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return idx
}

func addTypeDeclaration(idx *pkgIndex, obj types.Object, node ast.Node) {
	if idx == nil || obj == nil || node == nil {
		return
	}
	idx.decls[obj] = node
	underlying := obj.Type().Underlying()
	iface, ok := underlying.(*types.Interface)
	if !ok {
		return
	}
	iface.Complete()
	for i := 0; i < iface.NumExplicitMethods(); i++ {
		idx.decls[iface.ExplicitMethod(i)] = node
	}
}

func (a *tier2Analyzer) metaForPackage(p *packages.Package) *listPkg {
	for _, key := range []string{p.ID, p.PkgPath} {
		if key == "" {
			continue
		}
		if m := a.metaByPath[key]; m != nil {
			return m
		}
	}
	if p.Types != nil {
		if m := a.metaByPath[p.Types.Path()]; m != nil {
			return m
		}
	}
	return nil
}

func (idx *pkgIndex) cachedRefsForNode(node ast.Node) *cachedNodeRefs {
	if idx == nil || node == nil || idx.pkg == nil || idx.pkg.TypesInfo == nil {
		return nil
	}
	if idx.nodeRefs != nil {
		if refs := idx.nodeRefs[node]; refs != nil {
			return refs
		}
	} else {
		idx.nodeRefs = map[ast.Node]*cachedNodeRefs{}
	}
	refs := &cachedNodeRefs{}
	seenObj := map[types.Object]bool{}
	seenType := map[types.Type]bool{}
	addObj := func(obj types.Object) {
		if obj != nil && !seenObj[obj] {
			seenObj[obj] = true
			refs.objs = append(refs.objs, obj)
		}
	}
	addTyp := func(t types.Type) {
		if t != nil && !seenType[t] {
			seenType[t] = true
			refs.types = append(refs.types, t)
		}
	}
	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.IfStmt:
			if x.Init == nil && x.Body != nil {
				refs.hasIf = true
			}
		case *ast.Ident:
			if obj := idx.pkg.TypesInfo.Uses[x]; obj != nil {
				addObj(obj)
				addTyp(obj.Type())
			}
		case *ast.SelectorExpr:
			if sel := idx.pkg.TypesInfo.Selections[x]; sel != nil {
				addObj(sel.Obj())
				addTyp(sel.Recv())
			}
		}
		return true
	})
	idx.nodeRefs[node] = refs
	return refs
}

func (a *tier2Analyzer) scanNodeRefs(idx *pkgIndex, node ast.Node, startupOnly bool) {
	if idx == nil || node == nil || idx.pkg.TypesInfo == nil {
		return
	}
	refs := idx.cachedRefsForNode(node)
	if refs == nil {
		return
	}
	var skippedBody map[*ast.BlockStmt]bool
	if startupOnly && len(a.zeroGlobalDecls) > 0 && refs.hasIf {
		ast.Inspect(node, func(n ast.Node) bool {
			if _, isFuncLit := n.(*ast.FuncLit); isFuncLit {
				return false
			}
			if ifStmt, ok := n.(*ast.IfStmt); ok && ifStmt.Init == nil && ifStmt.Body != nil && ifCondRequiresNonZeroGlobalTyped(ifStmt.Cond, idx.pkg.TypesInfo, a.zeroGlobalDecls) {
				if skippedBody == nil {
					skippedBody = make(map[*ast.BlockStmt]bool)
				}
				skippedBody[ifStmt.Body] = true
			}
			return true
		})
	}
	if len(skippedBody) == 0 {
		if a.scannedNodes[node] {
			return
		}
		if a.scannedNodes != nil {
			a.scannedNodes[node] = true
		}
		for _, obj := range refs.objs {
			a.enqueueObject(obj)
		}
		for _, t := range refs.types {
			a.addType(t)
		}
		return
	}
	ast.Inspect(node, func(n ast.Node) bool {
		if blk, ok := n.(*ast.BlockStmt); ok && skippedBody[blk] {
			return false
		}
		switch x := n.(type) {
		case *ast.Ident:
			if obj := idx.pkg.TypesInfo.Uses[x]; obj != nil {
				a.enqueueObject(obj)
				a.addType(obj.Type())
			}
		case *ast.SelectorExpr:
			if sel := idx.pkg.TypesInfo.Selections[x]; sel != nil {
				a.enqueueObject(sel.Obj())
				a.addType(sel.Recv())
			}
		}
		return true
	})
}

func (a *tier2Analyzer) markPackage(idx *pkgIndex) {
	if idx != nil && idx.mutable {
		a.filePkgs[idx] = true
	}
}

func (a *tier2Analyzer) markFilePackage(idx *pkgIndex) {
	if idx != nil && (idx.mutable || idx.cache) {
		a.filePkgs[idx] = true
	}
}

func originObject(obj types.Object) types.Object {
	fn, ok := obj.(*types.Func)
	if !ok {
		return obj
	}
	if origin := fn.Origin(); origin != nil {
		return origin
	}
	return obj
}

func (a *tier2Analyzer) addReverseLinknameTargets(obj types.Object) {
	if obj == nil || obj.Pkg() == nil {
		return
	}
	key := obj.Pkg().Path() + "." + obj.Name()
	for _, linked := range a.objsByLinkTarget[key] {
		if linked != obj {
			a.enqueueObject(linked)
		}
	}
}

func (a *tier2Analyzer) addValueType(idx *pkgIndex, v ssa.Value) {
	t := v.Type()
	a.addType(t)
	if !a.valueTypeUsesUnsafePointer(t) {
		return
	}
	if idx == nil && v.Parent() != nil {
		idx = a.idxForFunction(v.Parent())
	}
	unindexedWrapper := idx == nil && v.Parent() != nil && isAnalyzableUnnamedWrapper(v.Parent())
	if unindexedWrapper || (idx != nil && !idx.std) {
		pkgID := "<synthetic>"
		if idx != nil {
			pkgID = idx.id
		}
		a.requestWiden("unsafe pointer reachable in " + pkgID)
	}
}

func (a *tier2Analyzer) valueTypeUsesUnsafePointer(t types.Type) bool {
	if t == nil {
		return false
	}
	if a != nil && a.base != nil && a.base.unsafeValueType != nil {
		if v, ok := a.base.unsafeValueType[t]; ok {
			return v
		}
	}
	res := false
	if tuple, ok := types.Unalias(t).(*types.Tuple); ok {
		for i := 0; i < tuple.Len(); i++ {
			elem := tuple.At(i).Type()
			if a.typeUsesUnsafePointer(elem) && !isOSFileType(elem) {
				res = true
				break
			}
		}
	} else {
		res = a.typeUsesUnsafePointer(t) && !isOSFileType(t)
	}
	if a != nil && a.base != nil && a.base.unsafeValueType != nil {
		a.base.unsafeValueType[t] = res
	}
	return res
}

func (a *tier2Analyzer) typeUsesUnsafePointer(t types.Type) bool {
	if t == nil {
		return false
	}
	if a == nil {
		return typeUsesUnsafePointer(t)
	}
	var memo map[types.Type]bool
	if a.base != nil {
		memo = a.base.unsafeElemType
	}
	return typeUsesUnsafePointerWith(t, false, memo, func(tt *types.Named, walk func(types.Type) bool) (bool, bool) {
		if a.h != nil && a.h.SelectionAudited() && tt.Obj() != nil && tt.Obj().Pkg() != nil && tt.Obj().Pkg().Path() == "go/token" && tt.Obj().Name() == "FileSet" {
			for i := 0; i < tt.TypeArgs().Len(); i++ {
				if walk(tt.TypeArgs().At(i)) {
					return true, true
				}
			}
			return false, true
		}
		if !a.isOpaquePropertyHarnessStruct(tt) {
			return false, false
		}
		for i := 0; i < tt.TypeArgs().Len(); i++ {
			if walk(tt.TypeArgs().At(i)) {
				return true, true
			}
		}
		return false, true
	})
}

func (a *tier2Analyzer) addType(t types.Type) {
	if t == nil || a.seenTypes[t] {
		return
	}
	u := types.Unalias(t)
	if a.seenTypes[u] {
		a.seenTypes[t] = true
		return
	}
	walkTypeGraph(u, true, a.seenTypes, func(t types.Type) bool {
		if named, ok := t.(*types.Named); ok {
			a.enqueueObject(named.Obj())
		}
		return true
	})
	a.seenTypes[t] = true
}

func (a *tier2Analyzer) idxForFunction(fn *ssa.Function) *pkgIndex {
	return idxForFunctionIn(a.idxByTypes, fn)
}

func (a *tier2Analyzer) isStdFunction(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	if idx := a.idxForFunction(fn); idx != nil {
		return idx.std
	}
	if isUnnamedStructPromotedWrapper(fn) {
		return false
	}
	return isStdImportPath(funcPkgPath(fn))
}

func (b *tier2Base) idxForFunction(fn *ssa.Function) *pkgIndex {
	return idxForFunctionIn(b.idxByTypes, fn)
}
