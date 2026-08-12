package closure

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

type tier2Result struct {
	effects      []externalEffect
	widen        bool
	widenReason  string
	unverifiable bool
	reason       string
}

func (h *Hasher) tier2Reachable(base *tier2Base, reachable attributedReachability) (tier2Result, error) {
	a := base.analyzer()
	a.rtaResolved = reachable.resolved
	a.skipOriginScan = reachable.instantiatedOrigins
	a.openWorld = reachable.openWorld
	a.fresh = newFreshParamAnalysis(reachable)
	for site, targets := range reachable.dynamicTargets {
		if !reachable.functions[site.Parent()] {
			continue
		}
		callerIdx := a.idxForFunction(site.Parent())
		if callerIdx == nil || callerIdx.testMain {
			continue
		}
		// The harness-dispatch admission: a site whose enumerated target
		// set is non-empty and entirely audited harness methods does not
		// widen (REQ-closure-observability-analysis). The bound is the
		// target SET — one non-harness target keeps the widen regardless
		// of that target's own effects.
		if a.rtaResolved[site] && !a.openWorld && len(targets) != 0 {
			allHarness := true
			for target := range targets {
				if !harnessLoggingFunction(target) {
					allHarness = false
					break
				}
			}
			if allHarness {
				a.harnessOnlyInvokes[site] = true
			}
		}
		for target := range targets {
			if observableDirEntryCall(site) {
				continue
			}
			idx := a.idxForFunction(target)
			if idx == nil {
				continue
			}
			// A NAMED harness function reached as a dynamic target keeps
			// the conservative refusal: its body is unscanned and no
			// static call site exists to gate the crossing arguments. An
			// anonymous harness function - the wrapped callback
			// MakeCheck returns - exists only because a gated harness
			// call in some analyzed flow created it: every flow that can
			// call into the harness carries the boundary gate, so its
			// bindings are already judged
			// (REQ-closure-observability-analysis).
			if a.propertyHarnessAudited(idx.path) {
				if target.Parent() == nil {
					a.requestWiden("property harness reached as a dynamic target in " + site.Parent().String())
				}
				continue
			}
			if !idx.std {
				continue
			}
			effect, ok := classBEffectForFunction(target)
			if !ok && harnessLoggingFunction(target) {
				a.recordExternalEffect(harnessLoggingEffect(functionSymbolName(target)))
				continue
			}
			if !ok && !callerIdx.std && !isSourceOnlyStandardPackage(idx.path) {
				// The audited-pure admissions hold for an enumerated
				// dynamic target exactly as for a static callee - the
				// admission is a property of the operation, not of the
				// call form (REQ-closure-observability-analysis).
				name := functionSymbolName(target)
				if !classBPureStandard(idx.path, name) && !auditedSyncSymbol(idx.path, name) && !auditedRuntimeTypeSymbol(idx.path, name) {
					effect = symbolExternalEffect(externalEffectUnauditedStandard, idx.path, name, "reaches unaudited standard operation "+idx.path+"."+name)
					ok = true
				}
			}
			if ok {
				a.recordExternalEffect(effect)
			}
		}
	}
	for fn := range reachable.functions {
		if err := a.contextErr(); err != nil {
			return tier2Result{}, err
		}
		a.rtaReach[fn] = true
	}
	for fn := range reachable.functions {
		if err := a.contextErr(); err != nil {
			return tier2Result{}, err
		}
		a.addFunction(fn)
		if idx := a.idxForFunction(fn); idx != nil && idx.std {
			continue
		}
		a.scanFunction(fn)
		if err := a.contextErr(); err != nil {
			return tier2Result{}, err
		}
	}
	if err := a.drainObjects(); err != nil {
		return tier2Result{}, err
	}
	for {
		if err := a.contextErr(); err != nil {
			return tier2Result{}, err
		}
		pkgCount := len(a.filePkgs)
		if err := a.addReachedPackageFiles(); err != nil {
			return tier2Result{}, err
		}
		if err := a.drainObjects(); err != nil {
			return tier2Result{}, err
		}
		if len(a.filePkgs) == pkgCount {
			break
		}
	}
	return a.result(), nil
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
	vars           []ast.Node
	inits          []ast.Node
	wasmImport     bool
	linknames      map[types.Object]string
	linknameByName map[string]string
}

// tier2Base is the immutable package/source index shared by every subject in
// one package analysis view. The AST, type, linkname, and package lookup maps
// are expensive to build but independent of a subject's reachable set.
type tier2Base struct {
	h                *Hasher
	buildFlags       []string
	prog             *program
	metas            []listPkg
	metaByPath       map[string]*listPkg
	idxByTypes       map[*types.Package]*pkgIndex
	objByName        map[string]types.Object
	objsByLinkTarget map[string][]types.Object
	// flagBacked marks package-level variables carrying flag-registered
	// state, judged at every registration call site program-wide by
	// flagRegistrationFacts. Their values change at flag.Parse -
	// command-line state the test log cannot audit - so a subject-flow
	// or test-main-flow reference is the covert channel's read side.
	// flagUntraceable records, per package path, a registration whose
	// registered storage the judgment could not trace - such a package
	// blocks every subject sharing the program
	// (REQ-closure-observability-analysis). Both computed once per base.
	flagBacked      map[*ssa.Global]bool
	flagUntraceable map[string]string
}

type tier2Analyzer struct {
	h          *Hasher
	buildFlags []string
	prog       *program
	metas      []listPkg
	metaByPath map[string]*listPkg
	flagBacked map[*ssa.Global]bool
	// skipOriginScan marks parameterized origins whose rooted
	// instantiations carry the concrete forms of every site: the
	// open-over-T origin body is never scanned, whatever path reaches it
	// (the reach loop, the object drain, a static-callee walk) - its
	// declaration still contributes.
	skipOriginScan   map[*ssa.Function]bool
	idxByTypes       map[*types.Package]*pkgIndex
	objByName        map[string]types.Object
	objsByLinkTarget map[string][]types.Object

	seenObjects map[types.Object]bool
	objectQueue []types.Object
	// seenTypes dedups the type walk by type identity: recursive types
	// self-reference through one instance, so pointer keys break cycles;
	// structurally identical distinct instances re-walk harmlessly
	// (enqueueObject dedups), and the TypeString render this key replaced
	// dominated the walk's allocations.
	seenTypes   map[types.Type]bool
	filePkgs    map[*pkgIndex]bool
	rtaReach    map[*ssa.Function]bool
	rtaResolved map[ssa.CallInstruction]bool
	// harnessOnlyInvokes marks invoke sites whose RTA-enumerated target
	// set is entirely audited harness methods: the one dispatch shape an
	// unresolved invoke may take without widening the subject world.
	harnessOnlyInvokes map[ssa.CallInstruction]bool
	// fresh carries the subject's cross-boundary fresh-path analysis;
	// nil outside per-subject reachability walks (maximal tier,
	// startup effects), where the intraprocedural grammar alone applies.
	fresh     *freshParamAnalysis
	openWorld bool
	scanned   map[*ssa.Function]bool
	effects   []externalEffect

	widen        bool
	widenReason  string
	unverifiable bool
	reason       string
	reasonRank   int
}

func newTier2Base(h *Hasher, prog *program, metas []listPkg) *tier2Base {
	a := &tier2Analyzer{
		h:                h,
		buildFlags:       append([]string(nil), h.buildFlags...),
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
	}
}

func (b *tier2Base) analyzer() *tier2Analyzer {
	flagBacked, _ := b.flagRegistrationFacts()
	return &tier2Analyzer{
		h:                  b.h,
		buildFlags:         b.buildFlags,
		prog:               b.prog,
		metas:              b.metas,
		metaByPath:         b.metaByPath,
		idxByTypes:         b.idxByTypes,
		objByName:          b.objByName,
		objsByLinkTarget:   b.objsByLinkTarget,
		flagBacked:         flagBacked,
		seenObjects:        map[types.Object]bool{},
		seenTypes:          map[types.Type]bool{},
		filePkgs:           map[*pkgIndex]bool{},
		rtaReach:           map[*ssa.Function]bool{},
		rtaResolved:        map[ssa.CallInstruction]bool{},
		harnessOnlyInvokes: map[ssa.CallInstruction]bool{},
		scanned:            map[*ssa.Function]bool{},
	}
}

func newTier2Analyzer(h *Hasher, prog *program, metas []listPkg) *tier2Analyzer {
	return newTier2Base(h, prog, metas).analyzer()
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
		testMain:       p.Name == "main" && path == a.prog.PkgPath+".test",
		decls:          map[types.Object]ast.Node{},
		linknames:      map[types.Object]string{},
		linknameByName: map[string]string{},
	}
	if meta != nil {
		idx.cache = meta.Module != nil && !meta.Module.Main && a.h.underCache(meta.Dir)
	} else if p.Module != nil {
		idx.cache = !p.Module.Main && a.h.underCache(p.Dir)
	}
	idx.mutable = !idx.std && !idx.testMain && !idx.cache
	if idx.id == "" {
		idx.id = path
	}

	for _, f := range p.Syntax {
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
				text = strings.TrimSpace(strings.TrimPrefix(text, "/*"))
				text = strings.TrimSpace(strings.TrimSuffix(text, "*/"))
				fields := strings.Fields(text)
				if len(fields) >= 3 && fields[0] == "go:linkname" {
					idx.linknameByName[fields[1]] = fields[2]
				}
				if strings.HasPrefix(text, "go:wasmimport") {
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
							// A later const spec can inherit expression/type/iota context from
							// earlier specs, so a used const hashes the whole group.
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
							}
						}
					case *ast.TypeSpec:
						if obj := p.TypesInfo.Defs[s.Name]; obj != nil {
							addTypeDeclaration(idx, obj, s)
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

func (a *tier2Analyzer) addFunction(fn *ssa.Function) {
	if fn == nil {
		return
	}
	if origin := fn.Origin(); origin != nil {
		fn = origin
	}
	idx := a.idxForFunction(fn)
	if idx == nil || idx.std || idx.cache || idx.testMain {
		return
	}
	if fn.Synthetic == "package initializer" || (fn.Name() == "init" && fn.Object() == nil) {
		a.addStartupPackage(idx)
		return
	}
	if obj := fn.Object(); obj != nil {
		a.enqueueObject(obj)
		return
	}
	if parent := fn.Parent(); parent != nil {
		a.addFunction(parent)
	}
}

func (a *tier2Analyzer) addStartupPackage(idx *pkgIndex) {
	if idx == nil || !idx.mutable {
		return
	}
	a.markPackage(idx)
	for _, n := range idx.vars {
		a.scanNodeRefs(idx, n)
	}
	for _, n := range idx.inits {
		a.scanNodeRefs(idx, n)
	}
}

func (a *tier2Analyzer) scanFunction(fn *ssa.Function) {
	if fn == nil || a.skipOriginScan[fn] {
		return
	}
	idx := a.idxForFunction(fn)
	if idx == nil || idx.testMain {
		return
	}
	if a.propertyHarnessAudited(idx.path) {
		// Audited property-harness surface: bodies are never walked -
		// the boundary gate at the call site is the whole judgment
		// (REQ-closure-observability-analysis).
		return
	}
	if !idx.std {
		a.markFilePackage(idx)
		if obj := fn.Object(); obj != nil {
			if target := a.linknameTarget(idx, obj); target != "" {
				a.addLinknameTarget(target)
			}
		}
	}
	if len(fn.Blocks) == 0 {
		return
	}
	if a.scanned[fn] {
		return
	}
	a.scanned[fn] = true
	classified, classifiedOK := classBEffectForFunction(fn)
	suppressNestedFileIO := idx.std && classifiedOK && classified.kind == externalEffectFileIO
	if !idx.std && idx.wasmImport {
		effect := opaqueExternalEffect(externalEffectLinkage, "reaches go:wasmimport")
		effect.unrefinable = true
		a.recordExternalEffect(effect)
	}
	if idx.cache && hasExternalCgoMeta(idx.meta) {
		effect := opaqueExternalEffect(externalEffectNative, "reaches cgo external library")
		effect.unrefinable = true
		a.recordExternalEffect(effect)
	}
	if idx.cache {
		a.scanCacheFunctionRefs(idx, fn)
	}
	if idx.std && (classifiedOK && classified.kind == externalEffectFileIO || atomicObservabilityOperation(fn) || harnessLoggingFunction(fn) || auditedHarnessSubtestDriver(fn) || harnessFuzzDriver(fn)) {
		return
	}
	var ops [16]*ssa.Value
	for _, block := range fn.Blocks {
		if a.contextErr() != nil {
			return
		}
		for _, instr := range block.Instrs {
			if v, ok := instr.(ssa.Value); ok {
				a.addValueType(idx, v)
			}
			for _, op := range instr.Operands(ops[:0]) {
				if op == nil || *op == nil {
					continue
				}
				a.scanValue(idx, *op)
			}
			fromRTA := a.rtaReach[fn]
			if idx.std {
				fromRTA = false
			}
			a.scanInstruction(idx, fn, instr, fromRTA, suppressNestedFileIO)
		}
	}
}

func atomicObservabilityOperation(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	pkgPath, name := funcPkgPath(fn), functionSymbolName(fn)
	if pkgPath == "testing" && name == "TempDir" || pkgPath == "path/filepath" && name == "Join" {
		return true
	}
	if pkgPath == "os" {
		switch name {
		case "WriteFile", "Remove", "RemoveAll":
			return true
		}
	}
	return false
}

func (a *tier2Analyzer) scanCacheFunctionRefs(idx *pkgIndex, fn *ssa.Function) {
	if idx == nil || fn == nil {
		return
	}
	if origin := fn.Origin(); origin != nil {
		fn = origin
	}
	obj := fn.Object()
	if obj == nil {
		if fn.Synthetic == "package initializer" || fn.Name() == "init" {
			for _, n := range idx.vars {
				a.scanNodeRefs(idx, n)
			}
			for _, n := range idx.inits {
				a.scanNodeRefs(idx, n)
			}
		}
		return
	}
	obj = originObject(obj)
	node := idx.decls[obj]
	if node == nil {
		a.requestWiden("missing cache function declaration for " + obj.String())
		return
	}
	a.scanNodeRefs(idx, node)
}

func (a *tier2Analyzer) scanValue(callerIdx *pkgIndex, v ssa.Value) {
	if v == nil {
		return
	}
	a.addValueType(a.idxForFunction(v.Parent()), v)
	switch x := v.(type) {
	case *ssa.Global:
		if obj := x.Object(); obj != nil {
			// No source-only exemption here, deliberately: the
			// audited-pure packages (io, encoding/xml, ...) depend on
			// this arm flagging their exported mutable vars (io.EOF,
			// xml.HTMLEntity) - exempting them would unsound the
			// audited set.
			if callerIdx != nil && !callerIdx.std && obj.Pkg() != nil && isStdImportPath(obj.Pkg().Path()) {
				a.recordExternalEffect(symbolExternalEffect(externalEffectUnauditedStandard, obj.Pkg().Path(), obj.Name(), "reaches standard global "+obj.Pkg().Path()+"."+obj.Name()))
			}
			a.enqueueObject(obj)
		}
	case *ssa.Function:
		a.addFunction(x)
	}
}

func isOSFileType(t types.Type) bool {
	if pointer, ok := types.Unalias(t).(*types.Pointer); ok {
		t = pointer.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "os" && named.Obj().Name() == "File"
}

func (a *tier2Analyzer) scanInstruction(idx *pkgIndex, caller *ssa.Function, instr ssa.Instruction, fromRTA, suppressNestedFileIO bool) {
	// A reference to a flag-backed package variable is the registration
	// channel's read side: the value changes at flag.Parse -
	// command-line input the test log cannot audit - and an address
	// escaping into the flow can only be read or laundered, so the
	// operand reference itself refuses
	// (REQ-closure-observability-analysis).
	recordFlagBackedReferences(a.flagBacked, a.recordExternalEffect, instr)
	switch x := instr.(type) {
	case ssa.CallInstruction:
		a.scanCall(idx, caller, x, fromRTA, suppressNestedFileIO)
	case *ssa.MakeInterface:
		a.addInterfaceMethodSet(x.X.Type())
	case *ssa.Field:
		if effect, ok := testingRuntimeFieldEffect(x.X.Type(), x.Field); ok {
			a.recordExternalEffect(effect)
		}
	case *ssa.FieldAddr:
		if effect, ok := testingRuntimeFieldEffect(x.X.Type(), x.Field); ok {
			a.recordExternalEffect(effect)
		}
	}
}

func testingRuntimeFieldReason(t types.Type, index int) string {
	effect, ok := testingRuntimeFieldEffect(t, index)
	if !ok {
		return ""
	}
	return effect.reason
}

func testingRuntimeFieldEffect(t types.Type, index int) (externalEffect, bool) {
	if pointer, ok := types.Unalias(t).(*types.Pointer); ok {
		t = pointer.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "testing" {
		return externalEffect{}, false
	}
	structure, ok := named.Underlying().(*types.Struct)
	if !ok || index < 0 || index >= structure.NumFields() {
		return externalEffect{}, false
	}
	if name := structure.Field(index).Name(); name == "N" {
		return symbolExternalEffect(externalEffectTestRuntime, "testing", "B.N", "reaches testing.B.N (test runtime configuration)"), true
	}
	return externalEffect{}, false
}

func (a *tier2Analyzer) scanCall(callerIdx *pkgIndex, caller *ssa.Function, site ssa.CallInstruction, fromRTA, suppressNestedFileIO bool) {
	c := site.Common()
	if c == nil {
		return
	}
	callerStd := callerIdx != nil && callerIdx.std
	if c.IsInvoke() && observableDirEntryCall(site) {
		return
	}
	// For an enumeration-closed subject the operand walk crosses
	// subject-attributed parameters through to the root's whole-view
	// caller sites — that crossing is the enumeration design itself.
	// Every other subject keeps the local walk: classifiability stays a
	// property of the dispatch shape, never of what a crossed-in
	// target's effects happen to be (the harnesswrap pin).
	operandClosed := subjectClosedDynamicValue(c.Value, make(map[ssa.Value]bool), a.localHarnessView())
	if !operandClosed && a.fresh != nil && a.fresh.enumRoot != nil {
		operandClosed = subjectClosedDynamicValue(c.Value, make(map[ssa.Value]bool), a.fresh)
	}
	resolved := fromRTA && a.rtaResolved[site] && !a.openWorld && operandClosed
	if c.IsInvoke() && !resolved && !callerStd && !(fromRTA && a.harnessOnlyInvokes[site] && subjectClosedDynamicValue(c.Value, make(map[ssa.Value]bool), a.fresh)) {
		a.requestWiden("interface invoke outside RTA")
	}
	if !c.IsInvoke() && c.StaticCallee() == nil {
		if _, ok := c.Value.(*ssa.Builtin); !ok && !callerStd && !resolved {
			a.requestWiden("computed function call in " + caller.String())
		}
	}
	callee := c.StaticCallee()
	if callee == nil {
		return
	}
	pkgPath, name := funcPkgPath(callee), functionSymbolName(callee)
	// A synthetic interface-method wrapper — any interface, the harness
	// included — performs the real dispatch inside a body no walk scans,
	// so the receiver's provenance is judged at the call site: a wrapper
	// over sibling-planted shared state refuses exactly as the direct
	// invoke would, while a subject-closed receiver keeps the wrapped
	// method's ordinary classification.
	if !callerStd && syntheticInterfaceMethodWrapper(callee) {
		receiver := wrapperReceiver(c, callee)
		if receiver == nil || !subjectClosedDynamicValue(receiver, make(map[ssa.Value]bool), a.fresh) {
			a.requestWiden("interface dispatch on unattributable state in " + caller.String())
			return
		}
	}
	if auditedHarnessLogging(pkgPath, name) {
		a.recordExternalEffect(harnessLoggingEffect(name))
		return
	}
	if auditedHarnessSubtestDriver(callee) {
		// The callback is subject flow reached through the harness's own
		// dispatch and classified at its own sites; the driver itself is
		// an admitted harness fact, never descended into
		// (REQ-closure-observability-analysis's subtest-driver channel).
		a.recordExternalEffect(harnessSubtestDriverEffect())
		return
	}
	if !callerStd && a.propertyHarnessAudited(pkgPath) {
		// The property-harness boundary gate: harness bodies are never
		// scanned, so every dynamic-carrying argument must be judged
		// here - judged callables become subject flow through the
		// harness's own dispatch; a judged call passes silently
		// exactly as the exempted standard harness does
		// (REQ-closure-observability-analysis).
		if !propertyHarnessClosedArgs(c, a.fresh) {
			a.requestWiden("property-harness argument is not locally closed in " + caller.String())
		}
		return
	}
	if observableFileMethod(callee) {
		if len(c.Args) != 0 && fileValueFromAdmittedOpen(c.Args[0], make(map[ssa.Value]bool)) {
			return
		}
		a.recordExternalEffect(symbolExternalEffect(externalEffectFileIO, "os", "File."+name, "reaches os.File."+name+" on an unattributed file handle (file I/O)"))
		return
	}
	effect, classified := classBEffect(pkgPath, name)
	calleeIdx := a.idxForFunction(callee)
	if !classified && name != "init" && !callerStd && calleeIdx != nil && calleeIdx.std && !isStandardFallbackExempt(pkgPath) && !classBPureStandard(pkgPath, name) && !auditedSyncSymbol(pkgPath, name) && !auditedRuntimeTypeSymbol(pkgPath, name) {
		effect = symbolExternalEffect(externalEffectUnauditedStandard, pkgPath, name, "reaches unaudited standard operation "+pkgPath+"."+name)
		classified = true
	}
	if osOpenFileMayMutate(callee, pkgPath, name, c) {
		effect = symbolExternalEffect(externalEffectFilesystemMutation, pkgPath, name, "reaches os.OpenFile (filesystem mutation)")
		classified = true
	}
	if !classified && syscallOpenMayCreate(pkgPath, name, c) {
		effect = symbolExternalEffect(externalEffectFilesystemMutation, pkgPath, name, "reaches "+pkgPath+"."+name+" (filesystem mutation)")
		classified = true
	}
	if classified && fmtFprintFamily(pkgPath, name) && len(c.Args) != 0 &&
		inMemoryFormattedSink(c.Args[0], make(map[ssa.Value]bool), map[ssa.Value]bool{}, a.fresh) {
		// Sprint-equivalent: the writer provably pins an audited
		// in-memory sink, so the formatted bytes never leave process
		// memory (the writer-sink admission). Argument methods stay
		// visible to reachability exactly as for the Sprint family.
		classified = false
	}
	if classified {
		effect.observable = observableCallEffect(effect, c, site, a.fresh)
		if callerStd && (effect.kind == externalEffectFilesystemMutation || effect.kind == externalEffectPathMutation) {
			return
		}
		// The flag package's own prints are help-path only - usage
		// output, Parse errors, and redefinition panics - none of which
		// execute in a run that neither fails Parse nor prints help; a
		// redefinition panic crashes loudly, never a silent input. The
		// registration admission would otherwise be defeated by the
		// internals it statically reaches
		// (REQ-closure-observability-analysis).
		if callerIdx != nil && callerIdx.path == "flag" && effect.kind == externalEffectFormattedOutput {
			return
		}
		if !(suppressNestedFileIO && effect.kind == externalEffectFileIO) {
			a.recordExternalEffect(effect)
		}
	}
	calleeStd := isStdImportPath(pkgPath)
	if !fromRTA || (!callerStd && calleeStd && !isBenchmarkHarnessPath(pkgPath)) {
		a.scanFunction(callee)
	}
	if !callerStd && pkgPath == "reflect" && (name == "Call" || name == "CallSlice" || name == "MakeFunc" || name == "MethodByName") {
		a.requestWiden("reflect dispatch")
	}
}

func (a *tier2Analyzer) addInterfaceMethodSet(t types.Type) {
	if !a.hasNonStdNamedType(t) {
		return
	}
	for _, mt := range []types.Type{t, types.NewPointer(t)} {
		set := types.NewMethodSet(mt)
		for i := 0; i < set.Len(); i++ {
			if fn, ok := set.At(i).Obj().(*types.Func); ok {
				a.enqueueObject(fn)
			}
		}
	}
}

func (a *tier2Analyzer) hasNonStdNamedType(t types.Type) bool {
	found := false
	walkTypeGraph(t, false, map[types.Type]bool{}, func(t types.Type) bool {
		named, ok := t.(*types.Named)
		if !ok {
			return true
		}
		obj := named.Obj()
		if obj == nil || obj.Pkg() == nil {
			return true
		}
		if idx := a.idxByTypes[obj.Pkg()]; idx != nil {
			if !idx.std {
				found = true
				return false
			}
		} else if !isStdImportPath(obj.Pkg().Path()) {
			found = true
			return false
		}
		return true
	})
	return found
}

func (a *tier2Analyzer) drainObjects() error {
	for len(a.objectQueue) > 0 {
		if err := a.contextErr(); err != nil {
			return err
		}
		obj := a.objectQueue[0]
		a.objectQueue = a.objectQueue[1:]
		a.addObject(obj)
	}
	return nil
}

func (a *tier2Analyzer) contextErr() error {
	if a == nil || a.h == nil || a.h.ctx == nil {
		return nil
	}
	return a.h.contextErr()
}

func (a *tier2Analyzer) enqueueObject(obj types.Object) {
	if obj == nil || obj.Pkg() == nil || a.seenObjects[obj] {
		return
	}
	a.seenObjects[obj] = true
	a.objectQueue = append(a.objectQueue, obj)
}

func (a *tier2Analyzer) addObject(obj types.Object) {
	if obj == nil || obj.Pkg() == nil {
		return
	}
	idx := a.idxByTypes[obj.Pkg()]
	if idx == nil {
		if !isStdImportPath(obj.Pkg().Path()) {
			a.requestWiden("missing source metadata for " + obj.Pkg().Path())
		}
		return
	}
	a.addReverseLinknameTargets(obj)
	if fn, ok := obj.(*types.Func); ok {
		if ssaFn := a.prog.Prog.FuncValue(fn); ssaFn != nil {
			a.scanFunction(ssaFn)
		}
	}
	if !idx.std {
		if target := a.linknameTarget(idx, obj); target != "" {
			a.addLinknameTarget(target)
		}
	}
	if idx.std || idx.testMain {
		return
	}
	if !isPackageLevelObject(obj) {
		return
	}
	node := idx.decls[originObject(obj)]
	if idx.cache {
		a.addType(obj.Type())
		if node != nil {
			a.scanNodeRefs(idx, node)
		} else if _, ok := obj.(*types.Func); !ok {
			a.requestWiden("missing declaration for " + obj.String())
		}
		if fn, ok := obj.(*types.Func); ok {
			if ssaFn := a.prog.Prog.FuncValue(fn); ssaFn != nil {
				a.scanFunction(ssaFn)
			}
		}
		return
	}
	if node == nil {
		if _, ok := obj.(*types.Func); ok {
			// A func object with no source decl node is source-free: buildIndex
			// records a decl for every FuncDecl (incl. asm bodies and generic
			// origins), so this is a synthetic/instantiated func whose real body,
			// if any, is hashed through RTA (addFunction resolves fn.Origin() for
			// every reachable instantiation — incl. methods RTA marks reachable
			// when their concrete type is converted to an interface). Hashing its
			// signature suffices; widening here would only lose precision. A
			// non-func with no node is genuinely missing source → widen.
			a.addType(obj.Type())
			return
		}
		a.requestWiden("missing declaration for " + obj.String())
		return
	}
	a.markPackage(idx)
	a.addType(obj.Type())
	a.scanNodeRefs(idx, node)
	if fn, ok := obj.(*types.Func); ok {
		if ssaFn := a.prog.Prog.FuncValue(fn); ssaFn != nil {
			a.scanFunction(ssaFn)
		}
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

func (a *tier2Analyzer) linknameTarget(idx *pkgIndex, obj types.Object) string {
	if idx == nil || obj == nil {
		return ""
	}
	if target := idx.linknames[obj]; target != "" {
		return target
	}
	return idx.linknameByName[obj.Name()]
}

func (a *tier2Analyzer) addLinknameTarget(target string) {
	lastDot := strings.LastIndexByte(target, '.')
	if lastDot < 0 {
		a.requestWiden("unresolved go:linkname target " + target)
		return
	}
	pkgPath, name := target[:lastDot], target[lastDot+1:]
	effect, classified := classBEffect(pkgPath, name)
	if !classified && isStdImportPath(pkgPath) {
		effect = symbolExternalEffect(externalEffectLinkage, pkgPath, name, "reaches standard linkname target "+target)
		classified = true
	}
	if classified {
		a.recordExternalEffect(effect)
	}
	obj := a.objByName[pkgPath+"."+name]
	if obj == nil {
		a.requestWiden("unresolved go:linkname target " + target)
		return
	}
	a.enqueueObject(obj)
}

// walkTypeGraph visits the types reachable from t through the structural
// edges listed here — element, key, field, parameter, result, underlying,
// and (when typeArgs is set) type-argument — Unalias-normalized, each
// type at most once per seen map. Interfaces are deliberately terminal:
// their embedded and method types stay unwalked, and the carrier rule
// judges interface-typed state separately — adding interface edges would
// move verdicts. visit returning false stops the whole walk. Callers own
// seen: the analyzer's addType shares one map across calls so a type
// reached once is never re-walked; the per-call predicates pass fresh
// maps. The typeArgs edge stays addType-only: the predicates never
// walked it, and widening their reach could move a verdict.
func walkTypeGraph(t types.Type, typeArgs bool, seen map[types.Type]bool, visit func(types.Type) bool) {
	stop := false
	var walk func(types.Type)
	walk = func(t types.Type) {
		if t == nil || stop {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		if !visit(t) {
			stop = true
			return
		}
		switch tt := t.(type) {
		case *types.Named:
			if typeArgs {
				for i := 0; i < tt.TypeArgs().Len(); i++ {
					walk(tt.TypeArgs().At(i))
				}
			}
			walk(tt.Underlying())
		case *types.Pointer:
			walk(tt.Elem())
		case *types.Slice:
			walk(tt.Elem())
		case *types.Array:
			walk(tt.Elem())
		case *types.Map:
			walk(tt.Key())
			walk(tt.Elem())
		case *types.Chan:
			walk(tt.Elem())
		case *types.Signature:
			for _, tuple := range []*types.Tuple{tt.Params(), tt.Results()} {
				for i := 0; tuple != nil && i < tuple.Len(); i++ {
					walk(tuple.At(i).Type())
				}
			}
		case *types.Struct:
			for i := 0; i < tt.NumFields(); i++ {
				walk(tt.Field(i).Type())
			}
		}
	}
	walk(t)
}

// addValueType walks one SSA value's type and widens on a reachable
// unsafe pointer anywhere in it — the one judgment every value-typed
// scan site shares; std packages carry the toolchain guard instead.
func (a *tier2Analyzer) addValueType(idx *pkgIndex, v ssa.Value) {
	a.addType(v.Type())
	if idx != nil && !idx.std && typeUsesUnsafePointer(v.Type()) && !isOSFileType(v.Type()) {
		a.requestWiden("unsafe pointer reachable in " + idx.id)
	}
}

// addType enqueues every named type the walked structure carries. The
// walk Unalias-normalizes, so alias targets are enqueued even when the
// alias never appears in scanned syntax — a reach-widening whose only
// possible divergence direction is conservative: enqueues add scans,
// scans add effects and widens, never the reverse.
func (a *tier2Analyzer) addType(t types.Type) {
	walkTypeGraph(t, true, a.seenTypes, func(t types.Type) bool {
		if named, ok := t.(*types.Named); ok {
			a.enqueueObject(named.Obj())
		}
		return true
	})
}

func (a *tier2Analyzer) scanNodeRefs(idx *pkgIndex, node ast.Node) {
	if idx == nil || node == nil || idx.pkg.TypesInfo == nil {
		return
	}
	ast.Inspect(node, func(n ast.Node) bool {
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

func (a *tier2Analyzer) addReachedPackageFiles() error {
	pkgs := make([]*pkgIndex, 0, len(a.filePkgs))
	for idx := range a.filePkgs {
		pkgs = append(pkgs, idx)
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].id < pkgs[j].id })
	for _, idx := range pkgs {
		if err := a.contextErr(); err != nil {
			return err
		}
		if idx.meta == nil {
			a.requestWiden("missing file metadata for " + idx.id)
			continue
		}
		if idx.wasmImport {
			effect := opaqueExternalEffect(externalEffectLinkage, "reaches go:wasmimport")
			effect.unrefinable = true
			a.recordExternalEffect(effect)
		}
		if hasExternalCgoMeta(idx.meta) {
			effect := opaqueExternalEffect(externalEffectNative, "reaches cgo external library")
			effect.unrefinable = true
			a.recordExternalEffect(effect)
		}
		if idx.mutable {
			if hasCgoCallbackBlindspot(idx.meta) {
				modCache := ""
				if a.h != nil {
					modCache = a.h.modCache
				}
				if root := cgoIncludeRootOutsideDir(idx.meta, modCache); root != "" {
					return fmt.Errorf("closure: cgo include root outside package dir: %s", root)
				}
				// The blindspot's bytes ride the maximal hash; the
				// analyzer keeps only the escape checks — error
				// conditions — and the widen.
				all, err := allPackageFiles(idx.meta.Dir)
				if err != nil {
					return err
				}
				if include, err := cgoEscapingInclude(idx.meta, all); err != nil {
					return err
				} else if include != "" {
					return fmt.Errorf("closure: cgo include escapes package dir: %s", include)
				}
				a.requestWiden("cgo callback source in " + idx.id)
			}
		}
		if len(idx.meta.SFiles) == 0 {
			continue
		}
		// Assembly is never an analysis surface (REQ-closure-blindspot):
		// the package's effect blocks the observability proof and the
		// subject widens to the maximal closure, whose hash covers the
		// package directory whole. Only mutable-local and cache packages
		// enter this loop — toolchain assembly rides the toolchain guard.
		a.recordExternalEffect(opaqueExternalEffect(externalEffectNative, "reaches non-standard assembly"))
		a.requestWiden("non-toolchain assembly in " + idx.id)
	}
	return nil
}

// requestWiden keeps the lexicographically least reason: widen sites fire
// in map-driven walk order, and the reason lands verbatim in persisted
// proofs, so the selection must be a deterministic function of the reason
// SET (the recorded-evidence stability REQ-closure-observability-memo
// binds).
func (a *tier2Analyzer) requestWiden(reason string) {
	if !a.widen || reason < a.widenReason {
		a.widen = true
		a.widenReason = reason
	}
}

func (a *tier2Analyzer) recordExternalEffect(effect externalEffect) {
	a.collectExternalEffect(effect)
	rank := effectCauseRank(effect)
	if !a.unverifiable || rank > a.reasonRank || (rank == a.reasonRank && effect.reason < a.reason) {
		a.reason = effect.reason
		a.reasonRank = rank
	}
	a.unverifiable = true
}

func (a *tier2Analyzer) collectExternalEffect(effect externalEffect) bool {
	before := len(a.effects)
	a.effects = appendExternalEffect(a.effects, effect)
	return len(a.effects) != before
}

// effectCauseRank is the one cause-preference order both diagnostic
// projections share: the legacy single-reason projection keeps the
// highest-ranked recorded effect, and the observation proof's refusal
// names the highest-ranked blocking effect. Structural findings and
// mutations outrank the generic file read, which outranks ambient
// formatting and environment, which outrank the unaudited and
// test-runtime classifications; the audited harness fact is strictly
// weakest — it flips the legacy projection when it is the only effect
// but never displaces a causal classification.
func effectCauseRank(effect externalEffect) int {
	if effect.kind == externalEffectTestRuntime && effect.observable {
		return -1
	}
	if effect.packagePath == "" {
		// Opaque structural findings (receiver escapes, wasm imports, cgo
		// libraries) carry no symbol yet name the mechanism directly.
		return 4
	}
	switch effect.kind {
	case externalEffectUnauditedStandard, externalEffectTestRuntime:
		return 0
	case externalEffectFormattedOutput, externalEffectEnvironment:
		return 1
	case externalEffectFileIO:
		return 3
	default:
		return 4
	}
}

func isStandardFallbackExempt(pkgPath string) bool {
	// The testing harness itself is selected infrastructure. Its externally
	// observable helpers are classified before this fallback.
	return pkgPath == "testing" || isSourceOnlyStandardPackage(pkgPath)
}

func (a *tier2Analyzer) result() tier2Result {
	effects := append([]externalEffect(nil), a.effects...)
	// The accumulation order follows type/object walks that range over
	// maps; the proof's refusal names the highest-ranked blocking effect
	// with the projection order as tie-break, so the projection sorts
	// under a total order — recomputation must reproduce diagnostics
	// byte-for-byte (the recorded-evidence stability
	// REQ-closure-observability-memo binds).
	sort.Slice(effects, func(i, j int) bool { return effectLess(effects[i], effects[j]) })
	return tier2Result{effects: effects, widen: a.widen, widenReason: a.widenReason, unverifiable: a.unverifiable, reason: a.reason}
}

// effectLess is a total order over effects: field-lexicographic. The
// accumulator dedups by struct equality, so no two list elements compare
// equal and the sort is fully deterministic.
func effectLess(a, b externalEffect) bool {
	if a.kind != b.kind {
		return a.kind < b.kind
	}
	if a.packagePath != b.packagePath {
		return a.packagePath < b.packagePath
	}
	if a.symbol != b.symbol {
		return a.symbol < b.symbol
	}
	if a.detail != b.detail {
		return a.detail < b.detail
	}
	if a.reason != b.reason {
		return a.reason < b.reason
	}
	if a.unrefinable != b.unrefinable {
		return b.unrefinable
	}
	return !a.observable && b.observable
}

func classBEffectForFunction(fn *ssa.Function) (externalEffect, bool) {
	if fn == nil {
		return externalEffect{}, false
	}
	return classBEffect(funcPkgPath(fn), functionSymbolName(fn))
}

func functionSymbolName(fn *ssa.Function) string {
	if obj := fn.Object(); obj != nil {
		return obj.Name()
	}
	return fn.Name()
}

// harnessLoggingFunction gates both the body-scan cut and the
// dynamic-target admission on the same audited set, so a harness logging
// method reached through an interface method set or an RTA-resolved
// dispatch classifies exactly as a static call to it would.
func harnessLoggingFunction(fn *ssa.Function) bool {
	return fn != nil && auditedHarnessLogging(funcPkgPath(fn), functionSymbolName(fn))
}

func classBReasonForFunction(fn *ssa.Function) string {
	effect, ok := classBEffectForFunction(fn)
	if !ok {
		return ""
	}
	return effect.reason
}

func osOpenFileMayMutate(callee *ssa.Function, pkgPath, name string, c *ssa.CallCommon) bool {
	if pkgPath != "os" || name != "OpenFile" {
		return false
	}
	flags, known := openFileFlagsForCallee(callee, c)
	return !known || openFileFlagsMutate(flags)
}

func openFileFlags(c *ssa.CallCommon) (int64, bool) {
	if c == nil {
		return 0, false
	}
	return openFileFlagsForCallee(c.StaticCallee(), c)
}

func openFileFlagsForCallee(callee *ssa.Function, c *ssa.CallCommon) (int64, bool) {
	flagArg := 1
	if callee != nil && callee.Signature != nil && callee.Signature.Recv() != nil {
		flagArg = 2
	}
	if c == nil || len(c.Args) <= flagArg {
		return 0, false
	}
	return constInt(c.Args[flagArg])
}

func openFileFlagsMutate(flags int64) bool {
	const mutatingFlags = int64(os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREATE | os.O_TRUNC)
	return flags&mutatingFlags != 0
}

func ordinaryOpenFileFlagsObservable(flags int64) bool {
	return flags == 0
}

func recognizedOpenFileFlags(callee *ssa.Function, flags int64) bool {
	if callee == nil || callee.Object() == nil || callee.Object().Pkg() == nil {
		return false
	}
	scope := callee.Object().Pkg().Scope()
	var mask int64
	var writeOnly, readWrite int64
	for _, name := range []string{"O_WRONLY", "O_RDWR", "O_APPEND", "O_CREATE", "O_EXCL", "O_SYNC", "O_TRUNC"} {
		object, ok := scope.Lookup(name).(*types.Const)
		if !ok {
			return false
		}
		value, ok := constant.Int64Val(object.Val())
		if !ok {
			return false
		}
		mask |= value
		if name == "O_WRONLY" {
			writeOnly = value
		}
		if name == "O_RDWR" {
			readWrite = value
		}
	}
	access := flags & (writeOnly | readWrite)
	return flags&^mask == 0 && (access == 0 || access == writeOnly || access == readWrite)
}

func syscallOpenMayCreate(pkgPath, name string, c *ssa.CallCommon) bool {
	if pkgPath != "syscall" && pkgPath != "golang.org/x/sys/unix" {
		return false
	}
	flagArg := -1
	switch name {
	case "Open":
		flagArg = 1
	case "Openat":
		flagArg = 2
	default:
		return false
	}
	if c == nil || flagArg >= len(c.Args) {
		return true
	}
	v, ok := c.Args[flagArg].(*ssa.Const)
	if !ok {
		return true
	}
	flags, ok := constant.Int64Val(v.Value)
	if !ok {
		return true
	}
	return flags&int64(os.O_CREATE) != 0
}

func (a *tier2Analyzer) idxForFunction(fn *ssa.Function) *pkgIndex {
	for f := fn; f != nil; f = f.Parent() {
		if f.Pkg != nil && f.Pkg.Pkg != nil {
			return a.idxByTypes[f.Pkg.Pkg]
		}
		if obj := f.Object(); obj != nil && obj.Pkg() != nil {
			return a.idxByTypes[obj.Pkg()]
		}
	}
	return nil
}

func funcPkgPath(fn *ssa.Function) string {
	for f := fn; f != nil; f = f.Parent() {
		if f.Pkg != nil && f.Pkg.Pkg != nil {
			return f.Pkg.Pkg.Path()
		}
		if obj := f.Object(); obj != nil && obj.Pkg() != nil {
			return obj.Pkg().Path()
		}
	}
	return ""
}

func isPackageLevelObject(obj types.Object) bool {
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	if obj.Parent() == obj.Pkg().Scope() {
		return true
	}
	_, isFunc := obj.(*types.Func)
	return isFunc
}

func linknamesFromDoc(doc *ast.CommentGroup) map[string]string {
	out := map[string]string{}
	if doc == nil {
		return out
	}
	for _, c := range doc.List {
		text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
		fields := strings.Fields(text)
		if len(fields) >= 3 && fields[0] == "go:linkname" {
			out[fields[1]] = fields[2]
		}
	}
	return out
}

func typeUsesUnsafePointer(t types.Type) bool {
	found := false
	walkTypeGraph(t, false, map[types.Type]bool{}, func(t types.Type) bool {
		if basic, ok := t.(*types.Basic); ok && basic.Kind() == types.UnsafePointer {
			found = true
			return false
		}
		if n, ok := t.(*types.Named); ok {
			if obj := n.Obj(); obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "unsafe" && obj.Name() == "Pointer" {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func hasExternalCgo(flags []string) bool {
	for _, f := range flags {
		for _, tok := range expandLinkerFlag(f) {
			if isExternalLinkToken(tok) {
				return true
			}
		}
	}
	return false
}

// expandLinkerFlag splits a linker pass-through flag into its sub-arguments. gcc
// carries multiple linker arguments in one comma-joined token (`-Wl,-Bstatic,-lfoo,
// -Bdynamic`), so a `-l` element can hide inside a single whitespace token; without
// expanding it, an external library links unseen and the closure reports `valid`
// while that library changes (REQ-closure-blindspot, REQ-fresh-verdict). `-Xlinker <arg>` needs no expansion —
// go list already emits its argument as a separate token.
func expandLinkerFlag(f string) []string {
	if rest, ok := strings.CutPrefix(f, "-Wl,"); ok {
		return strings.Split(rest, ",")
	}
	return []string{f}
}

func isExternalLinkToken(f string) bool {
	return strings.HasPrefix(f, "-l") || f == "-framework" || strings.Contains(f, "-framework") || strings.HasSuffix(f, ".a") || strings.HasSuffix(f, ".dylib") || strings.HasSuffix(f, ".so") || strings.Contains(f, ".dylib.") || strings.Contains(f, ".so.")
}

func hasExternalCgoMeta(p *listPkg) bool {
	return p != nil && (hasExternalCgo(p.CgoLDFLAGS) || len(p.CgoPkgConfig) > 0)
}

func hasCgoCallbackBlindspot(p *listPkg) bool {
	if p == nil {
		return false
	}
	for _, files := range [][]string{
		p.CgoFiles, p.CFiles, p.CXXFiles, p.MFiles, p.HFiles, p.FFiles,
		p.SwigFiles, p.SwigCXXFiles, p.SysoFiles,
	} {
		if len(files) > 0 {
			return true
		}
	}
	return false
}

func isStdImportPath(path string) bool {
	if path == "" || path == "C" {
		return false
	}
	first := path
	if i := strings.IndexByte(path, '/'); i >= 0 {
		first = path[:i]
	}
	return !strings.Contains(first, ".")
}

func isBenchmarkHarnessPath(path string) bool {
	return path == "testing" || strings.HasPrefix(path, "testing/")
}
