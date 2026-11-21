package propharness

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
	"github.com/greatliontech/gofresh/internal/trace"
)

var (
	harnessPureImageImports        = map[string]bool{"image": true, "image/color": true, "image/png": true}
	harnessSymbolAuditedStdImports = map[string]bool{"context": true, "fmt": true, "math": true, "sync": true, "sync/atomic": true}
	harnessProtocolStdImports      = map[string]bool{
		"flag": true, "hash/maphash": true, "html/template": true, "log": true,
		"os": true, "path/filepath": true, "reflect": true, "runtime": true,
		"testing": true, "testing/synctest": true, "time": true,
	}
)

// IsAllowedHarnessStdImport reports whether impPath belongs to the closed set
// of standard-library packages a verified property harness may import.
func IsAllowedHarnessStdImport(impPath string) bool {
	if impPath == "" || impPath == "C" || impPath == "unsafe" || impPath == "runtime/cgo" || impPath == "embed" {
		return false
	}
	return auditset.PurePackage(impPath) ||
		harnessPureImageImports[impPath] ||
		harnessSymbolAuditedStdImports[impPath] ||
		harnessProtocolStdImports[impPath]
}

var (
	harnessTemplateTypes = map[string]bool{"Template": true, "CSS": true}
	harnessTemplateFuncs = map[string]bool{"New": true, "Must": true}
	harnessTemplateMeths = map[string]bool{"Parse": true, "Execute": true}
	harnessOSFuncs       = map[string]bool{
		"LookupEnv": true, "Getenv": true, "Open": true, "Create": true, "CreateTemp": true,
		"MkdirAll": true, "Rename": true, "Remove": true, "Getpid": true, "IsNotExist": true,
	}
	harnessOSTypes = map[string]bool{"File": true, "FileMode": true, "FileInfo": true, "PathError": true}
	harnessOSMeths = map[string]bool{"Read": true, "Write": true, "WriteString": true, "Close": true, "Name": true, "Sync": true, "Stat": true}
	harnessMHTypes = map[string]bool{"Hash": true, "Seed": true}
	harnessMHFuncs = map[string]bool{"MakeSeed": true, "Bytes": true, "String": true}
	harnessMHMeths = map[string]bool{
		"Write": true, "WriteByte": true, "WriteString": true, "Sum64": true, "Reset": true,
		"SetSeed": true, "Seed": true, "BlockSize": true, "Size": true, "Sum": true,
	}
	harnessRuntimeTypes  = map[string]bool{"Frame": true, "Frames": true}
	harnessRuntimeConsts = map[string]bool{"GOOS": true, "GOARCH": true, "Compiler": true}
	harnessRuntimeFuncs  = map[string]bool{"Callers": true, "CallersFrames": true, "Goexit": true}
	harnessLogMeths      = map[string]bool{"Printf": true, "Print": true, "Println": true, "Writer": true, "Output": true, "Prefix": true, "Flags": true}
	harnessTestingTypes  = map[string]bool{"T": true, "B": true, "F": true, "TB": true}
	harnessTestingFuncs  = map[string]bool{"Short": true, "Verbose": true}
	harnessTestingMeths  = map[string]bool{
		"Helper": true, "Name": true, "Deadline": true, "Log": true, "Logf": true,
		"Error": true, "Errorf": true, "Fatal": true, "Fatalf": true, "Skip": true,
		"Skipf": true, "SkipNow": true, "Skipped": true, "Fail": true, "FailNow": true,
		"Failed": true, "Cleanup": true, "Context": true, "Output": true, "Run": true,
	}
	harnessSynctestFuncs = map[string]bool{"Test": true, "Wait": true}
	harnessReflectTypes  = map[string]bool{"Type": true, "Value": true, "Kind": true, "StructField": true, "StructTag": true, "Method": true}
	harnessReflectKinds  = map[string]bool{
		"Invalid": true, "Bool": true, "Int": true, "Int8": true, "Int16": true, "Int32": true, "Int64": true,
		"Uint": true, "Uint8": true, "Uint16": true, "Uint32": true, "Uint64": true, "Uintptr": true,
		"Float32": true, "Float64": true, "Complex64": true, "Complex128": true,
		"Array": true, "Map": true, "Pointer": true, "Ptr": true, "Slice": true, "String": true, "Struct": true,
	}
	harnessReflectFuncs = map[string]bool{
		"DeepEqual": true, "TypeOf": true, "ValueOf": true, "Zero": true, "New": true,
		"Indirect": true, "MakeSlice": true, "Append": true, "MakeMap": true, "MakeMapWithSize": true,
	}
	harnessReflectTypeMeths = map[string]bool{
		"Kind": true, "Elem": true, "Key": true, "Len": true, "NumField": true, "Field": true,
		"NumMethod": true, "Method": true, "Name": true, "PkgPath": true, "String": true,
		"Size": true, "Comparable": true, "AssignableTo": true, "ConvertibleTo": true, "Implements": true, "Bits": true,
	}
	harnessReflectValMeths = map[string]bool{
		"Type": true, "Kind": true, "Elem": true, "Field": true, "NumField": true, "NumMethod": true,
		"Index": true, "MapIndex": true, "Len": true, "Cap": true, "IsNil": true, "IsValid": true, "IsZero": true,
		"CanSet": true, "CanInterface": true, "Interface": true, "Convert": true, "Set": true, "SetBool": true,
		"SetInt": true, "SetUint": true, "SetFloat": true, "SetBytes": true, "SetString": true,
		"SetMapIndex": true, "Method": true, "Bool": true, "Int": true, "Uint": true, "Float": true, "String": true, "Bytes": true,
	}
	harnessReflectTagMeths = map[string]bool{"Get": true, "Lookup": true}
)

func verifyHarnessStdSymbolUses(g *harnessGraph) (bool, string) {
	info, pkgTypes := g.info, g.pkgTypes
	for ident, obj := range info.Uses {
		if ident != nil && obj != nil && obj.Pkg() != nil && obj.Pkg() != pkgTypes {
			if !checkHarnessStdObjectAllowed(obj.Pkg().Path(), obj) {
				return false, "disallowed std use: " + obj.Pkg().Path() + "." + obj.Name()
			}
		}
	}
	for _, sel := range info.Selections {
		if sel != nil && sel.Obj() != nil && sel.Obj().Pkg() != nil && sel.Obj().Pkg() != pkgTypes {
			obj := sel.Obj()
			if !checkHarnessStdObjectAllowed(obj.Pkg().Path(), obj) {
				return false, "disallowed std selection: " + obj.Pkg().Path() + "." + obj.Name()
			}
		}
	}
	return true, ""
}

func checkHarnessStdObjectAllowed(impPath string, obj types.Object) bool {
	if v, ok := obj.(*types.Var); ok && v.IsField() {
		return true
	}
	_, isVar := obj.(*types.Var)
	_, isConst := obj.(*types.Const)
	_, isType := obj.(*types.TypeName)
	fn, isFunc := obj.(*types.Func)
	hasRecv := isFunc && fn.Signature().Recv() != nil

	if auditset.PurePackage(impPath) || harnessPureImageImports[impPath] {
		if !isVar {
			return true
		}
		if auditset.StandardSentinelGlobal(impPath, obj.Name()) || impPath == "unicode" {
			return true
		}
		switch impPath + "." + obj.Name() {
		case "encoding/binary.NativeEndian",
			"encoding/base64.StdEncoding", "encoding/base64.RawStdEncoding", "encoding/base64.URLEncoding", "encoding/base64.RawURLEncoding",
			"image/color.Black", "image/color.White", "image/color.Transparent", "image/color.Opaque":
			return true
		}
		return false
	}

	switch impPath {
	case "context":
		if isVar {
			return auditset.StandardSentinelGlobal("context", obj.Name())
		}
		return auditset.Symbol("context", obj.Name())
	case "fmt":
		return !isVar && (auditset.Symbol("fmt", obj.Name()) || auditset.FmtWriterFunc(obj.Name()))
	case "math":
		return !isVar && obj.Name() != "FMA"
	case "sync":
		return !isVar && auditset.SyncSurfaceName(obj.Name())
	case "sync/atomic":
		return !isVar && (auditset.Symbol("sync/atomic", obj.Name()) || (isFunc && auditset.ReceiverMethod(fn, "sync/atomic", auditset.AtomicMethod)))
	case "flag":
		return isFunc && !hasRecv && auditset.FlagSurface(fn.Name()) == auditset.FlagRolePointerRegistration
	case "path/filepath":
		return !isVar && (auditset.Symbol("path/filepath", obj.Name()) || (isFunc && !hasRecv && fn.Name() == "Glob"))
	case "time":
		if isVar {
			return false
		}
		if auditset.Symbol("time", obj.Name()) || (isType && obj.Name() == "Location") {
			return true
		}
		if !isFunc {
			return false
		}
		if !hasRecv {
			return fn.Name() == "Now" || fn.Name() == "Since" || fn.Name() == "Until"
		}
		return auditset.ReceiverMethod(fn, "time", auditset.TimeMethod)
	case "html/template":
		if isType {
			return harnessTemplateTypes[obj.Name()]
		}
		if !isFunc {
			return false
		}
		if !hasRecv {
			return harnessTemplateFuncs[fn.Name()]
		}
		_, tn := recvNamedTypeName(fn.Signature())
		return tn == "Template" && harnessTemplateMeths[fn.Name()]
	case "os":
		return (isType && harnessOSTypes[obj.Name()]) || isConst || (isVar && obj.Name() == "Stdout") ||
			(isFunc && ((!hasRecv && harnessOSFuncs[fn.Name()]) || (hasRecv && harnessOSMeths[fn.Name()])))
	case "hash/maphash":
		return (isType && harnessMHTypes[obj.Name()]) ||
			(isFunc && ((!hasRecv && harnessMHFuncs[fn.Name()]) || (hasRecv && harnessMHMeths[fn.Name()])))
	case "runtime":
		return (isType && harnessRuntimeTypes[obj.Name()]) || (isConst && harnessRuntimeConsts[obj.Name()]) ||
			(isFunc && ((!hasRecv && harnessRuntimeFuncs[fn.Name()]) || (hasRecv && fn.Name() == "Next")))
	case "log":
		return (isType && obj.Name() == "Logger") || isConst ||
			(isFunc && ((!hasRecv && fn.Name() == "New") || (hasRecv && harnessLogMeths[fn.Name()])))
	case "testing":
		return (isType && harnessTestingTypes[obj.Name()]) ||
			(isFunc && ((!hasRecv && harnessTestingFuncs[fn.Name()]) || (hasRecv && harnessTestingMeths[fn.Name()])))
	case "testing/synctest":
		return isFunc && !hasRecv && harnessSynctestFuncs[fn.Name()]
	case "reflect":
		if isType {
			return harnessReflectTypes[obj.Name()]
		}
		if isConst {
			named, ok := types.Unalias(obj.Type()).(*types.Named)
			return ok && named.Obj() != nil && named.Obj().Name() == "Kind" && harnessReflectKinds[obj.Name()]
		}
		if !isFunc {
			return false
		}
		if !hasRecv {
			return harnessReflectFuncs[fn.Name()]
		}
		switch _, tn := recvNamedTypeName(fn.Signature()); tn {
		case "Type":
			return harnessReflectTypeMeths[fn.Name()]
		case "Value":
			return harnessReflectValMeths[fn.Name()]
		case "StructTag":
			return harnessReflectTagMeths[fn.Name()]
		case "StructField", "Method":
			return fn.Name() == "IsExported"
		case "Kind":
			return fn.Name() == "String"
		case "":
			if fn.Pkg() != nil && fn.Pkg().Scope() != nil {
				if typeObj := fn.Pkg().Scope().Lookup("Type"); typeObj != nil {
					if mObj, _, _ := types.LookupFieldOrMethod(typeObj.Type(), false, fn.Pkg(), fn.Name()); mObj == fn {
						return harnessReflectTypeMeths[fn.Name()]
					}
				}
			}
		}
	}
	return false
}

type harnessVarEntry struct {
	v    *types.Var
	spec *ast.ValueSpec
	val  ast.Expr
}

type harnessParamKey struct {
	fn  *types.Func
	idx int
}

type ambientOpSet struct {
	inInitOrGlobal bool
	funcs          map[*types.Func]bool
}

func (s *ambientOpSet) record(ownerOrig *types.Func, inInit bool) {
	if inInit || ownerOrig == nil {
		s.inInitOrGlobal = true
		return
	}
	if s.funcs == nil {
		s.funcs = map[*types.Func]bool{}
	}
	s.funcs[ownerOrig] = true
}

type harnessGraph struct {
	ctx                        context.Context
	domain                     trace.Domain
	pkg                        *packages.Package
	info                       *types.Info
	pkgTypes                   *types.Package
	idx                        *refconfine.PkgIndex
	screen                     *harnessScreen
	declFuncs                  map[*types.Func]*ast.FuncDecl
	allDecls                   map[*types.Func]*ast.FuncDecl
	declaredNamedTypes         []*types.Named
	pkgVars                    []harnessVarEntry
	pkgVarSet                  map[*types.Var]harnessVarEntry
	initOnly                   map[*types.Func]bool
	initReached                map[*types.Func]bool
	callSitesByFunc            map[*types.Func][]*ast.CallExpr
	mutatedNamedStructs        map[*types.Named]bool
	mutatedOrAddrLocals        map[*types.Var]bool
	generatorFieldsWriteOnceOK bool

	strictCallersOf     map[*types.Func]map[*types.Func]bool
	flagDirectCallersOf map[*types.Func]map[*types.Func]bool
	flagCallEdges       map[*types.Func]map[*ast.CallExpr]*types.Func
	envFlagReadIdents   map[*types.Var]map[*ast.Ident]*types.Func

	maphashOps        ambientOpSet
	driverOnlyOps     ambientOpSet
	testingCfgOps     ambientOpSet
	reflectSynthSeeds map[*types.Func]bool
}

func (g *harnessGraph) findFuncParamIndex(paramObj *types.Var) (*types.Func, int) {
	if paramObj != nil && g.idx != nil && g.idx.CallSites != nil {
		if cp, ok := g.idx.CallSites.Params[paramObj]; ok {
			return cp.Fn, cp.Index
		}
	}
	return nil, -1
}

func (g *harnessGraph) isFuncValueTaken(fn *types.Func) bool {
	return fn == nil || g.idx == nil || g.idx.FuncValueTaken[fn.Origin()]
}

func (g *harnessGraph) isReassignedParam(v *types.Var) bool {
	return v == nil || g.idx == nil || g.idx.CallSites == nil || g.idx.CallSites.Written[v]
}

func buildHarnessGraph(ctx context.Context, domain trace.Domain, pkg *packages.Package, idx *refconfine.PkgIndex, screen *harnessScreen) (*harnessGraph, string) {
	if idx == nil {
		idx = refconfine.BuildPkgIndex(pkg)
	}
	if idx == nil {
		return nil, "failed to build package index"
	}
	info, pkgTypes := pkg.TypesInfo, pkg.Types
	g := &harnessGraph{
		ctx:                        ctx,
		domain:                     domain,
		pkg:                        pkg,
		info:                       info,
		pkgTypes:                   pkgTypes,
		idx:                        idx,
		screen:                     screen,
		declFuncs:                  map[*types.Func]*ast.FuncDecl{},
		allDecls:                   map[*types.Func]*ast.FuncDecl{},
		pkgVarSet:                  map[*types.Var]harnessVarEntry{},
		initOnly:                   map[*types.Func]bool{},
		initReached:                map[*types.Func]bool{},
		callSitesByFunc:            map[*types.Func][]*ast.CallExpr{},
		mutatedNamedStructs:        map[*types.Named]bool{},
		mutatedOrAddrLocals:        map[*types.Var]bool{},
		generatorFieldsWriteOnceOK: true,
		strictCallersOf:            map[*types.Func]map[*types.Func]bool{},
		flagDirectCallersOf:        map[*types.Func]map[*types.Func]bool{},
		flagCallEdges:              map[*types.Func]map[*ast.CallExpr]*types.Func{},
		envFlagReadIdents:          map[*types.Var]map[*ast.Ident]*types.Func{},
		reflectSynthSeeds:          map[*types.Func]bool{},
	}

	unexportedMethodsByName := map[string][]*types.Func{}
	globalFuncInit := map[*types.Var]*types.Func{}
	seenNamedOrigins := map[*types.Named]bool{}
	for _, obj := range info.Defs {
		tn, ok := obj.(*types.TypeName)
		if !ok || tn == nil || tn.IsAlias() {
			continue
		}
		if named, okN := types.Unalias(tn.Type()).(*types.Named); okN && named != nil {
			orig := named.Origin()
			if !seenNamedOrigins[orig] {
				seenNamedOrigins[orig] = true
				g.declaredNamedTypes = append(g.declaredNamedTypes, orig)
			}
		}
	}

	for _, af := range pkg.Syntax {
		if af == nil {
			return nil, "nil ast.File"
		}
		for _, cg := range af.Comments {
			for _, c := range cg.List {
				if hasHarnessForbiddenDirective(c.Text) {
					return nil, "forbidden directive: " + c.Text
				}
			}
		}
		for _, imp := range af.Imports {
			if imp == nil || imp.Path == nil {
				return nil, "nil import spec"
			}
			impPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil || !IsAllowedHarnessStdImport(impPath) {
				return nil, "disallowed syntax import: " + imp.Path.Value
			}
			if imp.Name != nil && imp.Name.Name == "." {
				return nil, "dot import: " + impPath
			}
		}
		for _, decl := range af.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body == nil || d.Name == nil {
					return nil, "bodyless func decl"
				}
				if d.Recv == nil && d.Name.Name == "init" {
					continue
				}
				fn, ok := info.Defs[d.Name].(*types.Func)
				if !ok || fn == nil {
					if d.Recv == nil {
						return nil, "unresolved func decl: " + d.Name.Name
					}
					continue
				}
				orig := fn.Origin()
				g.allDecls[orig] = d
				if d.Recv == nil {
					g.declFuncs[orig] = d
				} else if !orig.Exported() {
					unexportedMethodsByName[orig.Name()] = append(unexportedMethodsByName[orig.Name()], orig)
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					continue
				}
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || (len(vs.Values) > 0 && len(vs.Values) != len(vs.Names)) {
						return nil, "invalid var spec"
					}
					for i, nameIdent := range vs.Names {
						if nameIdent == nil || nameIdent.Name == "_" {
							return nil, "blank var decl"
						}
						v, ok := info.Defs[nameIdent].(*types.Var)
						if !ok || v == nil || v.Exported() {
							return nil, "exported or unresolved var: " + nameIdent.Name
						}
						var initVal ast.Expr
						if i < len(vs.Values) {
							initVal = vs.Values[i]
							if id, isID := syntaxutil.UnwrapCallee(initVal).(*ast.Ident); isID {
								if initFn, isFn := info.Uses[id].(*types.Func); isFn && initFn != nil && initFn.Pkg() == pkgTypes {
									globalFuncInit[v] = initFn.Origin()
								}
							}
						}
						entry := harnessVarEntry{v: v, spec: vs, val: initVal}
						g.pkgVars = append(g.pkgVars, entry)
						g.pkgVarSet[v] = entry
					}
				}
			}
		}
	}

	calledFromInit := map[*types.Func]bool{}
	calledFromOther := map[*types.Func]bool{}
	declCallersOf := map[*types.Func]map[*types.Func]bool{}

	addStrictEdge := func(target *types.Func, ownerOrig *types.Func, inInitRoot bool) {
		if target == nil || g.allDecls[target] == nil {
			return
		}
		if inInitRoot {
			g.initReached[target] = true
		}
		if ownerOrig == nil {
			return
		}
		if g.strictCallersOf[target] == nil {
			g.strictCallersOf[target] = map[*types.Func]bool{}
		}
		g.strictCallersOf[target][ownerOrig] = true
	}
	addDirectFlagEdge := func(target *types.Func, ownerOrig *types.Func, inInitRoot bool) {
		addStrictEdge(target, ownerOrig, inInitRoot)
		if target == nil || ownerOrig == nil || g.allDecls[target] == nil {
			return
		}
		if g.flagDirectCallersOf[target] == nil {
			g.flagDirectCallersOf[target] = map[*types.Func]bool{}
		}
		g.flagDirectCallersOf[target][ownerOrig] = true
	}
	addCallFlagEdge := func(target *types.Func, call *ast.CallExpr, ownerOrig *types.Func, inInitRoot bool) {
		addStrictEdge(target, ownerOrig, inInitRoot)
		if target == nil || call == nil || ownerOrig == nil || g.allDecls[target] == nil {
			return
		}
		if g.flagCallEdges[target] == nil {
			g.flagCallEdges[target] = map[*ast.CallExpr]*types.Func{}
		}
		g.flagCallEdges[target][call] = ownerOrig
	}

	walkDecl := func(root ast.Node, inInitRoot bool, declCallerFn *types.Func, ownerOrig *types.Func) {
		callFunNodes := map[ast.Expr]bool{}
		ast.Inspect(root, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				callFunNodes[syntaxutil.UnwrapCallee(call.Fun)] = true
			}
			return true
		})

		var walk func(n ast.Node, inFuncLit bool, inOnceDo bool)
		walk = func(n ast.Node, inFuncLit bool, inOnceDo bool) {
			if n == nil {
				return
			}
			switch x := n.(type) {
			case *ast.FuncLit:
				if x.Type != nil {
					walk(x.Type, true, false)
				}
				if x.Body != nil {
					walk(x.Body, true, inOnceDo)
				}
				return
			case *ast.GoStmt:
				walk(x.Call, true, false)
				return
			case *ast.AssignStmt:
				isDef := x.Tok == token.DEFINE
				for _, lhs := range x.Lhs {
					g.noteMutationLHS(lhs, isDef, inOnceDo, x.Tok == token.ASSIGN)
				}
			case *ast.IncDecStmt:
				g.noteMutationLHS(x.X, false, false, false)
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					if x.Key != nil {
						g.noteMutationLHS(x.Key, false, false, false)
					}
					if x.Value != nil {
						g.noteMutationLHS(x.Value, false, false, false)
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					g.noteMutationLHS(x.X, false, false, false)
				}
			case *ast.SelectorExpr:
				if sel := info.Selections[x]; sel != nil {
					if fn, ok := sel.Obj().(*types.Func); ok && fn != nil {
						if fn.Pkg() == pkgTypes {
							if !callFunNodes[x] {
								addDirectFlagEdge(fn.Origin(), ownerOrig, inInitRoot)
								if !fn.Exported() {
									for _, cm := range unexportedMethodsByName[fn.Name()] {
										addDirectFlagEdge(cm, ownerOrig, inInitRoot)
									}
								}
							}
						} else {
							g.noteExternalFuncObj(fn, ownerOrig, inInitRoot)
						}
					}
				}
			case *ast.CallExpr:
				g.noteMutatingBuiltin(x)
				baseFun := syntaxutil.UnwrapCallee(x.Fun)
				if bf, ok := baseFun.(*ast.Ident); ok {
					if fn, isFn := info.Uses[bf].(*types.Func); isFn && fn != nil && g.declFuncs[fn.Origin()] != nil {
						orig := fn.Origin()
						g.callSitesByFunc[orig] = append(g.callSitesByFunc[orig], x)
						if inInitRoot && !inFuncLit {
							calledFromInit[orig] = true
						} else if declCallerFn != nil && !inFuncLit {
							if declCallersOf[orig] == nil {
								declCallersOf[orig] = map[*types.Func]bool{}
							}
							declCallersOf[orig][declCallerFn] = true
						} else {
							calledFromOther[orig] = true
						}
					}
				}
				callee := resolveHarnessFuncExpr(info, x.Fun)
				if callee != nil {
					if callee.Pkg() == pkgTypes {
						addCallFlagEdge(callee.Origin(), x, ownerOrig, inInitRoot)
						if !callee.Exported() && callee.Signature().Recv() != nil {
							for _, cm := range unexportedMethodsByName[callee.Name()] {
								addCallFlagEdge(cm, x, ownerOrig, inInitRoot)
							}
						}
					} else {
						g.noteExternalFuncObj(callee, ownerOrig, inInitRoot)
					}
					if callee.Name() == "Do" && len(x.Args) == 1 {
						if rPkg, rName := recvNamedTypeName(callee.Signature()); rPkg == "sync" && rName == "Once" {
							walk(x.Fun, inFuncLit, inOnceDo)
							walk(x.Args[0], inFuncLit, true)
							return
						}
					}
				}
			case *ast.Ident:
				if obj := info.Uses[x]; obj != nil {
					switch o := obj.(type) {
					case *types.Func:
						if o.Pkg() == pkgTypes {
							if !callFunNodes[x] {
								addDirectFlagEdge(o.Origin(), ownerOrig, inInitRoot)
							}
						} else {
							g.noteExternalFuncObj(o, ownerOrig, inInitRoot)
						}
					case *types.Var:
						if targetFn := globalFuncInit[o]; targetFn != nil {
							if !callFunNodes[x] {
								addDirectFlagEdge(targetFn, ownerOrig, inInitRoot)
							} else {
								addStrictEdge(targetFn, ownerOrig, inInitRoot)
							}
						}
						if _, isPkgVar := g.pkgVarSet[o]; isPkgVar && !inInitRoot && ownerOrig != nil {
							if g.envFlagReadIdents[o] == nil {
								g.envFlagReadIdents[o] = map[*ast.Ident]*types.Func{}
							}
							g.envFlagReadIdents[o][x] = ownerOrig
						}
					default:
						if obj.Pkg() != nil && obj.Pkg().Path() == "hash/maphash" {
							g.maphashOps.record(ownerOrig, inInitRoot)
						}
					}
				}
			}
			ast.Inspect(n, func(child ast.Node) bool {
				if child == nil || child == n {
					return true
				}
				walk(child, inFuncLit, inOnceDo)
				return false
			})
		}
		walk(root, false, false)
	}

	for _, af := range pkg.Syntax {
		for _, decl := range af.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.Name == "init" {
					walkDecl(d.Body, true, nil, nil)
				} else if fn, ok := info.Defs[d.Name].(*types.Func); ok && fn != nil {
					orig := fn.Origin()
					var declCaller *types.Func
					if d.Recv == nil && !orig.Exported() {
						declCaller = orig
					}
					walkDecl(d.Body, false, declCaller, orig)
				} else {
					walkDecl(d.Body, false, nil, nil)
				}
			case *ast.GenDecl:
				walkDecl(d, true, nil, nil)
			}
		}
	}

	for fn := range g.declFuncs {
		if !fn.Exported() && !g.isFuncValueTaken(fn) && !calledFromOther[fn] && (calledFromInit[fn] || len(declCallersOf[fn]) > 0) {
			g.initOnly[fn] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for fn := range g.initOnly {
			hasInitCaller := calledFromInit[fn]
			for caller := range declCallersOf[fn] {
				if !g.initOnly[caller] {
					delete(g.initOnly, fn)
					changed = true
					hasInitCaller = false
					break
				}
				hasInitCaller = true
			}
			if g.initOnly[fn] && !hasInitCaller {
				delete(g.initOnly, fn)
				changed = true
			}
		}
	}

	for changed := true; changed; {
		changed = false
		for callee, callers := range g.strictCallersOf {
			if g.initReached[callee] {
				continue
			}
			for caller := range callers {
				if g.initReached[caller] {
					g.initReached[callee] = true
					changed = true
					break
				}
			}
		}
	}

	for fn := range g.initReached {
		if g.maphashOps.funcs[fn] {
			g.maphashOps.inInitOrGlobal = true
		}
		if g.driverOnlyOps.funcs[fn] {
			g.driverOnlyOps.inInitOrGlobal = true
		}
		if g.testingCfgOps.funcs[fn] {
			g.testingCfgOps.inInitOrGlobal = true
		}
	}

	discoverReflectSynthFuncs(g)
	return g, ""
}

func (g *harnessGraph) noteExternalFuncObj(fn *types.Func, ownerOrig *types.Func, inInit bool) {
	if fn == nil || fn.Pkg() == nil {
		return
	}
	impPath, name := fn.Pkg().Path(), fn.Name()
	hasRecv := fn.Signature() != nil && fn.Signature().Recv() != nil
	switch impPath {
	case "hash/maphash":
		g.maphashOps.record(ownerOrig, inInit)
	case "time":
		if !hasRecv && (name == "Now" || name == "Since" || name == "Until") {
			g.driverOnlyOps.record(ownerOrig, inInit)
		}
	case "os":
		if !hasRecv {
			switch name {
			case "Getpid", "Open", "Create", "CreateTemp", "MkdirAll", "Remove", "Rename":
				g.driverOnlyOps.record(ownerOrig, inInit)
			}
		}
	case "path/filepath":
		if !hasRecv && name == "Glob" {
			g.driverOnlyOps.record(ownerOrig, inInit)
		}
	case "html/template":
		if hasRecv && name == "Execute" {
			g.driverOnlyOps.record(ownerOrig, inInit)
		}
	case "testing":
		if !hasRecv && (name == "Short" || name == "Verbose") {
			g.testingCfgOps.record(ownerOrig, inInit)
		}
	case "reflect":
		if (!hasRecv && (name == "New" || name == "Zero" || name == "MakeSlice" || name == "MakeMap" || name == "MakeMapWithSize")) ||
			(hasRecv && strings.HasPrefix(name, "Set")) {
			if ownerOrig != nil {
				g.reflectSynthSeeds[ownerOrig] = true
			}
		}
	}
}

// verifyHarnessAmbientConfinement proves upward intra-package caller and
// closure confinement across all four classes of ambient harness operations.
func verifyHarnessAmbientConfinement(g *harnessGraph, envFlagVars map[*types.Var]bool) (bool, string) {
	sc := g.screen

	checkStrict := func(label string, ops ambientOpSet, allowed func(*types.Func) bool) (bool, string) {
		if ops.inInitOrGlobal {
			return false, label + " in init or global initializer"
		}
		if len(ops.funcs) == 0 {
			return true, ""
		}
		visited := map[*types.Func]bool{}
		var queue []*types.Func
		for fn := range ops.funcs {
			visited[fn] = true
			queue = append(queue, fn)
		}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if cur == nil {
				return false, label + " nil caller"
			}
			if cur.Exported() {
				if !allowed(cur) {
					return false, label + " reaches disallowed exported symbol " + cur.Name()
				}
			} else if g.isFuncValueTaken(cur) {
				return false, label + " value-taken helper " + cur.Name()
			}
			for caller := range g.strictCallersOf[cur] {
				if !visited[caller] {
					visited[caller] = true
					queue = append(queue, caller)
				}
			}
		}
		return true, ""
	}

	if ok, reason := checkStrict("hash/maphash", g.maphashOps, func(fn *types.Func) bool {
		return sc.driverFuncs[fn] || sc.wrapperFuncs[fn] || sc.seededMethods[fn]
	}); !ok {
		return false, reason
	}
	if ok, reason := checkStrict("clock/fs/template", g.driverOnlyOps, func(fn *types.Func) bool {
		return sc.driverFuncs[fn] || sc.wrapperFuncs[fn]
	}); !ok {
		return false, reason
	}
	if ok, reason := checkStrict("testing config", g.testingCfgOps, func(fn *types.Func) bool {
		return sc.driverFuncs[fn] || sc.wrapperFuncs[fn] || sc.sealedHandleCallables[fn]
	}); !ok {
		return false, reason
	}

	if len(envFlagVars) > 0 {
		pureLogReads := findPureLoggingBoolFlagReads(g, envFlagVars)
		visitedFn := map[*types.Func]bool{}
		var fnQueue []*types.Func
		enqueueFn := func(fn *types.Func) {
			if fn != nil && !g.initOnly[fn] && !visitedFn[fn] {
				visitedFn[fn] = true
				fnQueue = append(fnQueue, fn)
			}
		}
		for v := range envFlagVars {
			for id, ownerFn := range g.envFlagReadIdents[v] {
				if !pureLogReads[id] {
					enqueueFn(ownerFn)
				}
			}
		}
		for len(fnQueue) > 0 {
			cur := fnQueue[0]
			fnQueue = fnQueue[1:]
			if cur.Exported() {
				allowedSealed := sc.sealedHandleCallables[cur] && cur.Signature() != nil && cur.Signature().Results().Len() == 0
				if !sc.driverFuncs[cur] && !sc.wrapperFuncs[cur] && !allowedSealed {
					return false, "env/flag global reaches disallowed exported symbol " + cur.Name()
				}
			} else if g.isFuncValueTaken(cur) {
				return false, "env/flag global value-taken helper " + cur.Name()
			}
			for caller := range g.flagDirectCallersOf[cur] {
				enqueueFn(caller)
			}
			for callExpr, caller := range g.flagCallEdges[cur] {
				if !sc.seededBaseSeedCalls[callExpr] {
					enqueueFn(caller)
				}
			}
		}
	}

	return true, ""
}

func hasHarnessForbiddenDirective(text string) bool {
	trimmed := strings.TrimSpace(strings.TrimPrefix(text, "//"))
	trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "/*"))
	trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, "*/"))
	for _, dir := range []string{"go:linkname", "go:linknamestd", "go:wasmimport", "go:cgo_", "go:embed"} {
		if strings.HasPrefix(trimmed, dir) {
			if dir == "go:cgo_" || trimmed == dir {
				return true
			}
			if _, ok := auditset.BoundedToken(trimmed, dir, " \t"); ok {
				return true
			}
		}
	}
	return false
}
