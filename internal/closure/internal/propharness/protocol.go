package propharness

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"

	"github.com/greatliontech/gofresh/internal/dynstate"
)

var harnessPureStdImports = map[string]bool{
	"bufio":           true,
	"bytes":           true,
	"cmp":             true,
	"context":         true,
	"encoding/base64": true,
	"encoding/binary": true,
	"errors":          true,
	"fmt":             true,
	"image":           true,
	"image/color":     true,
	"image/png":       true,
	"io":              true,
	"maps":            true,
	"math":            true,
	"math/bits":       true,
	"regexp":          true,
	"regexp/syntax":   true,
	"slices":          true,
	"sort":            true,
	"strconv":         true,
	"strings":         true,
	"sync":            true,
	"sync/atomic":     true,
	"unicode":         true,
	"unicode/utf8":    true,
}

var harnessProtocolStdImports = map[string]bool{
	"flag":             true,
	"hash/maphash":     true,
	"html/template":    true,
	"log":              true,
	"os":               true,
	"path/filepath":    true,
	"reflect":          true,
	"runtime":          true,
	"testing":          true,
	"testing/synctest": true,
	"time":             true,
}

var (
	harnessFlagFuncs = map[string]bool{
		"IntVar": true, "Int64Var": true, "UintVar": true, "Uint64Var": true,
		"StringVar": true, "BoolVar": true, "Float64Var": true, "DurationVar": true,
	}
	harnessTemplateTypes   = map[string]bool{"Template": true, "CSS": true}
	harnessTemplateFuncs   = map[string]bool{"New": true, "Must": true}
	harnessTemplateMethods = map[string]bool{"Parse": true, "Execute": true}
	harnessOSFuncs         = map[string]bool{
		"LookupEnv": true, "Getenv": true,
		"Open": true, "Create": true, "CreateTemp": true, "MkdirAll": true,
		"Rename": true, "Remove": true, "Getpid": true, "IsNotExist": true,
	}
	harnessOSTypes = map[string]bool{
		"File": true, "FileMode": true, "FileInfo": true, "PathError": true,
	}
	harnessOSMethods = map[string]bool{
		"Read": true, "Write": true, "WriteString": true,
		"Close": true, "Name": true, "Sync": true, "Stat": true,
	}
	harnessFilepathFuncs = map[string]bool{
		"Join": true, "Dir": true, "Base": true, "Clean": true,
		"Ext": true, "Split": true, "ToSlash": true, "FromSlash": true, "Glob": true,
	}
	harnessMaphashTypes   = map[string]bool{"Hash": true, "Seed": true}
	harnessMaphashFuncs   = map[string]bool{"MakeSeed": true, "Bytes": true, "String": true}
	harnessMaphashMethods = map[string]bool{
		"Write": true, "WriteByte": true, "WriteString": true,
		"Sum64": true, "Reset": true, "SetSeed": true, "Seed": true,
		"BlockSize": true, "Size": true, "Sum": true,
	}
	harnessTimeTypes = map[string]bool{"Time": true, "Duration": true, "Location": true}
	harnessTimeFuncs = map[string]bool{
		"ParseDuration": true, "Now": true, "Since": true, "Until": true,
		"Date": true, "Unix": true, "UnixMilli": true, "UnixMicro": true, "UnixNano": true,
	}
	harnessTimeMethods = map[string]bool{
		"Add": true, "Sub": true, "Before": true, "After": true, "Equal": true, "Compare": true,
		"IsZero": true, "Format": true, "String": true,
		"Nanoseconds": true, "Microseconds": true, "Milliseconds": true,
		"Seconds": true, "Minutes": true, "Hours": true, "Truncate": true, "Round": true,
		"UTC": true, "Unix": true, "UnixNano": true,
	}
	harnessRuntimeTypes   = map[string]bool{"Frame": true, "Frames": true}
	harnessRuntimeConsts  = map[string]bool{"GOOS": true, "GOARCH": true, "Compiler": true}
	harnessRuntimeFuncs   = map[string]bool{"Callers": true, "CallersFrames": true, "Goexit": true}
	harnessRuntimeMethods = map[string]bool{"Next": true}
	harnessLogTypes       = map[string]bool{"Logger": true}
	harnessLogFuncs       = map[string]bool{"New": true}
	harnessLogMethods     = map[string]bool{
		"Printf": true, "Print": true, "Println": true,
		"Writer": true, "Output": true, "Prefix": true, "Flags": true,
	}
	harnessTestingTypes   = map[string]bool{"T": true, "B": true, "F": true, "TB": true}
	harnessTestingFuncs   = map[string]bool{"Short": true, "Verbose": true}
	harnessTestingMethods = map[string]bool{
		"Helper": true, "Name": true, "Deadline": true,
		"Log": true, "Logf": true, "Error": true, "Errorf": true,
		"Fatal": true, "Fatalf": true, "Skip": true, "Skipf": true, "SkipNow": true, "Skipped": true,
		"Fail": true, "FailNow": true, "Failed": true,
		"Cleanup": true, "Context": true, "Output": true, "Run": true,
	}
	harnessSynctestFuncs = map[string]bool{"Test": true, "Wait": true}
	harnessReflectTypes  = map[string]bool{
		"Type": true, "Value": true, "Kind": true, "StructField": true, "StructTag": true, "Method": true,
	}
	harnessReflectKinds = map[string]bool{
		"Invalid": true, "Bool": true,
		"Int": true, "Int8": true, "Int16": true, "Int32": true, "Int64": true,
		"Uint": true, "Uint8": true, "Uint16": true, "Uint32": true, "Uint64": true, "Uintptr": true,
		"Float32": true, "Float64": true, "Complex64": true, "Complex128": true,
		"Array": true, "Map": true, "Pointer": true, "Ptr": true,
		"Slice": true, "String": true, "Struct": true,
	}
	harnessReflectFuncs = map[string]bool{
		"DeepEqual": true, "TypeOf": true, "ValueOf": true, "Zero": true,
		"New": true, "Indirect": true, "MakeSlice": true, "Append": true, "MakeMapWithSize": true,
	}
	harnessReflectTypeMethods = map[string]bool{
		"Kind": true, "Elem": true, "Key": true, "Len": true,
		"NumField": true, "Field": true, "NumMethod": true, "Method": true,
		"Name": true, "PkgPath": true, "String": true, "Size": true,
		"Comparable": true, "AssignableTo": true, "ConvertibleTo": true, "Implements": true, "Bits": true,
	}
	harnessReflectValueMethods = map[string]bool{
		"Type": true, "Kind": true, "Elem": true, "Field": true, "Index": true, "MapIndex": true,
		"Len": true, "Cap": true, "IsNil": true, "IsValid": true, "IsZero": true,
		"CanSet": true, "CanInterface": true, "Interface": true, "Convert": true,
		"Set": true, "SetMapIndex": true, "Method": true,
		"Bool": true, "Int": true, "Uint": true, "Float": true, "String": true, "Bytes": true,
	}
	harnessReflectTagMethods   = map[string]bool{"Get": true, "Lookup": true}
	harnessReflectFieldMethods = map[string]bool{"IsExported": true}
	harnessReflectKindMethods  = map[string]bool{"String": true}
)

func checkHarnessPureStdObjectUse(impPath string, obj types.Object) bool {
	// Disallow mutable package-level globals in stdlib packages (e.g. io.EOF
	// and io.Discard are immutable sentinels, whereas custom global registries are not).
	if v, ok := obj.(*types.Var); ok && !v.IsField() {
		switch impPath {
		case "io":
			return v.Name() == "Discard" || v.Name() == "EOF" || v.Name() == "ErrUnexpectedEOF"
		case "encoding/binary":
			return v.Name() == "LittleEndian" || v.Name() == "BigEndian" || v.Name() == "NativeEndian"
		case "encoding/base64":
			return v.Name() == "StdEncoding" || v.Name() == "RawStdEncoding" || v.Name() == "URLEncoding" || v.Name() == "RawURLEncoding"
		case "unicode":
			return true
		case "image/color":
			return v.Name() == "Black" || v.Name() == "White" || v.Name() == "Transparent" || v.Name() == "Opaque"
		default:
			return false
		}
	}
	return true
}

func checkHarnessProtocolObjectAllowed(impPath string, obj types.Object) bool {
	if v, ok := obj.(*types.Var); ok && v.IsField() {
		return true
	}
	switch impPath {
	case "flag":
		fn, ok := obj.(*types.Func)
		return ok && fn.Signature().Recv() == nil && harnessFlagFuncs[fn.Name()]
	case "html/template":
		switch o := obj.(type) {
		case *types.TypeName:
			return harnessTemplateTypes[o.Name()]
		case *types.Func:
			sig := o.Signature()
			if sig.Recv() == nil {
				return harnessTemplateFuncs[o.Name()]
			}
			_, typeName := recvNamedTypeName(sig)
			return typeName == "Template" && harnessTemplateMethods[o.Name()]
		}
		return false
	case "os":
		switch o := obj.(type) {
		case *types.TypeName:
			return harnessOSTypes[o.Name()]
		case *types.Const:
			return true
		case *types.Var:
			return o.Name() == "Stdout"
		case *types.Func:
			if o.Signature().Recv() == nil {
				return harnessOSFuncs[o.Name()]
			}
			return harnessOSMethods[o.Name()]
		}
		return false
	case "path/filepath":
		switch o := obj.(type) {
		case *types.Const:
			return o.Name() == "Separator" || o.Name() == "ListSeparator"
		case *types.Func:
			return o.Signature().Recv() == nil && harnessFilepathFuncs[o.Name()]
		}
		return false
	case "hash/maphash":
		switch o := obj.(type) {
		case *types.TypeName:
			return harnessMaphashTypes[o.Name()]
		case *types.Func:
			if o.Signature().Recv() == nil {
				return harnessMaphashFuncs[o.Name()]
			}
			return harnessMaphashMethods[o.Name()]
		}
		return false
	case "time":
		switch o := obj.(type) {
		case *types.TypeName:
			return harnessTimeTypes[o.Name()]
		case *types.Const:
			return true
		case *types.Func:
			if o.Signature().Recv() == nil {
				return harnessTimeFuncs[o.Name()]
			}
			return harnessTimeMethods[o.Name()]
		}
		return false
	case "runtime":
		switch o := obj.(type) {
		case *types.TypeName:
			return harnessRuntimeTypes[o.Name()]
		case *types.Const:
			return harnessRuntimeConsts[o.Name()]
		case *types.Func:
			if o.Signature().Recv() == nil {
				return harnessRuntimeFuncs[o.Name()]
			}
			return harnessRuntimeMethods[o.Name()]
		}
		return false
	case "log":
		switch o := obj.(type) {
		case *types.TypeName:
			return harnessLogTypes[o.Name()]
		case *types.Const:
			return true
		case *types.Func:
			if o.Signature().Recv() == nil {
				return harnessLogFuncs[o.Name()]
			}
			return harnessLogMethods[o.Name()]
		}
		return false
	case "testing":
		switch o := obj.(type) {
		case *types.TypeName:
			return harnessTestingTypes[o.Name()]
		case *types.Func:
			if o.Signature().Recv() == nil {
				return harnessTestingFuncs[o.Name()]
			}
			return harnessTestingMethods[o.Name()]
		}
		return false
	case "testing/synctest":
		fn, ok := obj.(*types.Func)
		return ok && fn.Signature().Recv() == nil && harnessSynctestFuncs[fn.Name()]
	case "reflect":
		switch o := obj.(type) {
		case *types.TypeName:
			return harnessReflectTypes[o.Name()]
		case *types.Const:
			named, ok := types.Unalias(o.Type()).(*types.Named)
			return ok && named.Obj() != nil && named.Obj().Name() == "Kind" && harnessReflectKinds[o.Name()]
		case *types.Func:
			sig := o.Signature()
			if sig.Recv() == nil {
				return harnessReflectFuncs[o.Name()]
			}
			_, typeName := recvNamedTypeName(sig)
			switch typeName {
			case "Type":
				return harnessReflectTypeMethods[o.Name()]
			case "Value":
				return harnessReflectValueMethods[o.Name()]
			case "StructTag":
				return harnessReflectTagMethods[o.Name()]
			case "StructField", "Method":
				return harnessReflectFieldMethods[o.Name()]
			case "Kind":
				return harnessReflectKindMethods[o.Name()]
			case "":
				if o.Pkg() != nil && o.Pkg().Scope() != nil {
					if typeObj := o.Pkg().Scope().Lookup("Type"); typeObj != nil {
						if mObj, _, _ := types.LookupFieldOrMethod(typeObj.Type(), false, o.Pkg(), o.Name()); mObj == o {
							return harnessReflectTypeMethods[o.Name()]
						}
					}
				}
			}
		}
		return false
	}
	return false
}

func verifyHarnessProtocolCallContexts(
	audited bool,
	idx *harnessPkgIndex,
	categoryA map[*types.Var]bool,
) (bool, string) {
	pkg := idx.pkg
	info := idx.info
	pkgTypes := idx.pkgTypes
	declFuncs := idx.declFuncs
	initOnly := idx.initOnly
	callSites := idx.callSitesByFunc

	failfileVars, failfileParams, failfileResults := computeHarnessFailfileProvenance(idx, categoryA)

	var validRapidEnvStringParam func(fn *types.Func, pIdx int, seen map[harnessParamKey]bool) bool
	validRapidEnvStringParam = func(fn *types.Func, pIdx int, seen map[harnessParamKey]bool) bool {
		if fn == nil || !initOnly[fn] || fn.Signature().Variadic() {
			return false
		}
		params := fn.Signature().Params()
		if pIdx < 0 || pIdx >= params.Len() {
			return false
		}
		key := harnessParamKey{fn: fn, idx: pIdx}
		if seen[key] {
			return true
		}
		seen[key] = true
		sites := callSites[fn]
		if len(sites) == 0 {
			return false
		}
		for _, site := range sites {
			if site.Ellipsis.IsValid() || pIdx >= len(site.Args) {
				return false
			}
			arg := site.Args[pIdx]
			if constStringPrefix(info, arg, "RAPID_") {
				continue
			}
			argIdent, ok := ast.Unparen(arg).(*ast.Ident)
			if !ok {
				return false
			}
			paramObj, ok := info.Uses[argIdent].(*types.Var)
			if !ok || paramObj == nil {
				return false
			}
			callerFn, callerIdx := idx.findFuncParamIndex(paramObj)
			if callerFn == nil || !validRapidEnvStringParam(callerFn, callerIdx, seen) {
				return false
			}
		}
		return true
	}

	var validInitLookupParam func(fn *types.Func, pIdx int, seen map[harnessParamKey]bool) bool
	validInitLookupParam = func(fn *types.Func, pIdx int, seen map[harnessParamKey]bool) bool {
		if fn == nil || !initOnly[fn] || fn.Signature().Variadic() {
			return false
		}
		params := fn.Signature().Params()
		if pIdx < 0 || pIdx >= params.Len() {
			return false
		}
		key := harnessParamKey{fn: fn, idx: pIdx}
		if seen[key] {
			return true
		}
		seen[key] = true
		paramVar := params.At(pIdx)
		fd := declFuncs[fn]
		if fd == nil || fd.Body == nil {
			return false
		}
		allowedIdents := map[*ast.Ident]bool{}
		okBody := true
		var inspectBody func(n ast.Node, inLit bool)
		inspectBody = func(n ast.Node, inLit bool) {
			if !okBody || n == nil {
				return
			}
			switch x := n.(type) {
			case *ast.FuncLit:
				inspectBody(x.Type, true)
				inspectBody(x.Body, true)
				return
			case *ast.GoStmt:
				inspectBody(x.Call, true)
				return
			case *ast.CallExpr:
				if funId, ok := peelHarnessCallee(x.Fun).(*ast.Ident); ok && info.Uses[funId] == paramVar {
					if inLit || x.Ellipsis.IsValid() || len(x.Args) != 1 {
						okBody = false
						return
					}
					allowedIdents[funId] = true
					keyArg := x.Args[0]
					if !constStringPrefix(info, keyArg, "RAPID_") {
						argId, ok := ast.Unparen(keyArg).(*ast.Ident)
						if !ok {
							okBody = false
							return
						}
						pObj, ok := info.Uses[argId].(*types.Var)
						if !ok || pObj == nil {
							okBody = false
							return
						}
						ownerFn, ownerIdx := idx.findFuncParamIndex(pObj)
						if ownerFn != fn || !validRapidEnvStringParam(fn, ownerIdx, map[harnessParamKey]bool{}) {
							okBody = false
							return
						}
					}
				} else {
					callee := resolveHarnessFuncExpr(info, x.Fun)
					for argIdx, arg := range x.Args {
						if argId, ok := ast.Unparen(arg).(*ast.Ident); ok && info.Uses[argId] == paramVar {
							if inLit || x.Ellipsis.IsValid() || callee == nil || declFuncs[callee] == nil || !validInitLookupParam(callee, argIdx, seen) {
								okBody = false
								return
							}
							allowedIdents[argId] = true
						}
					}
				}
			case *ast.Ident:
				if info.Uses[x] == paramVar && !allowedIdents[x] {
					okBody = false
					return
				}
			}
			ast.Inspect(n, func(child ast.Node) bool {
				if !okBody || child == nil {
					return false
				}
				if child == n {
					return true
				}
				inspectBody(child, inLit)
				return false
			})
		}
		inspectBody(fd.Body, false)
		return okBody
	}

	sawTBLogf := false
	okAll := true
	failReason := ""
	fail := func(msg string) {
		if okAll {
			okAll = false
			failReason = msg
		}
	}

	checkTree := func(root ast.Node, inInitRoot bool, enclosingFD *ast.FuncDecl, enclosingFn *types.Func) {
		approvedIdents := map[*ast.Ident]bool{}
		var tempFileVars map[*types.Var]bool
		if enclosingFD != nil && enclosingFD.Body != nil {
			tempFileVars = collectHarnessTempFileVars(idx, enclosingFD.Body, categoryA, failfileVars, failfileParams, failfileResults)
		}
		isFailfile := func(e ast.Expr) bool {
			return isHarnessFailfileExpr(info, e, declFuncs, categoryA, failfileVars, failfileParams, failfileResults)
		}

		var walk func(n ast.Node, inInitExec bool, inLit bool, inFlagBoolGuard bool)
		walk = func(n ast.Node, inInitExec bool, inLit bool, inFlagBoolGuard bool) {
			if !okAll || n == nil {
				return
			}
			switch x := n.(type) {
			case *ast.FuncLit:
				walk(x.Type, false, true, false)
				walk(x.Body, false, true, false)
				return
			case *ast.GoStmt:
				if inInitRoot || inLit || enclosingFD == nil || enclosingFD.Body == nil ||
					!verifyJoinedSynctestGoStmt(info, pkgTypes, enclosingFD.Body, x) {
					fail("unjoined go stmt")
					return
				}
				walk(x.Call, false, true, false)
				return
			case *ast.IfStmt:
				if x.Init != nil {
					walk(x.Init, inInitExec, inLit, inFlagBoolGuard)
				}
				walk(x.Cond, inInitExec, inLit, inFlagBoolGuard)
				condGuard := inFlagBoolGuard || (!inLit && isCategoryABoolFieldExpr(info, x.Cond, categoryA))
				walk(x.Body, inInitExec, inLit, condGuard)
				if x.Else != nil {
					walk(x.Else, inInitExec, inLit, inFlagBoolGuard)
				}
				return
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if rootImportedVar(info, lhs, pkgTypes) != nil {
						fail("assign imported var")
						return
					}
				}
			case *ast.IncDecStmt:
				if rootImportedVar(info, x.X, pkgTypes) != nil {
					fail("incdec imported var")
					return
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					if (x.Key != nil && rootImportedVar(info, x.Key, pkgTypes) != nil) ||
						(x.Value != nil && rootImportedVar(info, x.Value, pkgTypes) != nil) {
						fail("range assign imported var")
						return
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND && rootImportedVar(info, x.X, pkgTypes) != nil {
					fail("addr imported var")
					return
				}
			case *ast.CallExpr:
				if arg0, ok := mutatingBuiltinFirstArg(info, x); ok {
					if rootImportedVar(info, arg0, pkgTypes) != nil {
						fail("builtin mutate imported var")
						return
					}
				}
				callee := resolveHarnessFuncExpr(info, x.Fun)
				if callee != nil {
					if callee.Name() == "Logf" && callee.Signature().Recv() != nil {
						sawTBLogf = true
					}
					if callee.Pkg() != nil && callee.Pkg() != pkgTypes {
						impPath := callee.Pkg().Path()
						switch {
						case impPath == "flag":
							if !inInitExec || x.Ellipsis.IsValid() || len(x.Args) != 4 {
								fail("flag call outside init or bad arity: " + callee.Name())
								return
							}
							if !isAddrOfCarrierFreeFlagField(audited, info, x.Args[0], idx.pkgVarSet) || !constStringPrefix(info, x.Args[1], "rapid.") {
								fail("flag call bad target or prefix: " + callee.Name())
								return
							}
							markCalleeIdentApproved(x.Fun, approvedIdents)
						case impPath == "os" && (callee.Name() == "LookupEnv" || callee.Name() == "Getenv"):
							if !inInitExec || x.Ellipsis.IsValid() || len(x.Args) != 1 || !constStringPrefix(info, x.Args[0], "RAPID_") {
								fail("os env call bad context: " + callee.Name())
								return
							}
							markCalleeIdentApproved(x.Fun, approvedIdents)
						case impPath == "os" && callee.Signature().Recv() == nil:
							if !verifyHarnessOSFuncCall(info, enclosingFD, enclosingFn, inInitRoot, inLit, inFlagBoolGuard, callee.Name(), x, isFailfile, tempFileVars) {
								fail("os func call failed: os." + callee.Name())
								return
							}
							markCalleeIdentApproved(x.Fun, approvedIdents)
						case impPath == "path/filepath" && callee.Name() == "Glob":
							if inInitRoot || enclosingFn == nil || enclosingFn.Exported() || x.Ellipsis.IsValid() || len(x.Args) != 1 || !isFailfile(x.Args[0]) {
								fail("filepath.Glob failed")
								return
							}
							markCalleeIdentApproved(x.Fun, approvedIdents)
						case impPath == "log" && callee.Name() == "New":
							if !x.Ellipsis.IsValid() && len(x.Args) == 3 {
								if stdoutIdent := osStdoutIdent(info, x.Args[0]); stdoutIdent != nil {
									approvedIdents[stdoutIdent] = true
								}
							}
							markCalleeIdentApproved(x.Fun, approvedIdents)
						case impPath == "html/template":
							if !verifyHarnessTemplateCall(audited, info, pkgTypes, callee, x) {
								fail("html/template call failed: " + callee.Name())
								return
							}
							markCalleeIdentApproved(x.Fun, approvedIdents)
						case harnessProtocolStdImports[impPath]:
							markCalleeIdentApproved(x.Fun, approvedIdents)
						}
					} else if declFuncs[callee] != nil && initOnly[callee] && inInitExec && !x.Ellipsis.IsValid() {
						for argIdx, arg := range x.Args {
							if envIdent := osEnvLookupIdent(info, arg); envIdent != nil {
								if !validInitLookupParam(callee, argIdx, map[harnessParamKey]bool{}) {
									fail("invalid init lookup param: " + callee.Name())
									return
								}
								approvedIdents[envIdent] = true
							}
						}
					}
				}
			case *ast.Ident:
				if !approvedIdents[x] {
					if obj := info.Uses[x]; obj != nil && obj.Pkg() != nil {
						switch obj.Pkg().Path() {
						case "flag":
							if _, isFn := obj.(*types.Func); isFn {
								fail("unapproved flag ref: " + obj.Name())
								return
							}
						case "html/template":
							if _, isFn := obj.(*types.Func); isFn {
								fail("unapproved html/template ref: " + obj.Name())
								return
							}
						case "os":
							if _, isFn := obj.(*types.Func); isFn || obj.Name() == "Stdout" {
								fail("unapproved os ref: " + obj.Name())
								return
							}
						case "path/filepath":
							if fn, isFn := obj.(*types.Func); isFn && fn.Name() == "Glob" {
								fail("unapproved filepath.Glob ref")
								return
							}
						case "reflect":
							if _, isFn := obj.(*types.Func); isFn {
								fail("unapproved reflect ref: " + obj.Name())
								return
							}
						}
					}
				}
			}
			ast.Inspect(n, func(child ast.Node) bool {
				if !okAll || child == nil {
					return false
				}
				if child == n {
					return true
				}
				walk(child, inInitExec, inLit, inFlagBoolGuard)
				return false
			})
		}
		walk(root, inInitRoot, false, false)
	}

	for _, af := range pkg.Syntax {
		for _, decl := range af.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				inInit := false
				var fn *types.Func
				if d.Recv == nil && d.Name.Name == "init" {
					inInit = true
				} else if d.Recv == nil {
					fn, _ = info.Defs[d.Name].(*types.Func)
					if fn != nil && initOnly[fn] {
						inInit = true
					}
				}
				checkTree(d.Body, inInit, d, fn)
			case *ast.GenDecl:
				checkTree(d, true, nil, nil)
			}
			if !okAll {
				return false, failReason
			}
		}
	}

	if !sawTBLogf {
		return false, "missing TB.Logf"
	}
	if !verifyHarnessMaphashCallerConfinement(idx) {
		return false, "maphash caller confinement failed"
	}
	return true, ""
}

// verifyHarnessMaphashCallerConfinement verifies that every reference to "hash/maphash"
// inside pkg sits inside a non-init function/method whose transitive intra-package
// callers (attributing calls inside nested FuncLits to their enclosing FuncDecl and
// forbidding value-taken intermediate helpers) reach no exported symbol other than
// Check, MakeCheck, or (*Generator[V]).Example.
func verifyHarnessMaphashCallerConfinement(idx *harnessPkgIndex) bool {
	if idx.maphashInInitOrGlobal {
		return false
	}
	if len(idx.maphashSeeds) == 0 {
		return true
	}

	pkgTypes := idx.pkgTypes
	isAllowedExportedMaphashRoot := func(fn *types.Func) bool {
		sig := fn.Signature()
		if sig.Recv() == nil {
			return fn.Name() == "Check" || fn.Name() == "MakeCheck"
		}
		if fn.Name() != "Example" {
			return false
		}
		rt := types.Unalias(sig.Recv().Type())
		if ptr, ok := rt.(*types.Pointer); ok {
			rt = types.Unalias(ptr.Elem())
		}
		named, ok := rt.(*types.Named)
		return ok && named.Obj() != nil && named.Obj().Pkg() == pkgTypes && named.Obj().Name() == "Generator"
	}

	visited := map[*types.Func]bool{}
	var queue []*types.Func
	for fn := range idx.maphashSeeds {
		visited[fn] = true
		queue = append(queue, fn)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur == nil {
			return false
		}
		if cur.Exported() {
			if !isAllowedExportedMaphashRoot(cur) {
				return false
			}
			continue
		}
		if idx.anyValueTaken[cur] {
			return false
		}
		if cur.Signature().Recv() != nil {
			// Unexported method could satisfy an interface; disallow on maphash upward cone.
			return false
		}
		for caller := range idx.allCallersOf[cur] {
			if caller == nil {
				return false
			}
			if !visited[caller] {
				visited[caller] = true
				queue = append(queue, caller)
			}
		}
	}
	return true
}

func markCalleeIdentApproved(fun ast.Expr, approved map[*ast.Ident]bool) {
	switch x := peelHarnessCallee(fun).(type) {
	case *ast.Ident:
		approved[x] = true
	case *ast.SelectorExpr:
		if x.Sel != nil {
			approved[x.Sel] = true
		}
	}
}

func verifyJoinedSynctestGoStmt(info *types.Info, pkgTypes *types.Package, body *ast.BlockStmt, goStmt *ast.GoStmt) bool {
	if body == nil || goStmt == nil || goStmt.Call == nil || goStmt.Call.Ellipsis.IsValid() || len(goStmt.Call.Args) != 0 {
		return false
	}
	lit, ok := ast.Unparen(goStmt.Call.Fun).(*ast.FuncLit)
	if !ok || lit.Body == nil || len(lit.Body.List) == 0 {
		return false
	}

	goIdx := -1
	for i, st := range body.List {
		if st == goStmt {
			goIdx = i
			break
		}
	}
	if goIdx <= 0 || goIdx+1 >= len(body.List) {
		return false
	}

	// Locate top-level synctest.Test(parent, func(st *testing.T) { ... }) inside lit.Body.List.
	syncIdx := -1
	var synctestCallback ast.Node
	for i, st := range lit.Body.List {
		es, isES := st.(*ast.ExprStmt)
		if !isES {
			continue
		}
		call, isC := ast.Unparen(es.X).(*ast.CallExpr)
		if !isC || len(call.Args) != 2 {
			continue
		}
		if callee := resolveHarnessFuncExpr(info, call.Fun); callee != nil && callee.Pkg() != nil &&
			callee.Pkg().Path() == "testing/synctest" && callee.Name() == "Test" {
			if syncIdx != -1 {
				return false
			}
			syncIdx = i
			synctestCallback = call.Args[1]
		}
	}
	if syncIdx == -1 {
		return false
	}

	// Disallow any extra GoStmt inside lit.Body outside synctest.Test's bubble callback.
	hasExtraGo := false
	var scanOutsideBubble func(n ast.Node)
	scanOutsideBubble = func(n ast.Node) {
		if n == nil || hasExtraGo || n == synctestCallback {
			return
		}
		if _, isGo := n.(*ast.GoStmt); isGo {
			hasExtraGo = true
			return
		}
		ast.Inspect(n, func(child ast.Node) bool {
			if child == nil || hasExtraGo {
				return false
			}
			if child == n {
				return true
			}
			scanOutsideBubble(child)
			return false
		})
	}
	scanOutsideBubble(lit.Body)
	if hasExtraGo {
		return false
	}

	// Identify the single channel variable sent as the final action of lit.Body:
	// either (A) the final statement of a single top-level defer func() { ... }() at deferIdx < syncIdx
	// with zero ReturnStmt/DeferStmt before deferIdx+1 and zero ReturnStmt/BranchStmt inside the defer,
	// or (B) the final top-level statement of lit.Body.List after syncIdx with zero top-level DeferStmt
	// and zero ReturnStmt before it.
	var chVar *types.Var
	if lastSt, isSend := lit.Body.List[len(lit.Body.List)-1].(*ast.SendStmt); isSend && syncIdx < len(lit.Body.List)-1 {
		if chID, isID := ast.Unparen(lastSt.Chan).(*ast.Ident); isID {
			if v, isV := info.Uses[chID].(*types.Var); isV && v != nil && v.Parent() != pkgTypes.Scope() {
				badBefore := false
				for i := 0; i < len(lit.Body.List)-1; i++ {
					ast.Inspect(lit.Body.List[i], func(n ast.Node) bool {
						if n == synctestCallback || badBefore || n == nil {
							return false
						}
						switch n.(type) {
						case *ast.DeferStmt, *ast.ReturnStmt:
							badBefore = true
							return false
						case *ast.FuncLit:
							return false
						}
						return true
					})
				}
				if !badBefore {
					chVar = v
				}
			}
		}
	} else {
		deferIdx := -1
		var deferLit *ast.FuncLit
		for i := 0; i < syncIdx; i++ {
			ds, isDS := lit.Body.List[i].(*ast.DeferStmt)
			if !isDS {
				continue
			}
			if deferIdx != -1 || ds.Call == nil || ds.Call.Ellipsis.IsValid() || len(ds.Call.Args) != 0 {
				return false
			}
			dl, isFL := ast.Unparen(ds.Call.Fun).(*ast.FuncLit)
			if !isFL || dl.Body == nil || len(dl.Body.List) == 0 {
				return false
			}
			deferIdx = i
			deferLit = dl
		}
		if deferIdx != -1 && deferLit != nil {
			if sendSt, isSend := deferLit.Body.List[len(deferLit.Body.List)-1].(*ast.SendStmt); isSend {
				if chID, isID := ast.Unparen(sendSt.Chan).(*ast.Ident); isID {
					if v, isV := info.Uses[chID].(*types.Var); isV && v != nil && v.Parent() != pkgTypes.Scope() {
						badDefer := false
						for i := 0; i <= deferIdx; i++ {
							if i == deferIdx {
								continue
							}
							ast.Inspect(lit.Body.List[i], func(n ast.Node) bool {
								if badDefer || n == nil {
									return false
								}
								switch n.(type) {
								case *ast.ReturnStmt, *ast.DeferStmt, *ast.BranchStmt:
									badDefer = true
									return false
								case *ast.FuncLit:
									return false
								}
								return true
							})
						}
						for i := 0; i < len(deferLit.Body.List)-1; i++ {
							ast.Inspect(deferLit.Body.List[i], func(n ast.Node) bool {
								if badDefer || n == nil {
									return false
								}
								switch n.(type) {
								case *ast.ReturnStmt, *ast.BranchStmt, *ast.GoStmt:
									badDefer = true
									return false
								case *ast.FuncLit:
									return false
								}
								return true
							})
						}
						if !badDefer {
							chVar = v
						}
					}
				}
			}
		}
	}
	if chVar == nil {
		return false
	}

	// Locate top-level ch := make(chan ...) at defIdx < goIdx in body.List.
	defIdx := -1
	for i := 0; i < goIdx; i++ {
		as, isAS := body.List[i].(*ast.AssignStmt)
		if !isAS || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			continue
		}
		id, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
		if !isID || info.Defs[id] != chVar {
			continue
		}
		if !isMakeChanCall(info, as.Rhs[0]) {
			return false
		}
		defIdx = i
		break
	}
	if defIdx == -1 {
		return false
	}

	isRecvOnCh := func(e ast.Expr) bool {
		un, isUn := ast.Unparen(e).(*ast.UnaryExpr)
		if !isUn || un.Op != token.ARROW {
			return false
		}
		id, isID := ast.Unparen(un.X).(*ast.Ident)
		return isID && info.Uses[id] == chVar
	}
	isTopLevelUnconditionalRecv := func(st ast.Stmt) bool {
		switch s := st.(type) {
		case *ast.ExprStmt:
			return isRecvOnCh(s.X)
		case *ast.AssignStmt:
			return len(s.Rhs) == 1 && (len(s.Lhs) == 1 || len(s.Lhs) == 2) && isRecvOnCh(s.Rhs[0])
		case *ast.IfStmt:
			if s.Init != nil {
				as, isAS := s.Init.(*ast.AssignStmt)
				return isAS && len(as.Rhs) == 1 && (len(as.Lhs) == 1 || len(as.Lhs) == 2) && isRecvOnCh(as.Rhs[0])
			}
			if isRecvOnCh(s.Cond) {
				return true
			}
			if bin, isBin := ast.Unparen(s.Cond).(*ast.BinaryExpr); isBin && (bin.Op == token.EQL || bin.Op == token.NEQ) {
				return isRecvOnCh(bin.X) || isRecvOnCh(bin.Y)
			}
		}
		return false
	}

	recvIdx := -1
	for i := goIdx + 1; i < len(body.List); i++ {
		if isTopLevelUnconditionalRecv(body.List[i]) {
			recvIdx = i
			break
		}
	}
	if recvIdx == -1 {
		return false
	}

	// Disallow ReturnStmt, BranchStmt, or GoStmt anywhere in body.List[goIdx+1 : recvIdx].
	badBetween := false
	for i := goIdx + 1; i < recvIdx; i++ {
		ast.Inspect(body.List[i], func(n ast.Node) bool {
			if badBetween || n == nil {
				return false
			}
			switch n.(type) {
			case *ast.ReturnStmt, *ast.BranchStmt, *ast.GoStmt:
				badBetween = true
				return false
			case *ast.FuncLit:
				return false
			}
			return true
		})
	}
	if badBetween {
		return false
	}

	// Ensure chVar has exactly 3 identifier occurrences across the entire enclosing body:
	// 1 definition at defIdx, 1 channel send inside lit.Body, and 1 unconditional receive at recvIdx.
	refCount := 0
	ast.Inspect(body, func(n ast.Node) bool {
		if id, isID := n.(*ast.Ident); isID {
			if info.Defs[id] == chVar || info.Uses[id] == chVar {
				refCount++
			}
		}
		return true
	})
	return refCount == 3
}

func isMakeChanCall(info *types.Info, e ast.Expr) bool {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || (len(call.Args) != 1 && len(call.Args) != 2) {
		return false
	}
	id, ok := peelHarnessCallee(call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	b, ok := info.Uses[id].(*types.Builtin)
	if !ok || b.Name() != "make" {
		return false
	}
	if _, isCh := underlyingType(info.TypeOf(call.Args[0])).(*types.Chan); !isCh {
		return false
	}
	if len(call.Args) == 2 {
		tv, okTV := info.Types[call.Args[1]]
		if !okTV || tv.Value == nil || tv.Value.Kind() != constant.Int {
			return false
		}
		capVal, exact := constant.Int64Val(tv.Value)
		if !exact || (capVal != 0 && capVal != 1) {
			return false
		}
	}
	return true
}

func isFailfileStringOrSliceType(t types.Type) bool {
	if t == nil {
		return false
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Basic:
		return u.Kind() == types.String
	case *types.Slice:
		b, ok := types.Unalias(u.Elem()).Underlying().(*types.Basic)
		return ok && b.Kind() == types.String
	}
	return false
}

func isEmptyFailfileReset(info *types.Info, e ast.Expr) bool {
	e = ast.Unparen(e)
	if constStringEq(info, e, "") {
		return true
	}
	if id, ok := e.(*ast.Ident); ok && info.Uses[id] == types.Universe.Lookup("nil") {
		return true
	}
	if cl, ok := e.(*ast.CompositeLit); ok && len(cl.Elts) == 0 && isFailfileStringOrSliceType(info.TypeOf(cl)) {
		return true
	}
	return false
}

func isCategoryABoolFieldExpr(info *types.Info, e ast.Expr, categoryA map[*types.Var]bool) bool {
	sel, ok := ast.Unparen(e).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	b, ok := underlyingType(info.TypeOf(sel)).(*types.Basic)
	if !ok || b.Kind() != types.Bool {
		return false
	}
	baseId, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok {
		return false
	}
	v, ok := info.Uses[baseId].(*types.Var)
	return ok && categoryA[v]
}

func isHarnessFailfileExpr(
	info *types.Info,
	e ast.Expr,
	declFuncs map[*types.Func]*ast.FuncDecl,
	categoryA map[*types.Var]bool,
	failfileVars map[*types.Var]bool,
	failfileParams map[*types.Var]bool,
	failfileResults map[harnessParamKey]bool,
) bool {
	if e == nil {
		return false
	}
	e = ast.Unparen(e)
	if !isFailfileStringOrSliceType(info.TypeOf(e)) {
		return false
	}
	switch x := e.(type) {
	case *ast.Ident:
		v, ok := info.Uses[x].(*types.Var)
		return ok && (failfileVars[v] || failfileParams[v])
	case *ast.SelectorExpr:
		if baseId, ok := ast.Unparen(x.X).(*ast.Ident); ok {
			if v, ok := info.Uses[baseId].(*types.Var); ok && categoryA[v] {
				return true
			}
		}
	case *ast.CompositeLit:
		if len(x.Elts) == 0 {
			return false
		}
		saw := false
		for _, elt := range x.Elts {
			if isEmptyFailfileReset(info, elt) {
				continue
			}
			if isHarnessFailfileExpr(info, elt, declFuncs, categoryA, failfileVars, failfileParams, failfileResults) {
				saw = true
				continue
			}
			return false
		}
		return saw
	case *ast.CallExpr:
		if id, ok := peelHarnessCallee(x.Fun).(*ast.Ident); ok {
			if b, isB := info.Uses[id].(*types.Builtin); isB && b.Name() == "append" && len(x.Args) >= 2 {
				saw := false
				for _, arg := range x.Args {
					if isEmptyFailfileReset(info, arg) {
						continue
					}
					if isHarnessFailfileExpr(info, arg, declFuncs, categoryA, failfileVars, failfileParams, failfileResults) {
						saw = true
						continue
					}
					return false
				}
				return saw
			}
		}
		callee := resolveHarnessFuncExpr(info, x.Fun)
		if callee == nil || x.Ellipsis.IsValid() {
			return false
		}
		if callee.Pkg() != nil && callee.Pkg().Path() == "path/filepath" {
			switch callee.Name() {
			case "Join":
				if len(x.Args) < 2 {
					return false
				}
				for _, arg := range x.Args {
					if tv, ok := info.Types[arg]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
						if strings.Contains(constant.StringVal(tv.Value), "..") {
							return false
						}
					}
				}
				if constStringEq(info, x.Args[0], "testdata") && constStringEq(info, x.Args[1], "rapid") {
					return true
				}
				return isHarnessFailfileExpr(info, x.Args[0], declFuncs, categoryA, failfileVars, failfileParams, failfileResults)
			case "Dir", "Clean", "Glob":
				return len(x.Args) == 1 && isHarnessFailfileExpr(info, x.Args[0], declFuncs, categoryA, failfileVars, failfileParams, failfileResults)
			}
			return false
		}
		if declFuncs[callee] != nil && !callee.Exported() && callee.Signature().Results().Len() == 1 {
			return failfileResults[harnessParamKey{fn: callee, idx: 0}]
		}
	}
	return false
}

func computeHarnessFailfileProvenance(
	idx *harnessPkgIndex,
	categoryA map[*types.Var]bool,
) (map[*types.Var]bool, map[*types.Var]bool, map[harnessParamKey]bool) {
	info := idx.info
	pkgScope := idx.pkgTypes.Scope()
	declFuncs := idx.declFuncs
	initOnly := idx.initOnly
	funcValueTaken := idx.funcValueTaken
	callSites := idx.callSitesByFunc
	reassignedParams := idx.reassignedParams

	failfileVars := map[*types.Var]bool{}
	failfileParams := map[*types.Var]bool{}
	failfileResults := map[harnessParamKey]bool{}

	isFF := func(e ast.Expr) bool {
		return isHarnessFailfileExpr(info, e, declFuncs, categoryA, failfileVars, failfileParams, failfileResults)
	}

	changed := true
	for changed {
		changed = false
		for fn, fd := range declFuncs {
			if fn.Exported() || fd == nil || fd.Body == nil {
				continue
			}
			paramSet := map[*types.Var]bool{}
			for i := 0; i < fn.Signature().Params().Len(); i++ {
				paramSet[fn.Signature().Params().At(i)] = true
			}
			totalWrites := map[*types.Var]int{}
			validWrites := map[*types.Var]int{}
			positiveWrites := map[*types.Var]int{}
			addrTaken := map[*types.Var]bool{}
			isSelfAppend := func(target *types.Var, rhs ast.Expr) (valid, positive bool) {
				call, ok := ast.Unparen(rhs).(*ast.CallExpr)
				if !ok || len(call.Args) < 2 {
					return false, false
				}
				id, ok := peelHarnessCallee(call.Fun).(*ast.Ident)
				if !ok {
					return false, false
				}
				b, ok := info.Uses[id].(*types.Builtin)
				if !ok || b.Name() != "append" {
					return false, false
				}
				if lookupLocalVar(info, pkgScope, call.Args[0]) != target {
					return false, false
				}
				sawPos := false
				for _, arg := range call.Args[1:] {
					if isEmptyFailfileReset(info, arg) {
						continue
					}
					if isFF(arg) {
						sawPos = true
						continue
					}
					return false, false
				}
				return true, sawPos
			}

			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch s := n.(type) {
				case *ast.ValueSpec:
					for i, nm := range s.Names {
						v, ok := info.Defs[nm].(*types.Var)
						if !ok || v == nil || v.Parent() == pkgScope || paramSet[v] || !isFailfileStringOrSliceType(v.Type()) {
							continue
						}
						if i < len(s.Values) {
							totalWrites[v]++
							if isEmptyFailfileReset(info, s.Values[i]) {
								validWrites[v]++
							} else if isFF(s.Values[i]) {
								validWrites[v]++
								positiveWrites[v]++
							}
						}
					}
				case *ast.AssignStmt:
					if len(s.Rhs) == 1 && len(s.Lhs) > 1 {
						call, isCall := ast.Unparen(s.Rhs[0]).(*ast.CallExpr)
						var callee *types.Func
						if isCall {
							callee = resolveHarnessFuncExpr(info, call.Fun)
						}
						for i, lhs := range s.Lhs {
							v := lookupLocalVar(info, pkgScope, lhs)
							if v == nil || paramSet[v] || !isFailfileStringOrSliceType(v.Type()) {
								continue
							}
							totalWrites[v]++
							if callee != nil && !call.Ellipsis.IsValid() {
								if callee.Pkg() != nil && callee.Pkg().Path() == "path/filepath" && callee.Name() == "Glob" && i == 0 && len(call.Args) == 1 && isFF(call.Args[0]) {
									validWrites[v]++
									positiveWrites[v]++
								} else if declFuncs[callee] != nil && !callee.Exported() && failfileResults[harnessParamKey{fn: callee, idx: i}] {
									validWrites[v]++
									positiveWrites[v]++
								}
							}
						}
					} else {
						for i, lhs := range s.Lhs {
							v := lookupLocalVar(info, pkgScope, lhs)
							if v == nil || paramSet[v] || !isFailfileStringOrSliceType(v.Type()) {
								continue
							}
							totalWrites[v]++
							if s.Tok == token.ASSIGN || s.Tok == token.DEFINE {
								if i < len(s.Rhs) {
									if isEmptyFailfileReset(info, s.Rhs[i]) {
										validWrites[v]++
									} else if isFF(s.Rhs[i]) {
										validWrites[v]++
										positiveWrites[v]++
									} else if s.Tok == token.ASSIGN {
										if okSA, posSA := isSelfAppend(v, s.Rhs[i]); okSA {
											validWrites[v]++
											if posSA {
												positiveWrites[v]++
											}
										}
									}
								}
							}
						}
					}
				case *ast.RangeStmt:
					if s.Key != nil {
						if kv := lookupLocalVar(info, pkgScope, s.Key); kv != nil && !paramSet[kv] && isFailfileStringOrSliceType(kv.Type()) {
							totalWrites[kv]++
						}
					}
					if s.Value != nil {
						if vv := lookupLocalVar(info, pkgScope, s.Value); vv != nil && !paramSet[vv] && isFailfileStringOrSliceType(vv.Type()) {
							totalWrites[vv]++
							if isFF(s.X) {
								validWrites[vv]++
								positiveWrites[vv]++
							}
						}
					}
				case *ast.UnaryExpr:
					if s.Op == token.AND {
						if v := lookupLocalVar(info, pkgScope, s.X); v != nil {
							addrTaken[v] = true
						}
					}
				}
				return true
			})

			for v, tot := range totalWrites {
				if tot > 0 && validWrites[v] == tot && positiveWrites[v] > 0 && !addrTaken[v] && !failfileVars[v] {
					failfileVars[v] = true
					changed = true
				}
			}

			if !initOnly[fn] {
				resTuple := fn.Signature().Results()
				for rIdx := 0; rIdx < resTuple.Len(); rIdx++ {
					key := harnessParamKey{fn: fn, idx: rIdx}
					if failfileResults[key] || !isFailfileStringOrSliceType(resTuple.At(rIdx).Type()) {
						continue
					}
					allValid := true
					sawPos := false
					ast.Inspect(fd.Body, func(n ast.Node) bool {
						if !allValid || n == nil {
							return false
						}
						if _, isLit := n.(*ast.FuncLit); isLit {
							return false
						}
						ret, ok := n.(*ast.ReturnStmt)
						if !ok {
							return true
						}
						if rIdx >= len(ret.Results) {
							allValid = false
							return false
						}
						rExpr := ret.Results[rIdx]
						if isEmptyFailfileReset(info, rExpr) {
							return true
						}
						if isFF(rExpr) {
							sawPos = true
							return true
						}
						allValid = false
						return false
					})
					if allValid && sawPos {
						failfileResults[key] = true
						changed = true
					}
				}
			}

			if !funcValueTaken[fn] && !fn.Signature().Variadic() && len(callSites[fn]) > 0 {
				params := fn.Signature().Params()
				for pIdx := 0; pIdx < params.Len(); pIdx++ {
					pv := params.At(pIdx)
					if failfileParams[pv] || reassignedParams[pv] || !isFailfileStringOrSliceType(pv.Type()) {
						continue
					}
					allSitesOK := true
					sawPos := false
					for _, site := range callSites[fn] {
						if site.Ellipsis.IsValid() || pIdx >= len(site.Args) {
							allSitesOK = false
							break
						}
						arg := site.Args[pIdx]
						if isEmptyFailfileReset(info, arg) {
							continue
						}
						if isFF(arg) {
							sawPos = true
							continue
						}
						allSitesOK = false
						break
					}
					if allSitesOK && sawPos {
						failfileParams[pv] = true
						changed = true
					}
				}
			}
		}
	}

	return failfileVars, failfileParams, failfileResults
}

func collectHarnessTempFileVars(
	idx *harnessPkgIndex,
	body *ast.BlockStmt,
	categoryA map[*types.Var]bool,
	failfileVars map[*types.Var]bool,
	failfileParams map[*types.Var]bool,
	failfileResults map[harnessParamKey]bool,
) map[*types.Var]bool {
	info := idx.info
	pkgScope := idx.pkgTypes.Scope()
	declFuncs := idx.declFuncs
	totalWrites := map[*types.Var]int{}
	createTempWrites := map[*types.Var]int{}
	addrTaken := map[*types.Var]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			isCT := false
			if len(s.Rhs) == 1 && len(s.Lhs) == 2 {
				if call, ok := ast.Unparen(s.Rhs[0]).(*ast.CallExpr); ok && !call.Ellipsis.IsValid() && len(call.Args) == 2 {
					if callee := resolveHarnessFuncExpr(info, call.Fun); callee != nil && callee.Pkg() != nil &&
						callee.Pkg().Path() == "os" && callee.Name() == "CreateTemp" &&
						isHarnessFailfileExpr(info, call.Args[0], declFuncs, categoryA, failfileVars, failfileParams, failfileResults) {
						isCT = true
					}
				}
			}
			for i, lhs := range s.Lhs {
				v := lookupLocalVar(info, pkgScope, lhs)
				if v == nil {
					continue
				}
				totalWrites[v]++
				if isCT && i == 0 && (s.Tok == token.DEFINE || s.Tok == token.ASSIGN) {
					createTempWrites[v]++
				}
			}
		case *ast.UnaryExpr:
			if s.Op == token.AND {
				if v := lookupLocalVar(info, pkgScope, s.X); v != nil {
					addrTaken[v] = true
				}
			}
		}
		return true
	})
	out := map[*types.Var]bool{}
	for v, c := range createTempWrites {
		if c == 1 && totalWrites[v] == 1 && !addrTaken[v] {
			out[v] = true
		}
	}
	return out
}

func isTempFileNameCall(info *types.Info, e ast.Expr, tempFileVars map[*types.Var]bool) bool {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 0 {
		return false
	}
	sel, ok := peelHarnessCallee(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "Name" {
		return false
	}
	baseId, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok {
		return false
	}
	v, ok := info.Uses[baseId].(*types.Var)
	return ok && tempFileVars[v]
}

func isDebugVisHTMLName(info *types.Info, body *ast.BlockStmt, e ast.Expr) bool {
	isSprintfHTML := func(expr ast.Expr) bool {
		call, ok := ast.Unparen(expr).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) < 1 {
			return false
		}
		callee := resolveHarnessFuncExpr(info, call.Fun)
		if callee == nil || callee.Pkg() == nil || callee.Pkg().Path() != "fmt" || callee.Name() != "Sprintf" {
			return false
		}
		tv, ok := info.Types[call.Args[0]]
		if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
			return false
		}
		fmtStr := constant.StringVal(tv.Value)
		return strings.HasSuffix(fmtStr, ".html") && !strings.ContainsAny(fmtStr, `/\`) && !strings.Contains(fmtStr, "..")
	}
	if isSprintfHTML(e) {
		return true
	}
	if body == nil {
		return false
	}
	id, ok := ast.Unparen(e).(*ast.Ident)
	if !ok {
		return false
	}
	targetVar, ok := info.Uses[id].(*types.Var)
	if !ok || targetVar == nil {
		return false
	}
	writes := 0
	valid := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range s.Lhs {
				if lId, ok := ast.Unparen(lhs).(*ast.Ident); ok && (info.Defs[lId] == targetVar || info.Uses[lId] == targetVar) {
					writes++
					if i < len(s.Rhs) && (s.Tok == token.DEFINE || s.Tok == token.ASSIGN) && isSprintfHTML(s.Rhs[i]) {
						valid = true
					}
				}
			}
		case *ast.UnaryExpr:
			if s.Op == token.AND {
				if lId, ok := ast.Unparen(s.X).(*ast.Ident); ok && info.Uses[lId] == targetVar {
					writes += 2
				}
			}
		}
		return true
	})
	return writes == 1 && valid
}

func verifyHarnessOSFuncCall(
	info *types.Info,
	enclosingFD *ast.FuncDecl,
	enclosingFn *types.Func,
	inInitRoot bool,
	inLit bool,
	inFlagBoolGuard bool,
	fnName string,
	call *ast.CallExpr,
	isFailfile func(ast.Expr) bool,
	tempFileVars map[*types.Var]bool,
) bool {
	if call.Ellipsis.IsValid() {
		return false
	}
	switch fnName {
	case "Getpid":
		return len(call.Args) == 0
	case "IsNotExist":
		return len(call.Args) == 1
	case "Open":
		return !inInitRoot && enclosingFn != nil && !enclosingFn.Exported() && len(call.Args) == 1 && isFailfile(call.Args[0])
	case "MkdirAll", "CreateTemp":
		return !inInitRoot && enclosingFn != nil && !enclosingFn.Exported() && len(call.Args) == 2 && isFailfile(call.Args[0])
	case "Remove":
		return !inInitRoot && enclosingFn != nil && !enclosingFn.Exported() && len(call.Args) == 1 && isTempFileNameCall(info, call.Args[0], tempFileVars)
	case "Rename":
		return !inInitRoot && enclosingFn != nil && !enclosingFn.Exported() && len(call.Args) == 2 &&
			isTempFileNameCall(info, call.Args[0], tempFileVars) && isFailfile(call.Args[1])
	case "Create":
		var body *ast.BlockStmt
		if enclosingFD != nil {
			body = enclosingFD.Body
		}
		return !inInitRoot && !inLit && enclosingFn != nil && !enclosingFn.Exported() &&
			inFlagBoolGuard && len(call.Args) == 1 && isDebugVisHTMLName(info, body, call.Args[0])
	}
	return false
}

func verifyHarnessTemplateCall(
	audited bool,
	info *types.Info,
	pkgTypes *types.Package,
	callee *types.Func,
	call *ast.CallExpr,
) bool {
	if !audited || info == nil || pkgTypes == nil || callee == nil || call == nil || call.Ellipsis.IsValid() {
		return false
	}
	sig := callee.Signature()
	if sig.Recv() == nil {
		switch callee.Name() {
		case "New":
			return len(call.Args) == 1
		case "Must":
			return len(call.Args) == 1 || len(call.Args) == 2
		default:
			return false
		}
	}
	sel, ok := peelHarnessCallee(call.Fun).(*ast.SelectorExpr)
	if !ok || info.Selections[sel] == nil || info.Selections[sel].Kind() != types.MethodVal {
		return false
	}
	switch callee.Name() {
	case "Parse":
		return len(call.Args) == 1
	case "Execute":
		if len(call.Args) != 2 {
			return false
		}
		return isMethodlessCarrierFreeHarnessData(audited, pkgTypes, info.TypeOf(call.Args[1]))
	default:
		return false
	}
}

func isMethodlessCarrierFreeHarnessData(audited bool, pkgTypes *types.Package, t types.Type) bool {
	if !audited || pkgTypes == nil || t == nil || dynstate.TypeMayCarryUnknownDynamic(audited, t) {
		return false
	}
	top := types.Unalias(t)
	if ptr, ok := top.(*types.Pointer); ok {
		top = types.Unalias(ptr.Elem())
	}
	named, ok := top.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() != pkgTypes || named.Obj().Exported() {
		return false
	}
	if _, isStruct := named.Underlying().(*types.Struct); !isStruct {
		return false
	}
	return !typeTreeHasAnyMethods(t, map[types.Type]bool{})
}

func typeTreeHasAnyMethods(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if seen[t] {
		return false
	}
	seen[t] = true
	if types.NewMethodSet(t).Len() > 0 {
		return true
	}
	if _, isPtr := t.(*types.Pointer); !isPtr && !types.IsInterface(t) {
		if types.NewMethodSet(types.NewPointer(t)).Len() > 0 {
			return true
		}
	}
	switch x := t.Underlying().(type) {
	case *types.Pointer:
		return typeTreeHasAnyMethods(x.Elem(), seen)
	case *types.Slice:
		return typeTreeHasAnyMethods(x.Elem(), seen)
	case *types.Array:
		return typeTreeHasAnyMethods(x.Elem(), seen)
	case *types.Map:
		return typeTreeHasAnyMethods(x.Key(), seen) || typeTreeHasAnyMethods(x.Elem(), seen)
	case *types.Struct:
		for i := 0; i < x.NumFields(); i++ {
			if typeTreeHasAnyMethods(x.Field(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}
