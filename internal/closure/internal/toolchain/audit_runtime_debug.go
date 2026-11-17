package toolchain

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"slices"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/closure/internal/cprep"
)

var runtimeDebugReservedIdents = map[string]bool{
	"nil": true, "true": true, "false": true,
	"string": true, "bool": true, "int": true, "error": true,
	"len": true, "new": true, "append": true, "make": true, "copy": true, "clear": true,
	"fmt": true, "runtime": true, "strconv": true, "strings": true,
}

var allowedRuntimeDebugModFileImports = map[string]bool{
	"fmt":     true,
	"runtime": true,
	"strconv": true,
	"strings": true,
}

var allowedRuntimeDebugStringsSels = map[string]bool{
	"Builder":     true,
	"ContainsAny": true,
	"Cut":         true,
	"HasPrefix":   true,
	"Split":       true,
}

var allowedRuntimeDebugStrconvSels = map[string]bool{
	"Quote":        true,
	"QuotedPrefix": true,
	"Unquote":      true,
}

// VerifyRuntimeDebugPackageAST verifies the AST and compiler directives of
// runtime/debug's ReadBuildInfo, ParseBuildInfo, and BuildInfo surface.
func VerifyRuntimeDebugPackageAST(files []*ast.File, goSrcs []string) error {
	return VerifyRuntimeDebugPackage(context.Background(), files, goSrcs, nil, nil)
}

// VerifyRuntimeDebugPackage verifies the selected Go and assembly files of
// standard-library package runtime/debug for ReadBuildInfo and ParseBuildInfo.
func VerifyRuntimeDebugPackage(ctx context.Context, files []*ast.File, goSrcs []string, asmSources map[string]string, selectedHeaders map[string]bool) error {
	if len(files) == 0 || len(files) != len(goSrcs) {
		return fmt.Errorf("runtime/debug: invalid file/source slices (%d files, %d srcs)", len(files), len(goSrcs))
	}
	if len(asmSources) > 0 {
		asmNames := make([]string, 0, len(asmSources))
		for name := range asmSources {
			asmNames = append(asmNames, name)
		}
		slices.Sort(asmNames)
		for _, name := range asmNames {
			src := asmSources[name]
			if err := VerifyToolchainAssemblyFile(ctx, "runtime/debug", name, src, selectedHeaders); err != nil {
				return fmt.Errorf("runtime/debug: assembly %s: %w", name, err)
			}
			stripped := cprep.StripAssemblyComments(src, false, true)
			for _, rawLine := range strings.Split(stripped, "\n") {
				line := strings.TrimSpace(rawLine)
				if line != "" && !strings.HasPrefix(line, "#") {
					return fmt.Errorf("runtime/debug: unexpected assembly statement in %s: %q", name, line)
				}
			}
		}
	}

	for _, src := range goSrcs {
		err := scanVerifiedLinknameDirectives(src, func(line string, fields []string) error {
			if len(fields) != 3 {
				return fmt.Errorf("runtime/debug: unapproved single-argument linkname %q", line)
			}
			localSym, target := fields[1], fields[2]
			switch localSym {
			case "runtime_setCrashFD":
				if target != "runtime.setCrashFD" {
					return fmt.Errorf("runtime/debug: unapproved runtime_setCrashFD target %q", target)
				}
				return nil
			case "modinfo":
				if target != "runtime.modinfo" && target != "runtime.debug_modinfo" {
					return fmt.Errorf("runtime/debug: unapproved modinfo target %q", target)
				}
				return nil
			default:
				return fmt.Errorf("runtime/debug: forbidden linkname on %q (%q)", localSym, line)
			}
		})
		if err != nil {
			return err
		}
	}

	idx, err := indexPackageAST("runtime/debug", files, runtimeDebugReservedIdents, allowedRuntimeDebugModFileImports)
	if err != nil {
		return err
	}
	if idx.hasInitFunc {
		return fmt.Errorf("runtime/debug: unexpected init function")
	}
	if len(idx.pkgVarCounts) > 0 {
		return fmt.Errorf("runtime/debug: unexpected package-level variable declarations")
	}
	if len(idx.dupTopFuncs) > 0 || idx.anyDupTypeMethod {
		return fmt.Errorf("runtime/debug: duplicate function or method declarations")
	}

	isStringType := func(e ast.Expr) bool {
		_, ok := isIdentNamed(e, "string")
		return ok
	}
	isModuleValType := func(e ast.Expr) bool {
		_, ok := isIdentNamed(e, "Module")
		return ok
	}
	isModulePtrType := func(e ast.Expr) bool {
		st, ok := unwrapParens(e).(*ast.StarExpr)
		if !ok {
			return false
		}
		_, okID := isIdentNamed(st.X, "Module")
		return okID
	}
	isDepsSliceType := func(e ast.Expr) bool {
		at, ok := unwrapParens(e).(*ast.ArrayType)
		return ok && at.Len == nil && isModulePtrType(at.Elt)
	}
	isSettingsSliceType := func(e ast.Expr) bool {
		at, ok := unwrapParens(e).(*ast.ArrayType)
		if !ok || at.Len != nil {
			return false
		}
		_, okID := isIdentNamed(at.Elt, "BuildSetting")
		return okID
	}

	if _, _, ok := idx.VerifyStructFields("BuildInfo", map[string]func(ast.Expr) bool{
		"GoVersion": isStringType,
		"Path":      isStringType,
		"Main":      isModuleValType,
		"Deps":      isDepsSliceType,
		"Settings":  isSettingsSliceType,
	}, false); !ok {
		return fmt.Errorf("runtime/debug: BuildInfo struct schema mismatch")
	}
	if _, _, ok := idx.VerifyStructFields("Module", map[string]func(ast.Expr) bool{
		"Path":    isStringType,
		"Version": isStringType,
		"Sum":     isStringType,
		"Replace": isModulePtrType,
	}, false); !ok {
		return fmt.Errorf("runtime/debug: Module struct schema mismatch")
	}
	if _, _, ok := idx.VerifyStructFields("BuildSetting", map[string]func(ast.Expr) bool{
		"Key":   isStringType,
		"Value": isStringType,
	}, false); !ok {
		return fmt.Errorf("runtime/debug: BuildSetting struct schema mismatch")
	}

	modinfoDecls := idx.funcDeclsByName["modinfo"]
	if len(modinfoDecls) != 1 || idx.pkgDeclCounts["modinfo"] != 1 {
		return fmt.Errorf("runtime/debug: missing or duplicate modinfo stub")
	}
	modFn := modinfoDecls[0]
	if modFn.Recv != nil || modFn.Body != nil || modFn.Type == nil || modFn.Type.TypeParams != nil ||
		(modFn.Type.Params != nil && modFn.Type.Params.NumFields() != 0) ||
		modFn.Type.Results == nil || modFn.Type.Results.NumFields() != 1 ||
		!isStringType(funcResultFieldTypeAt(modFn.Type.Results, 0)) {
		return fmt.Errorf("runtime/debug: modinfo signature/body mismatch")
	}

	kernel := NewPackageInactiveKernel(idx, files, nil, nil)
	if err := verifyReadBuildInfoBody(idx, kernel); err != nil {
		return err
	}
	if err := verifyRuntimeDebugPureFunc(idx, kernel, "", "quoteKey", false, 1, 1, "bool"); err != nil {
		return err
	}
	if err := verifyRuntimeDebugPureFunc(idx, kernel, "", "quoteValue", false, 1, 1, "bool"); err != nil {
		return err
	}
	if len(idx.typeMethods["BuildInfo"]) != 1 || len(idx.typeMethods["Module"]) != 0 || len(idx.typeMethods["BuildSetting"]) != 0 {
		return fmt.Errorf("runtime/debug: unexpected method set on BuildInfo/Module/BuildSetting")
	}
	if err := verifyRuntimeDebugPureFunc(idx, kernel, "BuildInfo", "String", true, 0, 1, "string"); err != nil {
		return err
	}
	if err := verifyRuntimeDebugPureFunc(idx, kernel, "", "ParseBuildInfo", false, 1, 2, "error"); err != nil {
		return err
	}
	return nil
}

func verifyRuntimeDebugModFileImports(f *ast.File) error {
	if f == nil {
		return fmt.Errorf("runtime/debug: missing AST file")
	}
	for _, imp := range f.Imports {
		if imp.Path == nil {
			return fmt.Errorf("runtime/debug: empty import path")
		}
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return err
		}
		if imp.Name != nil || !allowedRuntimeDebugModFileImports[p] {
			return fmt.Errorf("runtime/debug: unapproved import %q in BuildInfo file", p)
		}
	}
	return nil
}

func verifyReadBuildInfoBody(idx *PackageASTIndex, kernel *PackageInactiveKernel) error {
	fn, f, ok := idx.VerifyFuncPreamble("", "ReadBuildInfo", false, runtimeDebugReservedIdents)
	if !ok {
		return fmt.Errorf("runtime/debug: invalid ReadBuildInfo preamble")
	}
	if err := verifyRuntimeDebugModFileImports(f); err != nil {
		return err
	}
	if !idx.hasFileImport(f, "runtime") {
		return fmt.Errorf("runtime/debug: ReadBuildInfo file missing runtime import")
	}
	if (fn.Type.Params != nil && fn.Type.Params.NumFields() != 0) ||
		fn.Type.Results == nil || fn.Type.Results.NumFields() != 2 {
		return fmt.Errorf("runtime/debug: ReadBuildInfo arity mismatch")
	}
	r0 := funcResultFieldTypeAt(fn.Type.Results, 0)
	r1 := funcResultFieldTypeAt(fn.Type.Results, 1)
	st0, ok0 := unwrapParens(r0).(*ast.StarExpr)
	_, okBI := false, false
	if ok0 {
		_, okBI = isIdentNamed(st0.X, "BuildInfo")
	}
	_, okBool := isIdentNamed(r1, "bool")
	if !okBI || !okBool {
		return fmt.Errorf("runtime/debug: ReadBuildInfo return type mismatch")
	}

	stmts, _ := kernel.PruneBlockStmts(fn.Body.List, fn, nil, nil, nil)
	if len(stmts) != 7 {
		return fmt.Errorf("runtime/debug: ReadBuildInfo statement count %d != 7", len(stmts))
	}

	// 1. data := modinfo()
	as0, okA0 := stmts[0].(*ast.AssignStmt)
	if !okA0 || as0.Tok != token.DEFINE || len(as0.Lhs) != 1 || len(as0.Rhs) != 1 {
		return fmt.Errorf("runtime/debug: ReadBuildInfo step 1 must bind modinfo()")
	}
	dataID, okData := unwrapParens(as0.Lhs[0]).(*ast.Ident)
	call0, okC0 := unwrapParens(as0.Rhs[0]).(*ast.CallExpr)
	if !okData || dataID.Name == "" || dataID.Name == "_" || !okC0 || call0.Ellipsis.IsValid() || len(call0.Args) != 0 {
		return fmt.Errorf("runtime/debug: ReadBuildInfo step 1 malformed")
	}
	if _, okMod := isIdentNamed(call0.Fun, "modinfo"); !okMod {
		return fmt.Errorf("runtime/debug: ReadBuildInfo step 1 must call modinfo()")
	}
	dataVar := dataID.Name

	// 2. if len(data) < 32 { return nil, false }
	if1, okI1 := stmts[1].(*ast.IfStmt)
	if !okI1 || if1.Init != nil || if1.Else != nil || !isReturnNilFalseBlock(if1.Body) || !isLenLessThanConst(if1.Cond, dataVar, "32") {
		return fmt.Errorf("runtime/debug: ReadBuildInfo step 2 must guard len(%s) < 32", dataVar)
	}

	// 3. data = data[16 : len(data)-16]
	as2, okA2 := stmts[2].(*ast.AssignStmt)
	if !okA2 || as2.Tok != token.ASSIGN || len(as2.Lhs) != 1 || len(as2.Rhs) != 1 {
		return fmt.Errorf("runtime/debug: ReadBuildInfo step 3 must slice sentinel bounds")
	}
	if _, okLHS := isIdentNamed(as2.Lhs[0], dataVar); !okLHS || !isSentinelTrimSlice(as2.Rhs[0], dataVar) {
		return fmt.Errorf("runtime/debug: ReadBuildInfo step 3 sentinel slice mismatch")
	}

	// 4. bi, err := ParseBuildInfo(data)
	as3, okA3 := stmts[3].(*ast.AssignStmt)
	if !okA3 || as3.Tok != token.DEFINE || len(as3.Lhs) != 2 || len(as3.Rhs) != 1 {
		return fmt.Errorf("runtime/debug: ReadBuildInfo step 4 must call ParseBuildInfo")
	}
	biID, okBIID := unwrapParens(as3.Lhs[0]).(*ast.Ident)
	errID, okErrID := unwrapParens(as3.Lhs[1]).(*ast.Ident)
	call3, okC3 := unwrapParens(as3.Rhs[0]).(*ast.CallExpr)
	if !okBIID || !okErrID || biID.Name == "" || biID.Name == "_" || errID.Name == "" || errID.Name == "_" || biID.Name == errID.Name || !okC3 || call3.Ellipsis.IsValid() || len(call3.Args) != 1 {
		return fmt.Errorf("runtime/debug: ReadBuildInfo step 4 malformed")
	}
	if _, okPBI := isIdentNamed(call3.Fun, "ParseBuildInfo"); !okPBI {
		return fmt.Errorf("runtime/debug: ReadBuildInfo step 4 must call ParseBuildInfo")
	}
	if _, okArg := isIdentNamed(call3.Args[0], dataVar); !okArg {
		return fmt.Errorf("runtime/debug: ReadBuildInfo step 4 argument mismatch")
	}

	// 5. if err != nil { return nil, false }
	if4, okI4 := stmts[4].(*ast.IfStmt)
	if !okI4 || if4.Init != nil || if4.Else != nil || !isReturnNilFalseBlock(if4.Body) || !isIdentNeqNil(if4.Cond, errID.Name) {
		return fmt.Errorf("runtime/debug: ReadBuildInfo step 5 must guard %s != nil", errID.Name)
	}

	// 6. bi.GoVersion = runtime.Version()
	as5, okA5 := stmts[5].(*ast.AssignStmt)
	if !okA5 || as5.Tok != token.ASSIGN || len(as5.Lhs) != 1 || len(as5.Rhs) != 1 {
		return fmt.Errorf("runtime/debug: ReadBuildInfo step 6 must assign GoVersion")
	}
	if _, okGV := isSelectorBaseField(as5.Lhs[0], biID.Name, "GoVersion"); !okGV {
		return fmt.Errorf("runtime/debug: ReadBuildInfo step 6 must assign %s.GoVersion", biID.Name)
	}
	call5, okC5 := unwrapParens(as5.Rhs[0]).(*ast.CallExpr)
	if !okC5 || call5.Ellipsis.IsValid() || len(call5.Args) != 0 {
		return fmt.Errorf("runtime/debug: ReadBuildInfo step 6 must call runtime.Version()")
	}
	if _, okVer := isSelectorBaseField(call5.Fun, "runtime", "Version"); !okVer {
		return fmt.Errorf("runtime/debug: ReadBuildInfo step 6 must call runtime.Version()")
	}

	// 7. return bi, true
	ret6, okR6 := stmts[6].(*ast.ReturnStmt)
	if !okR6 || len(ret6.Results) != 2 {
		return fmt.Errorf("runtime/debug: ReadBuildInfo step 7 must return (%s, true)", biID.Name)
	}
	_, okRetBI := isIdentNamed(ret6.Results[0], biID.Name)
	_, okRetTrue := isIdentNamed(ret6.Results[1], "true")
	if !okRetBI || !okRetTrue {
		return fmt.Errorf("runtime/debug: ReadBuildInfo step 7 return mismatch")
	}
	return nil
}

func isReturnNilFalseBlock(blk *ast.BlockStmt) bool {
	if blk == nil || len(blk.List) != 1 {
		return false
	}
	ret, ok := blk.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 2 {
		return false
	}
	_, okNil := isIdentNamed(ret.Results[0], "nil")
	_, okFalse := isIdentNamed(ret.Results[1], "false")
	return okNil && okFalse
}

func isLenLessThanConst(expr ast.Expr, varName, litVal string) bool {
	bin, ok := unwrapParens(expr).(*ast.BinaryExpr)
	if !ok || bin.Op != token.LSS {
		return false
	}
	call, okC := unwrapParens(bin.X).(*ast.CallExpr)
	if !okC || call.Ellipsis.IsValid() || len(call.Args) != 1 {
		return false
	}
	_, okLen := isIdentNamed(call.Fun, "len")
	_, okArg := isIdentNamed(call.Args[0], varName)
	lit, okLit := unwrapParens(bin.Y).(*ast.BasicLit)
	return okLen && okArg && okLit && lit.Kind == token.INT && lit.Value == litVal
}

func isSentinelTrimSlice(expr ast.Expr, varName string) bool {
	sl, ok := unwrapParens(expr).(*ast.SliceExpr)
	if !ok || sl.Slice3 || sl.Low == nil || sl.High == nil {
		return false
	}
	if _, okX := isIdentNamed(sl.X, varName); !okX {
		return false
	}
	lowLit, okLow := unwrapParens(sl.Low).(*ast.BasicLit)
	if !okLow || lowLit.Kind != token.INT || lowLit.Value != "16" {
		return false
	}
	bin, okBin := unwrapParens(sl.High).(*ast.BinaryExpr)
	if !okBin || bin.Op != token.SUB {
		return false
	}
	call, okC := unwrapParens(bin.X).(*ast.CallExpr)
	if !okC || call.Ellipsis.IsValid() || len(call.Args) != 1 {
		return false
	}
	_, okLen := isIdentNamed(call.Fun, "len")
	_, okArg := isIdentNamed(call.Args[0], varName)
	hiLit, okHi := unwrapParens(bin.Y).(*ast.BasicLit)
	return okLen && okArg && okHi && hiLit.Kind == token.INT && hiLit.Value == "16"
}

func isIdentNeqNil(expr ast.Expr, varName string) bool {
	bin, ok := unwrapParens(expr).(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return false
	}
	if _, okX := isIdentNamed(bin.X, varName); okX {
		_, okNil := isIdentNamed(bin.Y, "nil")
		return okNil
	}
	if _, okY := isIdentNamed(bin.Y, varName); okY {
		_, okNil := isIdentNamed(bin.X, "nil")
		return okNil
	}
	return false
}

func verifyRuntimeDebugPureFunc(idx *PackageASTIndex, kernel *PackageInactiveKernel, recvType, name string, wantPtrRecv bool, wantParams, wantResults int, lastResType string) error {
	fn, f, ok := idx.VerifyFuncPreamble(recvType, name, wantPtrRecv, runtimeDebugReservedIdents)
	if !ok {
		return fmt.Errorf("runtime/debug: invalid %s preamble", name)
	}
	if err := verifyRuntimeDebugModFileImports(f); err != nil {
		return err
	}
	gotParams := 0
	if fn.Type.Params != nil {
		for _, fld := range fn.Type.Params.List {
			if _, isStr := isIdentNamed(fld.Type, "string"); !isStr {
				return fmt.Errorf("runtime/debug: %s parameter type mismatch", name)
			}
		}
		gotParams = fn.Type.Params.NumFields()
	}
	if gotParams != wantParams || fn.Type.Results == nil || fn.Type.Results.NumFields() != wantResults {
		return fmt.Errorf("runtime/debug: %s signature arity mismatch", name)
	}
	if wantResults == 2 {
		st, okS := unwrapParens(funcResultFieldTypeAt(fn.Type.Results, 0)).(*ast.StarExpr)
		if !okS {
			return fmt.Errorf("runtime/debug: %s first result must be *BuildInfo", name)
		}
		if _, okBI := isIdentNamed(st.X, "BuildInfo"); !okBI {
			return fmt.Errorf("runtime/debug: %s first result must be *BuildInfo", name)
		}
	}
	if _, okLast := isIdentNamed(funcResultFieldTypeAt(fn.Type.Results, wantResults-1), lastResType); !okLast {
		return fmt.Errorf("runtime/debug: %s result type mismatch", name)
	}

	structFieldSets := map[string]map[string]bool{
		"BuildInfo":    {"GoVersion": true, "Path": true, "Main": true, "Deps": true, "Settings": true},
		"Module":       {"Path": true, "Version": true, "Sum": true, "Replace": true},
		"BuildSetting": {"Key": true, "Value": true},
	}
	structLitKeys := map[*ast.Ident]bool{}
	localBuilders := collectLocalStringsBuilderVars(fn)
	var astErr error
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if astErr != nil || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.GoStmt, *ast.SendStmt:
			astErr = fmt.Errorf("runtime/debug: forbidden concurrency in %s", name)
			return false
		case *ast.UnaryExpr:
			if x.Op == token.ARROW {
				astErr = fmt.Errorf("runtime/debug: forbidden channel receive in %s", name)
				return false
			}
		case *ast.CompositeLit:
			tID, okT := unwrapParens(x.Type).(*ast.Ident)
			fset := structFieldSets[""]
			if okT {
				fset = structFieldSets[tID.Name]
			}
			if fset == nil {
				astErr = fmt.Errorf("runtime/debug: unapproved composite literal in %s", name)
				return false
			}
			for _, elt := range x.Elts {
				kv, okKV := elt.(*ast.KeyValueExpr)
				if !okKV {
					astErr = fmt.Errorf("runtime/debug: positional struct literal element in %s", name)
					return false
				}
				kID, okK := unwrapParens(kv.Key).(*ast.Ident)
				if !okK || !fset[kID.Name] {
					astErr = fmt.Errorf("runtime/debug: invalid struct literal key in %s", name)
					return false
				}
				structLitKeys[kID] = true
			}
		case *ast.CallExpr:
			if sel, okS := unwrapParens(x.Fun).(*ast.SelectorExpr); okS {
				if pkgID, okID := unwrapParens(sel.X).(*ast.Ident); okID && pkgID.Name == "fmt" && sel.Sel.Name == "Fprintf" {
					if x.Ellipsis.IsValid() || len(x.Args) < 2 {
						astErr = fmt.Errorf("runtime/debug: invalid fmt.Fprintf arity in %s", name)
						return false
					}
					wID, okW := unwrapParens(x.Args[0]).(*ast.Ident)
					if !okW || !localBuilders[wID.Name] {
						astErr = fmt.Errorf("runtime/debug: fmt.Fprintf non-builder sink in %s", name)
						return false
					}
					fmtLit, okLit := unwrapParens(x.Args[1]).(*ast.BasicLit)
					if !okLit || fmtLit.Kind != token.STRING {
						astErr = fmt.Errorf("runtime/debug: non-literal fmt.Fprintf format in %s", name)
						return false
					}
					unq, err := strconv.Unquote(fmtLit.Value)
					if err != nil || auditset.FormatStringExposesPointerIdentity(unq) {
						astErr = fmt.Errorf("runtime/debug: pointer-exposing format in %s", name)
						return false
					}
				}
			}
		}
		return true
	})
	if astErr != nil {
		return astErr
	}

	scope := map[string]bool{}
	if rName := recvVarName(fn); rName != "" {
		scope[rName] = true
	}
	for _, fl := range []*ast.FieldList{fn.Type.Params, fn.Type.Results} {
		if fl == nil {
			continue
		}
		for _, fld := range fl.List {
			for _, id := range fld.Names {
				if id.Name != "" && id.Name != "_" {
					scope[id.Name] = true
				}
			}
		}
	}
	allowedFreeIdents := map[string]bool{
		"nil": true, "true": true, "false": true,
		"string": true, "bool": true, "int": true, "error": true,
		"len": true, "new": true, "append": true, "make": true, "copy": true, "clear": true,
		"BuildInfo": true, "Module": true, "BuildSetting": true,
		"quoteKey": true, "quoteValue": true,
	}
	for cName := range kernel.FalseConsts {
		allowedFreeIdents[cName] = true
	}
	for cName := range kernel.TrueConsts {
		allowedFreeIdents[cName] = true
	}

	WalkLexicalASTSkippingIdents(fn.Body, scope, structLitKeys,
		func(ident string) {
			if astErr == nil && !allowedFreeIdents[ident] {
				astErr = fmt.Errorf("runtime/debug: unapproved free identifier %q in %s", ident, name)
			}
		},
		nil,
		func(base, sel string) {
			if astErr != nil {
				return
			}
			switch base {
			case "strings":
				if !allowedRuntimeDebugStringsSels[sel] {
					astErr = fmt.Errorf("runtime/debug: unapproved strings.%s in %s", sel, name)
				}
			case "strconv":
				if !allowedRuntimeDebugStrconvSels[sel] {
					astErr = fmt.Errorf("runtime/debug: unapproved strconv.%s in %s", sel, name)
				}
			case "fmt":
				if sel != "Errorf" && sel != "Fprintf" {
					astErr = fmt.Errorf("runtime/debug: unapproved fmt.%s in %s", sel, name)
				}
			default:
				astErr = fmt.Errorf("runtime/debug: unapproved qualified reference %s.%s in %s", base, sel, name)
			}
		},
	)
	return astErr
}

func collectLocalStringsBuilderVars(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	disqualified := map[string]bool{}
	if fn == nil || fn.Body == nil {
		return out
	}
	if rName := recvVarName(fn); rName != "" {
		disqualified[rName] = true
	}
	for _, fl := range []*ast.FieldList{fn.Type.Params, fn.Type.Results} {
		if fl == nil {
			continue
		}
		for _, fld := range fl.List {
			for _, id := range fld.Names {
				if id.Name != "" && id.Name != "_" {
					disqualified[id.Name] = true
				}
			}
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ValueSpec:
			for _, id := range x.Names {
				disqualified[id.Name] = true
			}
		case *ast.RangeStmt:
			for _, e := range []ast.Expr{x.Key, x.Value} {
				if id, okID := unwrapParens(e).(*ast.Ident); okID {
					disqualified[id.Name] = true
				}
			}
		case *ast.IncDecStmt:
			if id, okID := unwrapParens(x.X).(*ast.Ident); okID {
				disqualified[id.Name] = true
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				if id, okID := unwrapParens(x.X).(*ast.Ident); okID {
					disqualified[id.Name] = true
				}
			}
		case *ast.AssignStmt:
			if x.Tok == token.DEFINE && len(x.Lhs) == 1 && len(x.Rhs) == 1 {
				if id, okID := unwrapParens(x.Lhs[0]).(*ast.Ident); okID && id.Name != "" && id.Name != "_" {
					if isNewStringsBuilderExpr(x.Rhs[0]) {
						if out[id.Name] {
							disqualified[id.Name] = true
						}
						out[id.Name] = true
						return true
					}
				}
			}
			for _, lhs := range x.Lhs {
				if id, okID := unwrapParens(lhs).(*ast.Ident); okID {
					disqualified[id.Name] = true
				}
			}
		}
		return true
	})
	for k := range disqualified {
		delete(out, k)
	}
	return out
}

func isNewStringsBuilderExpr(expr ast.Expr) bool {
	call, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 1 {
		return false
	}
	if _, okNew := isIdentNamed(call.Fun, "new"); !okNew {
		return false
	}
	_, okSB := isSelectorBaseField(call.Args[0], "strings", "Builder")
	return okSB
}

// VerifyRuntimeModinfoAST verifies that package runtime defines an unexported,
// write-free `var modinfo string` (except for the linker 1-byte sentinel clear
// `if len(modinfo) == 1 { modinfo = "" }`) and exposes it to
// `runtime/debug.modinfo` via `debug_modinfo` with no non-Go symbol mutations.
func VerifyRuntimeModinfoAST(runtimeFiles []*ast.File, runtimeGoSrcs []string, nonGoIdents map[string]bool) error {
	if len(runtimeFiles) == 0 || len(runtimeFiles) != len(runtimeGoSrcs) {
		return fmt.Errorf("runtime: invalid file/source slices for modinfo audit")
	}
	if nonGoIdents["modinfo"] || nonGoIdents["debug_modinfo"] {
		return fmt.Errorf("runtime: forbidden non-Go symbol reference to modinfo")
	}
	sawPush := false
	for _, src := range runtimeGoSrcs {
		err := scanGoDirectiveComments(src, func(line string) error {
			if !strings.HasPrefix(line, "//go:linkname") {
				return nil
			}
			_, plain := auditset.BoundedToken(line, "//go:linkname", " \t")
			_, std := auditset.BoundedToken(line, "//go:linknamestd", " \t")
			fields := strings.Fields(line)
			if (!plain && !std) || (len(fields) != 2 && len(fields) != 3) {
				return fmt.Errorf("runtime: malformed linkname %q", line)
			}
			if len(fields) == 3 && fields[2] == "runtime/debug.modinfo" {
				if fields[1] != "debug_modinfo" {
					return fmt.Errorf("runtime: unexpected symbol %q linked to runtime/debug.modinfo", fields[1])
				}
				sawPush = true
			} else if fields[1] == "modinfo" || (len(fields) == 3 && fields[2] == "runtime.modinfo") {
				return fmt.Errorf("runtime: forbidden external linkname on runtime.modinfo: %q", line)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	if !sawPush {
		return fmt.Errorf("runtime: missing //go:linkname debug_modinfo runtime/debug.modinfo")
	}

	var modinfoDeclIdent *ast.Ident
	modinfoVarDecls := 0
	debugModinfoDecls := 0
	var debugModinfoFn *ast.FuncDecl

	for _, f := range runtimeFiles {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok {
						for _, id := range vs.Names {
							if id.Name == "modinfo" {
								modinfoVarDecls++
								if d.Tok == token.VAR && len(vs.Values) == 0 && len(vs.Names) == 1 {
									if _, isStr := isIdentNamed(vs.Type, "string"); isStr {
										modinfoDeclIdent = id
									}
								}
							}
							if id.Name == "debug_modinfo" {
								debugModinfoDecls++
							}
						}
					} else if ts, ok := spec.(*ast.TypeSpec); ok && ts.Name != nil {
						if ts.Name.Name == "modinfo" {
							modinfoVarDecls++
						}
						if ts.Name.Name == "debug_modinfo" {
							debugModinfoDecls++
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name != nil {
					if d.Name.Name == "modinfo" {
						modinfoVarDecls++
					}
					if d.Name.Name == "debug_modinfo" {
						debugModinfoDecls++
						debugModinfoFn = d
					}
				}
			}
		}
	}
	if modinfoVarDecls != 1 || modinfoDeclIdent == nil {
		return fmt.Errorf("runtime: expected unique `var modinfo string`")
	}
	if debugModinfoDecls != 1 || debugModinfoFn == nil || debugModinfoFn.Body == nil || len(debugModinfoFn.Body.List) != 1 ||
		debugModinfoFn.Type == nil || debugModinfoFn.Type.TypeParams != nil ||
		(debugModinfoFn.Type.Params != nil && debugModinfoFn.Type.Params.NumFields() != 0) ||
		!funcHasUnnamedResults(debugModinfoFn.Type, 1) {
		return fmt.Errorf("runtime: invalid debug_modinfo declaration")
	}
	if _, isStr := isIdentNamed(debugModinfoFn.Type.Results.List[0].Type, "string"); !isStr {
		return fmt.Errorf("runtime: debug_modinfo must return string")
	}
	ret, okRet := debugModinfoFn.Body.List[0].(*ast.ReturnStmt)
	if !okRet || len(ret.Results) != 1 {
		return fmt.Errorf("runtime: debug_modinfo must be `return modinfo`")
	}
	if _, okID := isIdentNamed(ret.Results[0], "modinfo"); !okID {
		return fmt.Errorf("runtime: debug_modinfo must return modinfo")
	}

	// Verify modinfo is never mutated or addressed outside an unshadowed
	// `if len(modinfo) == 1 { modinfo = "" }` or `if modinfo == "" { modinfo = "" }` sentinel guard.
	for _, f := range runtimeFiles {
		var mutErr error
		var walkModinfo func(n, parent ast.Node, enclFn *ast.FuncDecl, inAsync bool)
		walkModinfo = func(n, parent ast.Node, enclFn *ast.FuncDecl, inAsync bool) {
			if mutErr != nil || n == nil {
				return
			}
			switch x := n.(type) {
			case *ast.FuncDecl:
				enclFn = x
			case *ast.FuncLit, *ast.GoStmt:
				inAsync = true
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					if _, okID := isIdentNamed(x.X, "modinfo"); okID {
						mutErr = fmt.Errorf("runtime: forbidden &modinfo")
						return
					}
				}
			case *ast.IncDecStmt:
				if _, okID := isIdentNamed(x.X, "modinfo"); okID {
					mutErr = fmt.Errorf("runtime: forbidden modinfo++")
					return
				}
			case *ast.AssignStmt:
				for i, lhs := range x.Lhs {
					if _, okID := isIdentNamed(lhs, "modinfo"); okID {
						if x.Tok == token.DEFINE {
							continue
						}
						if !inAsync && enclFn != nil && !funcShadowsAnyIdent(enclFn, map[string]bool{"modinfo": true, "len": true, "false": true}) &&
							x.Tok == token.ASSIGN && len(x.Lhs) == 1 && len(x.Rhs) == 1 {
							if lit, okL := unwrapParens(x.Rhs[i]).(*ast.BasicLit); okL && lit.Kind == token.STRING && lit.Value == `""` {
								if blk, okB := parent.(*ast.BlockStmt); okB && len(blk.List) == 1 && blk.List[0] == x && isSafeRuntimeModinfoEmptyGuard(f, blk, x) {
									continue
								}
							}
						}
						mutErr = fmt.Errorf("runtime: unapproved assignment to modinfo")
						return
					}
				}
			}
			ast.Inspect(n, func(ch ast.Node) bool {
				if ch == n {
					return true
				}
				walkModinfo(ch, n, enclFn, inAsync)
				return false
			})
		}
		walkModinfo(f, nil, nil, false)
		if mutErr != nil {
			return mutErr
		}
	}
	return nil
}

func isSafeRuntimeModinfoEmptyGuard(f *ast.File, bodyBlk *ast.BlockStmt, assign *ast.AssignStmt) bool {
	_, ancestors := findEnclosingFuncAndAncestors(f, assign)
	if len(ancestors) < 3 {
		return false
	}
	ifs, okIf := ancestors[len(ancestors)-3].(*ast.IfStmt)
	if !okIf || ifs.Body != bodyBlk || ifs.Init != nil || ifs.Else != nil {
		return false
	}
	if _, isFalse := isIdentNamed(ifs.Cond, "false"); isFalse {
		return true
	}
	bin, okB := unwrapParens(ifs.Cond).(*ast.BinaryExpr)
	if !okB || bin.Op != token.EQL {
		return false
	}
	checkLenOne := func(a, b ast.Expr) bool {
		lit, okL := unwrapParens(b).(*ast.BasicLit)
		if !okL || lit.Kind != token.INT || lit.Value != "1" {
			return false
		}
		lc, okC := unwrapParens(a).(*ast.CallExpr)
		if !okC || lc.Ellipsis.IsValid() || len(lc.Args) != 1 {
			return false
		}
		_, okLen := isIdentNamed(lc.Fun, "len")
		_, okMod := isIdentNamed(lc.Args[0], "modinfo")
		return okLen && okMod
	}
	checkEmpty := func(a, b ast.Expr) bool {
		_, okMod := isIdentNamed(a, "modinfo")
		lit, okL := unwrapParens(b).(*ast.BasicLit)
		return okMod && okL && lit.Kind == token.STRING && lit.Value == `""`
	}
	return checkLenOne(bin.X, bin.Y) || checkLenOne(bin.Y, bin.X) || checkEmpty(bin.X, bin.Y) || checkEmpty(bin.Y, bin.X)
}
