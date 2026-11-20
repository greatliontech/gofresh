package closure

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
)

// importAlias is one import declaration's resolved alias and path, shared
// by the preferred-reason derivation and the effect collection so the scan
// unquotes each import once.
type importAlias struct {
	alias   string
	pkgPath string
}

// maximalFileEffects is the per-file external-effect scan: a pure function
// of the file's bytes. One read and one parse serve both the effect
// collection and the preferred-reason derivation
// (equivalence-pinned by TestFileEffectScanMatchesTwoPassReference).
func maximalFileEffects(audited bool, filename string) (maximalEffectScan, error) {
	fb, err := readBytes(filename)
	if err != nil {
		return maximalEffectScan{}, err
	}
	return maximalFileEffectsContent(audited, filename, fb.content)
}

// maximalFileEffectsContent is the scan over bytes already read.
func maximalFileEffectsContent(audited bool, filename string, content []byte) (maximalEffectScan, error) {
	return maximalFileEffectsContentWithNames(audited, filename, content, nil)
}

// maximalFileEffectsContentWithNames scans file bytes using declaredNames
// (when supplied by the package listing) to bind unnamed imports to their
// actual declared package names before falling back to path derivation.
func maximalFileEffectsContentWithNames(audited bool, filename string, content []byte, declaredNames map[string]string) (maximalEffectScan, error) {
	return maximalFileEffectsContentWithNamesFiltered(audited, filename, content, declaredNames, nil)
}

func maximalFileEffectsContentWithNamesFiltered(audited bool, filename string, content []byte, declaredNames map[string]string, reachedDecls map[funcDeclKey]bool) (maximalEffectScan, error) {
	return maximalFileEffectsContentWithContextFiltered(audited, filename, content, declaredNames, nil, reachedDecls)
}

func maximalFileEffectsContentWithContextFiltered(audited bool, filename string, content []byte, declaredNames map[string]string, nonStdPaths map[string]bool, reachedDecls map[funcDeclKey]bool) (maximalEffectScan, error) {
	return maximalFileEffectsContentWithZeroGlobals(audited, filename, content, declaredNames, nonStdPaths, reachedDecls, nil, "", nil, nil, nil, nil)
}

type parsedMaximalFile struct {
	filename      string
	dir           string
	pkgClause     string
	text          string
	hasWasmImport bool
	file          *ast.File
	imports       []importAlias
	aliases       map[string]string
	stdAliases    map[string]string
	collisions    []string
	importNames   map[string]bool
	testMainDecl  *ast.FuncDecl
	handleTypes   map[string]bool
	localNames    map[*ast.FuncDecl]map[string]bool
}

func parseMaximalFile(filename string, content []byte, declaredNames map[string]string, nonStdPaths map[string]bool) (*parsedMaximalFile, error) {
	text := string(content)
	hasWasmImport := strings.Contains(text, "//go:wasmimport")
	// The walks read identifiers by name and imports from file.Imports;
	// object resolution is unused, so skipping it saves its allocations.
	file, err := parser.ParseFile(token.NewFileSet(), filename, content, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("closure: parse %s: %w", filename, err)
	}
	imports := make([]importAlias, 0, len(file.Imports))
	aliases := make(map[string]string, len(file.Imports))
	var collisions []string
	// Three tiers bind an identifier at this syntactic tier, a lower
	// never displacing a higher: an explicit alias is ground truth; an
	// unnamed import's declared package name from the listing (when
	// known) or last path element is the primary; a trailing
	// major-version element without a known declared name additionally
	// derives the element before it as a secondary, bound only where
	// unclaimed and unique. A clash within a tier is what the language
	// forbids and refuses the file fail-closed, except two derived
	// version-element primaries, whose identifiers live on their
	// secondaries (REQ-closure-observability-declaration-bindings).
	secondaries := map[string][]string{}
	versioned := map[string]bool{}
	explicit := map[string]bool{}
	for _, spec := range file.Imports {
		pkgPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return nil, fmt.Errorf("closure: parse import in %s: %w", filename, err)
		}
		alias := path.Base(pkgPath)
		if spec.Name != nil {
			alias = spec.Name.Name
			if prior, taken := aliases[alias]; taken && explicit[alias] && prior != pkgPath && alias != "_" && alias != "." {
				collisions = append(collisions, "import name collision at the file scan: "+prior+" and "+pkgPath+" both bind "+alias)
			}
			explicit[alias] = true
			aliases[alias] = pkgPath
			imports = append(imports, importAlias{alias: alias, pkgPath: pkgPath})
			continue
		}
		if declared := declaredNames[pkgPath]; declared != "" {
			alias = declared
		} else if derived := implicitImportName(pkgPath); derived != alias {
			secondaries[derived] = append(secondaries[derived], pkgPath)
			versioned[pkgPath] = true
		}
		imports = append(imports, importAlias{alias: alias, pkgPath: pkgPath})
		if explicit[alias] {
			continue
		}
		if prior, taken := aliases[alias]; taken && prior != pkgPath && alias != "_" && alias != "." && !(versioned[prior] && versioned[pkgPath]) {
			collisions = append(collisions, "import name collision at the file scan: "+prior+" and "+pkgPath+" both bind "+alias)
		}
		aliases[alias] = pkgPath
	}
	for name, paths := range secondaries {
		if _, claimed := aliases[name]; !claimed && len(paths) == 1 {
			aliases[name] = paths[0]
		}
	}
	stdAliases := aliases
	if len(nonStdPaths) > 0 {
		stdAliases = make(map[string]string, len(aliases))
		for alias, pkgPath := range aliases {
			if !(isStdImportPath(pkgPath) && nonStdPaths[pkgPath]) {
				stdAliases[alias] = pkgPath
			}
		}
	}
	pkgClause := ""
	if file.Name != nil {
		pkgClause = file.Name.Name
	}
	return &parsedMaximalFile{
		filename:      filename,
		dir:           filepath.Clean(filepath.Dir(filename)),
		pkgClause:     pkgClause,
		text:          text,
		hasWasmImport: hasWasmImport,
		file:          file,
		imports:       imports,
		aliases:       aliases,
		stdAliases:    stdAliases,
		collisions:    collisions,
		importNames:   fileImportNames(file, declaredNames),
		testMainDecl:  userTestMainDecl(file, stdAliases),
		handleTypes:   testingHandleTypeNames(file, stdAliases),
	}, nil
}

func (p *parsedMaximalFile) funcLocals(fn *ast.FuncDecl) map[string]bool {
	if fn == nil {
		return nil
	}
	if p.localNames != nil {
		if names, ok := p.localNames[fn]; ok {
			return names
		}
	}
	names := funcLocalDeclaredNames(fn)
	if p.localNames == nil {
		p.localNames = make(map[*ast.FuncDecl]map[string]bool)
	}
	p.localNames[fn] = names
	return names
}

func (h *Hasher) parsedMaximalFile(filename string, content []byte, declaredNames map[string]string, nonStdPaths map[string]bool, overridesKey string) (*parsedMaximalFile, error) {
	cacheKey := filename + overridesKey
	if h != nil && h.maximalParsedFiles != nil {
		if parsed, ok := h.maximalParsedFiles[cacheKey]; ok {
			return parsed, nil
		}
	}
	parsed, err := parseMaximalFile(filename, content, declaredNames, nonStdPaths)
	if err != nil {
		return nil, err
	}
	if h != nil && h.maximalParsedFiles != nil {
		h.maximalParsedFiles[cacheKey] = parsed
	}
	return parsed, nil
}

func maximalFileEffectsContentWithZeroGlobals(audited bool, filename string, content []byte, declaredNames map[string]string, nonStdPaths map[string]bool, reachedDecls, startupOnlyDecls map[funcDeclKey]bool, filePkgPath string, startupZeroGlobalDecls, wholeZeroGlobalDecls map[pkgVarKey]bool, pkgScopeShadowed, verifiedLinknameLocals map[string]bool) (maximalEffectScan, error) {
	parsed, err := parseMaximalFile(filename, content, declaredNames, nonStdPaths)
	if err != nil {
		return maximalEffectScan{}, err
	}
	return maximalFileEffectsParsed(audited, parsed, nonStdPaths, reachedDecls, startupOnlyDecls, filePkgPath, startupZeroGlobalDecls, wholeZeroGlobalDecls, pkgScopeShadowed, verifiedLinknameLocals, false, false), nil
}

func maximalFileEffectsParsed(audited bool, parsed *parsedMaximalFile, nonStdPaths map[string]bool, reachedDecls, startupOnlyDecls map[funcDeclKey]bool, filePkgPath string, startupZeroGlobalDecls, wholeZeroGlobalDecls map[pkgVarKey]bool, pkgScopeShadowed, verifiedLinknameLocals map[string]bool, pkgConfinedUnsafe, trackedChdirSafe bool) maximalEffectScan {
	file := parsed.file
	text := parsed.text
	hasWasmImport := parsed.hasWasmImport
	hasLinkname := hasRawGoLinkname(text) && !auditedLinknamesWithLocals(audited, text, verifiedLinknameLocals)
	var scan maximalEffectScan
	// The preferred diagnostic derives from the same single walk's
	// effect set under the shared cause-preference order
	// (preferredEffectReason); the potential-external import fallback
	// names a dependence only for an effect-less file
	// (REQ-closure-observability-cause-order).
	potentialExternal := ""
	if hasWasmImport {
		effect := opaqueExternalEffect(externalEffectLinkage, "reaches go:wasmimport")
		effect.unrefinable = true
		scan.add(effect)
	}
	if hasLinkname {
		scan.add(opaqueExternalEffect(externalEffectLinkage, "reaches go:linkname (opaque linkage)"))
	}
	for _, collision := range parsed.collisions {
		scan.add(opaqueExternalEffect(externalEffectUnauditedStandard, collision))
	}
	for _, imp := range parsed.imports {
		if isStdImportPath(imp.pkgPath) && nonStdPaths[imp.pkgPath] {
			continue
		}
		if imp.pkgPath == "testing" {
			if imp.alias == "." {
				scan.add(opaqueExternalEffect(externalEffectUnauditedStandard, "reaches testing (potential external dependence)"))
				potentialExternal = imp.pkgPath
			}
			continue
		}
		if auditset.AlwaysExternalPackage(imp.pkgPath) && imp.alias != "." && imp.alias != "_" {
			// A plain always-external import is a diagnostic candidate
			// only: the dot and blank spellings record the effect
			// itself below.
			scan.importCandidates = appendExternalEffect(scan.importCandidates, trueExternalEffect(imp.pkgPath))
		}
		if imp.alias == "." && packageHasClassifiedExternalAPI(imp.pkgPath) && potentialExternal == "" {
			potentialExternal = imp.pkgPath
		}
		if potentialExternal == "" && !(imp.alias == "_" && imp.pkgPath == "unsafe") && isStdImportPath(imp.pkgPath) && !isSourceOnlyStandardPackage(audited, imp.pkgPath) {
			potentialExternal = imp.pkgPath
		}
		// Blank-importing the compiler pseudo-package "unsafe" (required for
		// //go:linkname directives, which are classified independently above)
		// executes no package init and introduces no unqualified identifiers;
		// dot-importing "unsafe" remains blocked.
		if imp.alias == "." || (imp.alias == "_" && imp.pkgPath != "unsafe") {
			if auditset.AlwaysExternalPackage(imp.pkgPath) {
				scan.add(trueExternalEffect(imp.pkgPath))
			} else if packageHasClassifiedExternalAPI(imp.pkgPath) || isStdImportPath(imp.pkgPath) && !isSourceOnlyStandardPackage(audited, imp.pkgPath) {
				scan.add(opaqueExternalEffect(externalEffectUnauditedStandard, "reaches "+imp.pkgPath+" (potential external dependence)"))
			}
		}
	}
	stdAliases := parsed.stdAliases
	// The canonical test-main epilogue is harness protocol, not an
	// unaudited operation: os.Exit inside the user TestMain(*testing.M)
	// declaration is admitted exactly as the observed test-main walk
	// admits it - it runs post-bracket and adds no input channel to any
	// subject's execution (REQ-closure-observability-testmain-exit).
	testMainDecl := parsed.testMainDecl
	inTestMain := func(node ast.Node) bool {
		return testMainDecl != nil && node.Pos() >= testMainDecl.Pos() && node.End() <= testMainDecl.End()
	}
	unreachedDecls := unreachedASTDecls(parsed.dir, parsed.pkgClause, file, testMainDecl, reachedDecls)
	inUnreachedDecl := func(node ast.Node) bool {
		for _, d := range unreachedDecls {
			if node.Pos() >= d.Pos() && node.End() <= d.End() {
				return true
			}
		}
		return false
	}
	deadInBinaryBody, deadForSubjectBody := deadZeroGlobalIfBodiesParsed(parsed, filePkgPath, startupOnlyDecls, startupZeroGlobalDecls, wholeZeroGlobalDecls, pkgScopeShadowed)
	inDeadForSubjectBody := func(node ast.Node) bool {
		for blk := range deadForSubjectBody {
			if node.Pos() >= blk.Pos() && node.End() <= blk.End() {
				return true
			}
		}
		return false
	}
	addSelEffect := func(sel *ast.SelectorExpr, effect externalEffect) {
		if (inUnreachedDecl(sel) || inDeadForSubjectBody(sel)) && !packageWideMaximalHazardForPkg(audited, effect, pkgConfinedUnsafe, trackedChdirSafe) {
			return
		}
		scan.add(effect)
	}
	allowedTimeUnixChained := map[*ast.SelectorExpr]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		if blk, ok := node.(*ast.BlockStmt); ok && deadInBinaryBody[blk] {
			return false
		}
		if audited {
			if outerCall, ok := node.(*ast.CallExpr); ok {
				if innerSel := chainedTimeUnixSelector(outerCall, stdAliases, reachedDecls != nil); innerSel != nil {
					allowedTimeUnixChained[innerSel] = true
				}
			}
		}
		if sel, ok := node.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				pkgPath := stdAliases[ident.Name]
				if pkgPath == "" {
					return true
				}
				if allowedTimeUnixChained[sel] {
					return true
				}
				if effect, ok := classBEffect(pkgPath, sel.Sel.Name); ok {
					addSelEffect(sel, effect)
				} else if pkgPath == "os" && sel.Sel.Name == "Exit" && inTestMain(sel) {
					// admitted test-main epilogue
				} else if isCompileTimeUnsafeIntrinsic(pkgPath, sel.Sel.Name) {
					// Go language compile-time layout intrinsics (unsafe.Alignof,
					// unsafe.Offsetof, unsafe.Sizeof) evaluate strictly to compile-time
					// uintptr constants determined by (MaximalClosure, Toolchain,
					// BuildConfig) without executing runtime code or dereferencing
					// runtime memory; operand syntax continues to be walked below
					// (REQ-closure-observability-unsafe).
				} else if flagRegistrationSymbol(pkgPath, sel.Sel.Name) {
					// flag registration is a process-local registry
					// mutation; the name-based admission is sound
					// because the registration-facts sink judgment
					// guards every call site program-wide - traced
					// storage refuses on reference, an untraceable
					// sink poisons the package
					// (REQ-closure-observability-flag-registration).
				} else if !admittedPureStandardOrDelegateSymbol(audited, nil, pkgPath, sel.Sel.Name) && (auditset.AlwaysExternalPackage(pkgPath) || isStdImportPath(pkgPath) && !isStandardFallbackExempt(audited, pkgPath)) {
					addSelEffect(sel, unauditedStandardEffect(pkgPath, sel.Sel.Name))
				}
			}
		}
		return true
	})
	var testingSkipped map[*ast.BlockStmt]bool
	if len(deadInBinaryBody) > 0 || len(deadForSubjectBody) > 0 {
		testingSkipped = make(map[*ast.BlockStmt]bool, len(deadInBinaryBody)+len(deadForSubjectBody))
		for blk := range deadInBinaryBody {
			testingSkipped[blk] = true
		}
		for blk := range deadForSubjectBody {
			testingSkipped[blk] = true
		}
	}
	for _, effect := range testingMethodEffectsFilteredWithHandles(audited, trackedChdirSafe, file, stdAliases, parsed.handleTypes, unreachedDecls, testingSkipped) {
		scan.add(effect)
	}
	scan.preferred = preferredEffectReason(append(append([]externalEffect(nil), scan.effects...), scan.importCandidates...))
	if scan.preferred == "" && potentialExternal != "" {
		scan.preferred = "reaches " + potentialExternal + " (potential external dependence)"
	}
	return scan
}

func isCompileTimeUnsafeIntrinsic(pkgPath, name string) bool {
	return pkgPath == "unsafe" && refconfine.IsCompileTimeUnsafeBuiltinName(name)
}

func hasPkgZeroGlobals(zeroGlobalDecls map[pkgVarKey]bool, pkgPath string) bool {
	if len(zeroGlobalDecls) == 0 || pkgPath == "" {
		return false
	}
	for k := range zeroGlobalDecls {
		if k.pkgPath == pkgPath {
			return true
		}
	}
	return false
}

func deadZeroGlobalIfBodiesParsed(parsed *parsedMaximalFile, pkgPath string, startupOnlyDecls map[funcDeclKey]bool, startupZeroGlobalDecls, wholeZeroGlobalDecls map[pkgVarKey]bool, pkgScopeShadowed map[string]bool) (deadInBinary, deadForSubject map[*ast.BlockStmt]bool) {
	hasStartup := hasPkgZeroGlobals(startupZeroGlobalDecls, pkgPath)
	hasWhole := hasPkgZeroGlobals(wholeZeroGlobalDecls, pkgPath)
	if parsed == nil || parsed.file == nil || pkgPath == "" || (!hasStartup && !hasWhole) {
		return nil, nil
	}
	for _, decl := range parsed.file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn == parsed.testMainDecl || (fn.Name != nil && fn.Name.Name == "TestMain") {
			continue
		}
		isInitDecl := fn.Recv == nil && fn.Name != nil && fn.Name.Name == "init"
		isStartupOnlyDecl := false
		if isInitDecl {
			isStartupOnlyDecl = hasStartup
		} else if key, ok := funcDeclKeyForAST(parsed.dir, parsed.pkgClause, fn); ok && startupOnlyDecls[key] {
			isStartupOnlyDecl = true
		}
		if !hasWhole && !isStartupOnlyDecl {
			continue
		}
		shadowed := mergeShadowedNames(pkgScopeShadowed, parsed.importNames, parsed.funcLocals(fn))
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if _, isFuncLit := n.(*ast.FuncLit); isFuncLit {
				return false
			}
			ifStmt, ok := n.(*ast.IfStmt)
			if !ok || ifStmt.Init != nil || ifStmt.Body == nil {
				return true
			}
			if (hasWhole && ifCondRequiresNonZeroGlobal(ifStmt.Cond, pkgPath, shadowed, wholeZeroGlobalDecls)) ||
				(isInitDecl && isStartupOnlyDecl && hasStartup && ifCondRequiresNonZeroGlobal(ifStmt.Cond, pkgPath, shadowed, startupZeroGlobalDecls)) {
				if deadInBinary == nil {
					deadInBinary = make(map[*ast.BlockStmt]bool)
				}
				deadInBinary[ifStmt.Body] = true
			} else if isStartupOnlyDecl && hasStartup && ifCondRequiresNonZeroGlobal(ifStmt.Cond, pkgPath, shadowed, startupZeroGlobalDecls) {
				if deadForSubject == nil {
					deadForSubject = make(map[*ast.BlockStmt]bool)
				}
				deadForSubject[ifStmt.Body] = true
			}
			return true
		})
	}
	return deadInBinary, deadForSubject
}

func fileImportNames(file *ast.File, declaredNames map[string]string) map[string]bool {
	if file == nil || len(file.Imports) == 0 {
		return nil
	}
	var out map[string]bool
	for _, spec := range file.Imports {
		if spec == nil {
			continue
		}
		name := ""
		if spec.Name != nil {
			name = spec.Name.Name
		} else if spec.Path != nil {
			if pkgPath, err := strconv.Unquote(spec.Path.Value); err == nil {
				if declared := declaredNames[pkgPath]; declared != "" {
					name = declared
				} else {
					name = implicitImportName(pkgPath)
				}
			}
		}
		if name != "" && name != "_" && name != "." {
			if out == nil {
				out = make(map[string]bool, len(file.Imports))
			}
			out[name] = true
		}
	}
	return out
}

func mergeShadowedNames(maps ...map[string]bool) map[string]bool {
	total := 0
	for _, m := range maps {
		total += len(m)
	}
	if total == 0 {
		return nil
	}
	out := make(map[string]bool, total)
	for _, m := range maps {
		for k, v := range m {
			if v {
				out[k] = true
			}
		}
	}
	return out
}

func funcLocalDeclaredNames(fn *ast.FuncDecl) map[string]bool {
	var names map[string]bool
	add := func(ident *ast.Ident) {
		if ident == nil || ident.Name == "" || ident.Name == "_" {
			return
		}
		if names == nil {
			names = make(map[string]bool)
		}
		names[ident.Name] = true
	}
	addFieldList := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, id := range f.Names {
				add(id)
			}
		}
	}
	addFieldList(fn.Recv)
	if fn.Type != nil {
		addFieldList(fn.Type.TypeParams)
		addFieldList(fn.Type.Params)
		addFieldList(fn.Type.Results)
	}
	if fn.Body != nil {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.ValueSpec:
				for _, id := range x.Names {
					add(id)
				}
			case *ast.TypeSpec:
				add(x.Name)
			case *ast.AssignStmt:
				if x.Tok == token.DEFINE {
					for _, lhs := range x.Lhs {
						if id, ok := lhs.(*ast.Ident); ok {
							add(id)
						}
					}
				}
			case *ast.RangeStmt:
				if x.Tok == token.DEFINE {
					if id, ok := x.Key.(*ast.Ident); ok {
						add(id)
					}
					if id, ok := x.Value.(*ast.Ident); ok {
						add(id)
					}
				}
			case *ast.FuncLit:
				if x.Type != nil {
					addFieldList(x.Type.TypeParams)
					addFieldList(x.Type.Params)
					addFieldList(x.Type.Results)
				}
			}
			return true
		})
	}
	return names
}

func ifCondRequiresNonZeroGlobal(expr ast.Expr, pkgPath string, shadowed map[string]bool, zeroGlobalDecls map[pkgVarKey]bool) bool {
	if expr == nil || pkgPath == "" || len(zeroGlobalDecls) == 0 {
		return false
	}
	return ifCondRequiresNonZeroGlobalWith(
		expr,
		func(id *ast.Ident) bool {
			return id != nil && (id.Name == "nil" || id.Name == "false") && !shadowed[id.Name]
		},
		func(id *ast.Ident) bool {
			if id == nil || id.Name == "" || shadowed[id.Name] {
				return false
			}
			return zeroGlobalDecls[pkgVarKey{pkgPath: pkgPath, name: id.Name}]
		},
	)
}

func ifCondRequiresNonZeroGlobalTyped(expr ast.Expr, info *types.Info, zeroGlobalDecls map[pkgVarKey]bool) bool {
	if expr == nil || info == nil || len(zeroGlobalDecls) == 0 {
		return false
	}
	return ifCondRequiresNonZeroGlobalWith(
		expr,
		func(id *ast.Ident) bool {
			if id == nil || (id.Name != "nil" && id.Name != "false") {
				return false
			}
			u := types.Universe.Lookup(id.Name)
			return u != nil && info.Uses[id] == u
		},
		func(id *ast.Ident) bool {
			if id == nil || id.Name == "" {
				return false
			}
			v, ok := info.Uses[id].(*types.Var)
			if !ok || v == nil || v.IsField() || v.Pkg() == nil || v.Parent() != v.Pkg().Scope() {
				return false
			}
			return zeroGlobalDecls[pkgVarKey{pkgPath: v.Pkg().Path(), name: v.Name()}]
		},
	)
}

func ifCondRequiresNonZeroGlobalWith(expr ast.Expr, isUniverseZeroIdent, isZeroGlobalIdent func(*ast.Ident) bool) bool {
	isZeroIdentExpr := func(e ast.Expr) bool {
		id, ok := ast.Unparen(e).(*ast.Ident)
		return ok && isZeroGlobalIdent(id)
	}
	isZeroLiteralExpr := func(e ast.Expr) bool {
		switch x := ast.Unparen(e).(type) {
		case *ast.Ident:
			return isUniverseZeroIdent != nil && isUniverseZeroIdent(x)
		case *ast.BasicLit:
			switch x.Kind {
			case token.INT, token.FLOAT, token.IMAG:
				v, err := strconv.ParseFloat(x.Value, 64)
				return err == nil && v == 0
			case token.STRING:
				s, err := strconv.Unquote(x.Value)
				return err == nil && s == ""
			}
		}
		return false
	}
	switch x := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return isZeroIdentExpr(x)
	case *ast.StarExpr:
		return isZeroIdentExpr(x.X)
	case *ast.BinaryExpr:
		switch x.Op {
		case token.LAND:
			return ifCondRequiresNonZeroGlobalWith(x.X, isUniverseZeroIdent, isZeroGlobalIdent) ||
				ifCondRequiresNonZeroGlobalWith(x.Y, isUniverseZeroIdent, isZeroGlobalIdent)
		case token.LOR:
			return ifCondRequiresNonZeroGlobalWith(x.X, isUniverseZeroIdent, isZeroGlobalIdent) &&
				ifCondRequiresNonZeroGlobalWith(x.Y, isUniverseZeroIdent, isZeroGlobalIdent)
		case token.NEQ:
			return (isZeroIdentExpr(x.X) && isZeroLiteralExpr(x.Y)) ||
				(isZeroIdentExpr(x.Y) && isZeroLiteralExpr(x.X))
		}
	}
	return false
}

func isASTTimeFixedZoneCall(expr ast.Expr, aliases map[string]string) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 2 || call.Ellipsis.IsValid() {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "FixedZone" {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && aliases[ident.Name] == "time"
}

func chainedTimeUnixSelector(outerCall *ast.CallExpr, aliases map[string]string, hasSSAFlow bool) *ast.SelectorExpr {
	if outerCall == nil || outerCall.Ellipsis.IsValid() {
		return nil
	}
	outerSel, ok := ast.Unparen(outerCall.Fun).(*ast.SelectorExpr)
	if !ok || outerSel.Sel == nil {
		return nil
	}
	switch outerSel.Sel.Name {
	case "UTC":
		if len(outerCall.Args) != 0 {
			return nil
		}
	case "In":
		if len(outerCall.Args) != 1 || (!hasSSAFlow && !isASTTimeFixedZoneCall(outerCall.Args[0], aliases)) {
			return nil
		}
	default:
		return nil
	}
	innerCall, ok := ast.Unparen(outerSel.X).(*ast.CallExpr)
	if !ok || innerCall.Ellipsis.IsValid() {
		return nil
	}
	innerSel, ok := ast.Unparen(innerCall.Fun).(*ast.SelectorExpr)
	if !ok || innerSel.Sel == nil {
		return nil
	}
	ident, ok := innerSel.X.(*ast.Ident)
	if !ok || aliases[ident.Name] != "time" {
		return nil
	}
	switch innerSel.Sel.Name {
	case "Unix":
		if len(innerCall.Args) != 2 {
			return nil
		}
	case "UnixMilli", "UnixMicro":
		if len(innerCall.Args) != 1 {
			return nil
		}
	default:
		return nil
	}
	return innerSel
}

// testingMethodEffectsFiltered returns the file's testing-runtime effects.
func testingMethodEffectsFiltered(file *ast.File, aliases map[string]string, unreachedDecls []ast.Node) []externalEffect {
	return testingMethodEffectsFilteredWithSkipped(file, aliases, unreachedDecls, nil)
}

func testingMethodEffectsFilteredWithSkipped(file *ast.File, aliases map[string]string, unreachedDecls []ast.Node, skippedBody map[*ast.BlockStmt]bool) []externalEffect {
	if file == nil {
		return nil
	}
	return testingMethodEffectsFilteredWithHandles(false, false, file, aliases, testingHandleTypeNames(file, aliases), unreachedDecls, skippedBody)
}

func testingMethodEffectsFilteredWithHandles(audited, trackedChdirSafe bool, file *ast.File, aliases map[string]string, handleTypes map[string]bool, unreachedDecls []ast.Node, skippedBody map[*ast.BlockStmt]bool) []externalEffect {
	if file == nil {
		return nil
	}
	var effects []externalEffect
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Type.Params == nil || function.Body == nil {
			continue
		}
		receivers := map[string]bool{}
		for _, field := range function.Type.Params.List {
			if isTestingHandleType(field.Type, aliases, handleTypes) {
				for _, name := range field.Names {
					receivers[name.Name] = true
				}
			}
		}
		if len(receivers) == 0 {
			continue
		}
		unreached := slices.Contains(unreachedDecls, ast.Node(function))
		addTestingEffect := func(effect externalEffect) {
			if unreached && !packageWideMaximalHazardForPkg(audited, effect, false, trackedChdirSafe) {
				return
			}
			effects = appendExternalEffect(effects, effect)
		}
		// One body walk collects both the parent map and the name-propagation
		// edges; the fixed point then iterates the small edge list instead of
		// re-walking the whole body per round. The fixed point is
		// order-independent, so the collection order only bounds round count
		// (equivalence-pinned by
		// TestFileEffectScanMatchesTwoPassReference's backward rows).
		type propagation struct{ from, to string }
		var edges []propagation
		parents := make(map[ast.Node]ast.Node)
		var stack []ast.Node
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if node == nil {
				stack = stack[:len(stack)-1]
				return false
			}
			if blk, ok := node.(*ast.BlockStmt); ok && skippedBody[blk] {
				return false
			}
			if len(stack) != 0 {
				parents[node] = stack[len(stack)-1]
			}
			stack = append(stack, node)
			if specification, ok := node.(*ast.ValueSpec); ok {
				for i, value := range specification.Values {
					if name, ok := identifierName(value); ok && i < len(specification.Names) {
						edges = append(edges, propagation{from: name, to: specification.Names[i].Name})
					}
				}
			}
			assignment, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, rhs := range assignment.Rhs {
				name, ok := identifierName(rhs)
				if !ok || i >= len(assignment.Lhs) {
					continue
				}
				if lhs, ok := assignment.Lhs[i].(*ast.Ident); ok {
					edges = append(edges, propagation{from: name, to: lhs.Name})
				}
			}
			return true
		})
		changed := true
		for changed {
			changed = false
			for _, edge := range edges {
				if receivers[edge.from] && !receivers[edge.to] {
					receivers[edge.to] = true
					changed = true
				}
			}
		}
		escape := opaqueExternalEffect(externalEffectTestRuntime, "testing runtime value escapes analyzable receiver")
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if blk, ok := node.(*ast.BlockStmt); ok && skippedBody[blk] {
				return false
			}
			switch node := node.(type) {
			case *ast.AssignStmt:
				for i, rhs := range node.Rhs {
					name, ok := identifierName(rhs)
					if ok && receivers[name] && i < len(node.Lhs) {
						if _, ok := node.Lhs[i].(*ast.Ident); !ok {
							addTestingEffect(escape)
						}
					}
				}
			case *ast.CallExpr:
				for _, argument := range node.Args {
					if name, ok := identifierName(argument); ok && receivers[name] {
						addTestingEffect(escape)
					}
				}
			case *ast.ReturnStmt:
				for _, result := range node.Results {
					if name, ok := identifierName(result); ok && receivers[name] {
						addTestingEffect(escape)
					}
				}
			case *ast.Ident:
				if receivers[node.Name] && !testingIdentifierUseSupported(node, parents) {
					addTestingEffect(escape)
				}
			}
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			receiver, ok := selector.X.(*ast.Ident)
			if !ok || !receivers[receiver.Name] {
				return true
			}
			if effect, ok := classBEffect("testing", selector.Sel.Name); ok {
				addTestingEffect(effect)
			}
			return true
		})
	}
	return effects
}

func testingIdentifierUseSupported(identifier *ast.Ident, parents map[ast.Node]ast.Node) bool {
	var node ast.Node = identifier
	parent := parents[node]
	for {
		parenthesized, ok := parent.(*ast.ParenExpr)
		if !ok || parenthesized.X != node {
			break
		}
		node = parent
		parent = parents[node]
	}
	switch parent := parent.(type) {
	case *ast.Field:
		return true
	case *ast.SelectorExpr:
		return parent.X == node
	case *ast.AssignStmt:
		for i, lhs := range parent.Lhs {
			if lhs == node {
				return true
			}
			if i < len(parent.Rhs) && ast.Unparen(parent.Rhs[i]) == identifier {
				_, ok := lhs.(*ast.Ident)
				return ok
			}
		}
	case *ast.ValueSpec:
		for _, name := range parent.Names {
			if name == identifier {
				return true
			}
		}
		for i, value := range parent.Values {
			if ast.Unparen(value) == identifier {
				return i < len(parent.Names)
			}
		}
	}
	return false
}

func identifierName(expression ast.Expr) (string, bool) {
	expression = ast.Unparen(expression)
	identifier, ok := expression.(*ast.Ident)
	if !ok {
		return "", false
	}
	return identifier.Name, true
}

func testingHandleTypeNames(file *ast.File, aliases map[string]string) map[string]bool {
	handles := map[string]bool{}
	changed := true
	for changed {
		changed = extendTestingHandleTypeNames(file, aliases, handles)
	}
	return handles
}

func extendTestingHandleTypeNames(file *ast.File, aliases map[string]string, handles map[string]bool) bool {
	changed := false
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.TYPE {
			continue
		}
		for _, specification := range general.Specs {
			typeSpec, ok := specification.(*ast.TypeSpec)
			if ok && !handles[typeSpec.Name.Name] && isTestingHandleType(typeSpec.Type, aliases, handles) {
				handles[typeSpec.Name.Name] = true
				changed = true
			}
		}
	}
	return changed
}

func isTestingHandleType(expression ast.Expr, aliases map[string]string, handles map[string]bool) bool {
	switch expression := expression.(type) {
	case *ast.StarExpr:
		return isTestingHandleType(expression.X, aliases, handles)
	case *ast.Ident:
		return handles[expression.Name]
	case *ast.SelectorExpr:
		qualifier, ok := expression.X.(*ast.Ident)
		if !ok || aliases[qualifier.Name] != "testing" {
			return false
		}
		switch expression.Sel.Name {
		case "T", "B", "F", "M":
			return true
		}
	case *ast.StructType:
		for _, field := range expression.Fields.List {
			if isTestingHandleType(field.Type, aliases, handles) {
				return true
			}
		}
	}
	return false
}
