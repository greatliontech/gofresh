package gofresh

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/internal/gotool"
	"golang.org/x/tools/go/packages"
)

// ScanPureDirectives loads pkgPaths and returns a purity predicate marking every
// symbol whose declaration carries a //gofresh:pure directive (REQ-purity-directive).
// It is the durable, in-code form of a purity assertion — written once and honored
// automatically by every consumer of the engine. The returned predicate is for
// inspection; callers use WithAssumePure only for additional caller-owned assertions.
// gofresh never infers purity from behavior (REQ-purity-responsibility).
//
// A symbol is named as the closure engine resolves it: a function by its name, a
// method as "Type.Method" with the receiver's pointer star and generics dropped.
func ScanPureDirectives(pkgPaths ...string) (func(Subject) bool, error) {
	return ScanPureDirectivesInWithBuildFlags("", nil, pkgPaths...)
}

// ScanPureDirectivesIn scans under an explicit tree root ("" = the process
// working directory), for callers fingerprinting a tree they do not run
// inside.
func ScanPureDirectivesIn(dir string, pkgPaths ...string) (func(Subject) bool, error) {
	return ScanPureDirectivesInWithBuildFlags(dir, nil, pkgPaths...)
}

// ScanPureDirectivesWithBuildFlags scans the packages selected by buildFlags under
// the process working directory. The flags must match the producing build, so a
// directive in a mutually exclusive unselected file cannot confer purity on the
// selected declaration (REQ-purity-directive, REQ-guard-buildconfig).
func ScanPureDirectivesWithBuildFlags(buildFlags []string, pkgPaths ...string) (func(Subject) bool, error) {
	return ScanPureDirectivesInWithBuildFlags("", buildFlags, pkgPaths...)
}

// ScanPureDirectivesInWithBuildFlags scans under an explicit tree root and the
// producing build's executable flags.
func ScanPureDirectivesInWithBuildFlags(dir string, buildFlags []string, pkgPaths ...string) (func(Subject) bool, error) {
	scan, err := scanSubjectsInWithBuildFlags(context.Background(), dir, buildFlags, pkgPaths...)
	if err != nil {
		return nil, err
	}
	return scan.directivePure, nil
}

func scanSubjectsInWithBuildFlags(ctx context.Context, dir string, buildFlags []string, pkgPaths ...string) (*subjectScan, error) {
	return scanSubjectsInWithBuildFlagsEnv(ctx, dir, os.Environ(), buildFlags, pkgPaths...)
}

func scanSubjectsInWithBuildFlagsEnv(ctx context.Context, dir string, env, buildFlags []string, pkgPaths ...string) (*subjectScan, error) {
	hasher, err := closure.NewAtContextEnv(ctx, dir, env, buildFlags...)
	if err != nil {
		return nil, err
	}
	scan, _, err := scanViewSubjects(ctx, hasher, "", dir, env, buildFlags, nil, pkgPaths...)
	return scan, err
}

// scanViewSubjects performs one observation pass's whole subject scan: the
// metadata graph names every node and its mutability class, one typed load
// covers the view packages' variants and every mutable-local graph package,
// the dynamic-state derivation serves version-pinned facts from the memo, and
// the subject walk reads that one load (REQ-fresh-coherent-view). The typed
// load is installed on the hasher for the pass's sibling consumers. An empty
// factScope disables fact persistence, never the derivation.
func scanViewSubjects(ctx context.Context, hasher *closure.Hasher, factScope, dir string, env, buildFlags []string, snapshot *gotool.EnvSnapshot, pkgPaths ...string) (*subjectScan, *closure.ViewLoad, error) {
	meta, err := hasher.GraphMetadata(pkgPaths...)
	if err != nil {
		return nil, nil, err
	}
	requested := make(map[string]bool, len(pkgPaths))
	for _, pkgPath := range pkgPaths {
		requested[pkgPath] = true
	}
	patterns := append([]string(nil), pkgPaths...)
	seenPattern := make(map[string]bool, len(pkgPaths))
	for _, pkgPath := range pkgPaths {
		seenPattern[pkgPath] = true
	}
	for _, node := range meta {
		// Plain mutable-local graph packages load as patterns; test
		// variants of the view packages load through the view patterns, and
		// an intermediate recompilation ("r [a.test]") is scanned from its
		// own compilation via the dependency-expanded fallback load in
		// deriveViewDynamicState — a plain stand-in would miss variant-only
		// resolution and need not even compile.
		if node.Class != closure.MutableLocalPackage || node.TestMain || node.ForTest != "" || seenPattern[node.PkgPath] {
			continue
		}
		seenPattern[node.PkgPath] = true
		patterns = append(patterns, node.PkgPath)
	}
	load, err := closure.LoadViewPackagesEnvSnapshot(ctx, dir, env, buildFlags, snapshot, patterns...)
	if err != nil {
		return nil, nil, err
	}
	hasher.UseViewLoad(load)
	state, err := deriveViewDynamicState(ctx, hasher, factScope, dir, env, buildFlags, load, pkgPaths)
	if err != nil {
		return nil, nil, err
	}
	scan, err := scanSubjectsFromLoaded(load.Packages(), state, pkgPaths...)
	return scan, load, err
}

// subjectScan is one observation pass's subject-walk result: enumeration,
// directive purity, per-subject dynamic-signature marks, and the subjects
// whose identity collapsed distinct declarations.
type subjectScan struct {
	pure      map[Subject]bool
	known     map[Subject]bool
	openWorld map[Subject]bool
	external  map[Subject]bool
	// downgradeReason maps each subject of a shared-dynamic-state
	// downgraded package to the refusal reason naming the owning package
	// and variable (REQ-closure-shared-dynamic-state).
	downgradeReason map[Subject]string
	// ambiguous holds, per subject whose identity is declared more than
	// once across the package and its test variants, the message naming
	// both declarations. Capture is refused for exactly these subjects —
	// no directive or assertion can be attributed to one declaration —
	// while sibling subjects scan normally (REQ-purity-directive).
	ambiguous map[Subject]string
}

func (s *subjectScan) directivePure(subject Subject) bool { return s.pure[subject] }

// scanSubjectsFromLoaded derives the subject walk — subject enumeration,
// directives, per-subject dynamic-signature marks — from an observation
// pass's already-loaded packages, applying the pass's dynamic-state
// derivation for the shared-dynamic-state downgrade and promoted-method
// directives (REQ-fresh-coherent-view, REQ-closure-shared-dynamic-state).
func scanSubjectsFromLoaded(pkgs []*packages.Package, state *viewDynamicState, pkgPaths ...string) (*subjectScan, error) {
	scan := &subjectScan{
		pure:            map[Subject]bool{},
		known:           map[Subject]bool{},
		openWorld:       map[Subject]bool{},
		external:        map[Subject]bool{},
		downgradeReason: map[Subject]string{},
		ambiguous:       map[Subject]string{},
	}
	pure, external, known, openWorld := scan.pure, scan.external, scan.known, scan.openWorld
	requestedPackages := make(map[string]bool, len(pkgPaths))
	for _, pkgPath := range pkgPaths {
		requestedPackages[pkgPath] = true
	}
	declarations := map[Subject]string{}
	var scanErr error
	record := func(subject Subject, declaration string) {
		if scanErr != nil {
			return
		}
		// Distinct declarations collapsing onto one subject identity —
		// legal Go: `package x` and `package x_test` in one directory may
		// share a top-level name — refuse capture for THAT subject and
		// scan on: the collision is subject-local, and failing the whole
		// scan would make the package unmeasurable over a name no caller
		// may ever request (REQ-purity-directive).
		if previous := declarations[subject]; previous != "" && previous != declaration {
			scan.ambiguous[subject] = fmt.Sprintf("declared at both %s and %s", previous, declaration)
			return
		}
		declarations[subject] = declaration
		known[subject] = true
	}
	for _, p := range pkgs {
		// A subject's package is the import path the engine resolves it under. The
		// package under test's own test variants declare subjects of the package
		// under test, so key those by ForTest — keying by the variant's own PkgPath
		// would silently drop a directive on an external-test-file subject
		// (REQ-purity-directive). But ForTest alone is not that discriminator: the
		// go tool sets it on every package recompiled into the test binary,
		// including intermediate dependencies (r imports a, a's external test
		// imports r → "r [a.test]" carries ForTest=a). Only the in-package variant
		// (PkgPath == ForTest) and the external test package (PkgPath is the tested
		// path + "_test", the go tool's naming for it) declare the tested package's
		// subjects; a recompiled dependency keeps its own PkgPath identity —
		// otherwise its declarations enter the scan as subjects of the tested
		// package and a shared top-level name fails the whole request as an
		// ambiguous subject.
		pkgPath := p.PkgPath
		if p.ForTest != "" && (p.PkgPath == p.ForTest || p.PkgPath == p.ForTest+"_test") {
			pkgPath = p.ForTest
		}
		if requestedPackages[pkgPath] {
			for _, f := range p.Syntax {
				for _, decl := range f.Decls {
					fd, ok := decl.(*ast.FuncDecl)
					if !ok {
						continue
					}
					sym := fd.Name.Name
					if recv := recvTypeName(fd); recv != "" {
						sym = recv + "." + sym
					}
					subject := Subject{Package: pkgPath, Symbol: sym}
					record(subject, nodeDeclarationKey(p, fd.Name))
					isPure, isExternal := hasDirective(fd.Doc, "//gofresh:pure"), hasDirective(fd.Doc, "//gofresh:external")
					if isPure && isExternal && scanErr == nil {
						// The declarations contradict: pure vouches reuse,
						// external forbids it (REQ-external-precedence). The
						// refusal is scoped to declarations yielding this
						// scan's subjects — a conflicted declaration deeper
						// in the loaded graph is its own package's defect,
						// surfacing when that package is scanned.
						scanErr = fmt.Errorf("gofresh: %s carries both //gofresh:pure and //gofresh:external", nodeDeclarationKey(p, fd.Name))
					}
					if isPure {
						pure[subject] = true
					}
					if isExternal {
						external[subject] = true
					}
					if fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func); ok && signatureMayReceiveUnknownDynamic(fn.Type().(*types.Signature)) {
						openWorld[subject] = true
					}
				}
			}
		}
		if p.Types == nil || !requestedPackages[pkgPath] {
			continue
		}
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			typeName, ok := scope.Lookup(name).(*types.TypeName)
			if !ok {
				continue
			}
			for _, methods := range []*types.MethodSet{
				types.NewMethodSet(types.NewPointer(typeName.Type())),
				types.NewMethodSet(typeName.Type()),
			} {
				for i := 0; i < methods.Len(); i++ {
					method, ok := methods.At(i).Obj().(*types.Func)
					if !ok {
						continue
					}
					subject := Subject{Package: pkgPath, Symbol: name + "." + method.Name()}
					record(subject, objectDeclarationKey(p, method))
					if sig, ok := method.Type().(*types.Signature); ok && signatureMayReceiveUnknownDynamic(sig) {
						openWorld[subject] = true
					}
					pureKey, externalKey := state.methodDirectives(method)
					if pureKey != "" && externalKey != "" && scanErr == nil {
						scanErr = fmt.Errorf("gofresh: %s carries both //gofresh:pure and //gofresh:external", pureKey)
					}
					if pureKey != "" {
						pure[subject] = true
					}
					if externalKey != "" {
						external[subject] = true
					}
				}
			}
		}
	}
	if scanErr != nil {
		return nil, scanErr
	}
	// Refused capture for ambiguous identities: no purity or externality
	// may be attributed to one of the collapsed declarations
	// (REQ-purity-directive); openness marks stay — their union only
	// widens, the safe direction, and the view force-marks ambiguous
	// subjects regardless. The subject stays known — it IS declared —
	// and the view marks it unverifiable with the naming diagnosis.
	for subject := range scan.ambiguous {
		delete(pure, subject)
		delete(external, subject)
	}
	// The shared-dynamic-state downgrade: every subject of a package whose
	// graph carries mutated shared dynamic state is unverifiable
	// (REQ-closure-shared-dynamic-state); the reachability came from the
	// pass's dynamic-state derivation over the metadata graph. The
	// downgrade carries its own reason naming the owning package and
	// variable — its channel is separately actionable from signature
	// dynamism.
	for subject := range known {
		if reason := state.downgraded[subject.Package]; reason != "" {
			scan.downgradeReason[subject] = "package graph shares mutated dynamic state: " + reason
		}
	}
	return scan, nil
}

func signatureMayReceiveUnknownDynamic(sig *types.Signature) bool {
	if sig == nil {
		return true
	}
	if isHarnessSignature(sig) {
		return false
	}
	// The type-parameter lists are consulted directly: a zero-parameter
	// generic reads closed through Params alone, and both tiers must
	// give one openness answer (REQ-closure-analysis's
	// parameterized-subject arm).
	for _, list := range []*types.TypeParamList{sig.TypeParams(), sig.RecvTypeParams()} {
		for i := 0; list != nil && i < list.Len(); i++ {
			if !closure.TypeParamBoundsAwayFromDynamic(list.At(i)) {
				return true
			}
		}
	}
	// One fresh map per parameter, mirroring the closure tier: no
	// cross-parameter mark leakage, cycle-safe within each evaluation.
	if recv := sig.Recv(); recv != nil && typeMayCarryUnknownDynamic(recv.Type(), make(map[types.Type]bool)) {
		return true
	}
	params := sig.Params()
	for i := 0; params != nil && i < params.Len(); i++ {
		if typeMayCarryUnknownDynamic(params.At(i).Type(), make(map[types.Type]bool)) {
			return true
		}
	}
	return false
}

func isHarnessSignature(sig *types.Signature) bool {
	if sig == nil || sig.Recv() != nil || sig.Params().Len() != 1 {
		return false
	}
	pointer, ok := sig.Params().At(0).Type().(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := pointer.Elem().(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "testing" {
		return false
	}
	switch named.Obj().Name() {
	case "T", "B", "F", "M":
		return true
	default:
		return false
	}
}

func typeMayCarryUnknownDynamic(t types.Type, seen map[types.Type]bool) bool {
	if t == nil || seen[t] {
		return false
	}
	seen[t] = true
	switch t := types.Unalias(t).(type) {
	case *types.Basic:
		return t.Kind() == types.UnsafePointer
	case *types.Interface, *types.Signature:
		return true
	case *types.TypeParam:
		return !closure.TypeParamBoundsAwayFromDynamic(t)
	case *types.Named:
		return typeMayCarryUnknownDynamic(t.Underlying(), seen)
	case *types.Pointer:
		return typeMayCarryUnknownDynamic(t.Elem(), seen)
	case *types.Slice:
		return typeMayCarryUnknownDynamic(t.Elem(), seen)
	case *types.Array:
		return typeMayCarryUnknownDynamic(t.Elem(), seen)
	case *types.Map:
		return typeMayCarryUnknownDynamic(t.Key(), seen) || typeMayCarryUnknownDynamic(t.Elem(), seen)
	case *types.Chan:
		return typeMayCarryUnknownDynamic(t.Elem(), seen)
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if typeMayCarryUnknownDynamic(t.Field(i).Type(), seen) {
				return true
			}
		}
	case *types.Tuple:
		for i := 0; i < t.Len(); i++ {
			if typeMayCarryUnknownDynamic(t.At(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

// nodeDeclarationKey and objectDeclarationKey derive the identity the
// ambiguous-subject refusal compares: one declaration must yield one key no
// matter which build variant sights it. Under Tests: true the same source
// package is visited once per variant with distinct pkg.IDs ("p" and
// "p [p.test]"), so no key may incorporate the sighting variant's identity —
// a variant-dependent key manufactures ambiguity for a single declaration and
// fails the whole package.
func nodeDeclarationKey(pkg *packages.Package, node ast.Node) string {
	if pkg != nil && pkg.Fset != nil && node != nil {
		position := pkg.Fset.PositionFor(node.Pos(), false)
		if position.Filename != "" {
			return fmt.Sprintf("%s:%d", position.Filename, position.Offset)
		}
	}
	return fmt.Sprintf("%s:%d", pkg.PkgPath, node.Pos())
}

func objectDeclarationKey(pkg *packages.Package, obj types.Object) string {
	if pkg != nil && pkg.Fset != nil && obj != nil {
		position := pkg.Fset.PositionFor(obj.Pos(), false)
		if position.Filename != "" {
			return fmt.Sprintf("%s:%d", position.Filename, position.Offset)
		}
	}
	if obj != nil && obj.Pkg() != nil {
		return obj.Pkg().Path() + "." + obj.Name()
	}
	// Position-less and package-less means a universe declaration — the
	// canonical case is error's Error method promoted through embedding. The
	// object's own description identifies it fully; genuinely distinct
	// declarations never reach this branch (real declarations carry a position
	// or a defining package).
	return fmt.Sprintf("universe:%v", obj)
}

// hasDirective reports whether a doc comment group carries the named gofresh
// directive — a comment line whose text is exactly the directive, the Go
// directive form with no leading space.
func hasDirective(doc *ast.CommentGroup, directive string) bool {
	if doc == nil {
		return false
	}
	for _, c := range doc.List {
		if c.Text == directive {
			return true
		}
	}
	return false
}

// recvTypeName is a method's receiver type name with the leading pointer star and
// any generic parameters stripped — "" for a plain function or an unnameable
// receiver. It matches stipulator's Go backend, so a method is named identically
// going into a bind and resolving here.
func recvTypeName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	t := fd.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if idx, ok := t.(*ast.IndexExpr); ok { // Recv[T]
		t = idx.X
	}
	if idx, ok := t.(*ast.IndexListExpr); ok { // Recv[T, U]
		t = idx.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// dynamicVarKey identifies a package-level variable stably across the
// test-variant recompilations packages.Load produces: variant type
// objects differ per graph, the (package path, name) pair does not. A
// mutation recorded under any variant marks the name for all — the
// conservative direction.
func dynamicVarKey(variable *types.Var) string {
	if variable.Pkg() == nil {
		return variable.Name()
	}
	return variable.Pkg().Path() + "." + variable.Name()
}

// recordDynamicGlobalMutations walks one package's syntax for
// post-initialization mutation of package-level dynamic-capable
// variables anywhere in the program, judged fail-closed by carrier
// shape (REQ-closure-shared-dynamic-state). By-value carriers mutate
// exactly by a write (assignment, inc/dec, range target, send), an
// address capture, or a pointer-receiver method use — at bind or call
// position alike. Alias-handing carriers (interface values, channels,
// pointers/maps/slices reaching a dynamic carrier, unsafe pointers)
// hand shared mutable access to every reader, so any use at all marks
// them. init functions are exempt — startup flow is deterministic,
// source-determined state — but function bodies nested in package-level
// declarations are program code and are walked.
func recordDynamicGlobalMutations(p *packages.Package, mutated map[string]bool) {
	recordDynamicGlobalUses(p, mutated, map[string]bool{}, initOnlyReachableHelpers(p), nil, nil, nil)
}

// recordDynamicGlobalUses classifies every package-level dynamic-capable
// variable use in one package's syntax: mutated collects demonstrated
// mutations (writes, growth/deletion, sends, address captures,
// pointer-receiver method uses, rebindings), escaped collects
// alias-carrier values handed to code that may write them (call
// arguments, stores, returns, bindings, method calls, type
// assertions). Reads that provably cannot write — indexing, iteration,
// length/capacity, comparison — mark neither, and initOnly names the
// init-only-reachable helpers whose bodies are init flow
// (REQ-closure-shared-dynamic-state).
// attributedUse carries a mutation or escape recorded inside a plain
// named function instead of marking immediately: composition
// discharges it when the whole graph proves the function reachable
// only from init flow, and promotes it otherwise
// (REQ-closure-shared-dynamic-state's cross-package init-only class).
type attributedUse struct {
	fn, key string
	escape  bool
	// method carries a deferred method-use's fact key: composition
	// skips it entirely when fn proves init-only, resolves it against
	// the receiver-effect read-only union otherwise.
	method string
}

// plainCalleeFunc resolves a call's function expression to a plain named
// function and its declaring package path, unwrapping parenthesization
// and explicit generic instantiation; the generic origin carries the
// declared identity. Method values, builtins, and function-typed values
// resolve to nil - only a named function has a parameter fact to defer
// to (REQ-closure-shared-dynamic-state).
func plainCalleeFunc(p *packages.Package, fun ast.Expr) (*types.Func, string) {
	for {
		switch f := fun.(type) {
		case *ast.ParenExpr:
			fun = f.X
			continue
		case *ast.IndexExpr:
			fun = f.X
			continue
		case *ast.IndexListExpr:
			fun = f.X
			continue
		}
		break
	}
	var obj types.Object
	switch f := fun.(type) {
	case *ast.Ident:
		obj = p.TypesInfo.Uses[f]
	case *ast.SelectorExpr:
		if x, ok := f.X.(*ast.Ident); ok {
			if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
				obj = p.TypesInfo.Uses[f.Sel]
			}
		}
	}
	fn, ok := obj.(*types.Func)
	if !ok || fn.Pkg() == nil {
		return nil, ""
	}
	fn = fn.Origin()
	if sig, ok := fn.Type().(*types.Signature); !ok || sig.Recv() != nil {
		return nil, ""
	}
	return fn, fn.Pkg().Path()
}

// pendingReturnDisposition is one conditionally discharged range whose
// enclosing function returned the binding: the fn's callers decide, and
// an uncontained handout restores the escape - to the attributed record
// when the range sat in an attributed body, to the immediate marks
// otherwise (REQ-closure-shared-dynamic-state).
type pendingReturnDisposition struct {
	fn     string
	keys   []string
	attrFn string
}

func recordDynamicGlobalUses(p *packages.Package, mutated, escaped, initOnly map[string]bool, methodUses, paramUses map[string]map[string]bool, attributed *[]attributedUse) {
	if p == nil || p.TypesInfo == nil {
		return
	}
	dynamicPackageVar := func(obj types.Object) (*types.Var, bool) {
		variable, ok := obj.(*types.Var)
		if !ok || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
			return nil, false
		}
		if !typeMayCarryUnknownDynamic(variable.Type(), make(map[types.Type]bool)) {
			return nil, false
		}
		return variable, true
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
	// aliasedLocals is set only while walking an init-flow body's
	// interiors: init-locals bound from carriers, mapped to the carrier
	// keys they alias.
	var aliasedLocals map[types.Object]map[string]bool
	// currentFn is the FuncDecl whose direct body walkBody is walking
	// (nil inside interiors and package-level literals); currentAttrFn
	// its attribution key when the walk records into the attributed
	// maps. pendingReturns collects conditionally discharged ranges
	// whose enclosing function returned the binding - resolved against
	// the function's callers by package-local fixed point after the
	// walk, an uncontained handout restoring the escape.
	var currentFn *ast.FuncDecl
	var currentAttrFn string
	var pendingReturns []pendingReturnDisposition
	// markTargets marks every dynamic-capable package variable an
	// expression subtree reaches — deliberately over-approximate: a
	// spurious mark only keeps a variable's current conservative
	// disposition.
	markTargets := func(expr ast.Expr) {
		ast.Inspect(expr, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if obj, ok := resolve(ident); ok {
				if variable, ok := dynamicPackageVar(obj); ok {
					mutated[dynamicVarKey(variable)] = true
				} else {
					for key := range aliasedLocals[obj] {
						mutated[key] = true
					}
				}
			}
			return true
		})
	}
	// initAliasedLocals maps an init-flow body's locals bound from
	// carriers to the carrier keys they alias, to a fixpoint over
	// assignment and range chains, with nested literals and go
	// statements excluded (they are program code, walked separately).
	// An interior that touches such a local touches the carrier.
	initAliasedLocals := func(body ast.Node) map[types.Object]map[string]bool {
		aliased := map[types.Object]map[string]bool{}
		rhsKeys := func(expr ast.Expr) map[string]bool {
			keys := map[string]bool{}
			ast.Inspect(expr, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.FuncLit:
					return false
				case *ast.Ident:
					if obj, ok := resolve(n); ok {
						if variable, ok := dynamicPackageVar(obj); ok {
							keys[dynamicVarKey(variable)] = true
						} else if source := aliased[obj]; source != nil {
							for key := range source {
								keys[key] = true
							}
						}
					}
				}
				return true
			})
			return keys
		}
		bind := func(target ast.Expr, keys map[string]bool) bool {
			if len(keys) == 0 {
				return false
			}
			for {
				paren, ok := target.(*ast.ParenExpr)
				if !ok {
					break
				}
				target = paren.X
			}
			ident, ok := target.(*ast.Ident)
			if !ok {
				return false
			}
			obj, ok := resolve(ident)
			if !ok {
				return false
			}
			if _, pkg := dynamicPackageVar(obj); pkg {
				return false
			}
			if !typeHandsOutDynamicAlias(obj.Type(), make(map[types.Type]bool)) {
				return false
			}
			changed := false
			if aliased[obj] == nil {
				aliased[obj] = map[string]bool{}
			}
			for key := range keys {
				if !aliased[obj][key] {
					aliased[obj][key] = true
					changed = true
				}
			}
			return changed
		}
		for changed := true; changed; {
			changed = false
			ast.Inspect(body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.FuncLit, *ast.GoStmt:
					return false
				case *ast.AssignStmt:
					if len(n.Lhs) == len(n.Rhs) {
						for i, rhs := range n.Rhs {
							if bind(n.Lhs[i], rhsKeys(rhs)) {
								changed = true
							}
						}
					} else if len(n.Rhs) == 1 {
						keys := rhsKeys(n.Rhs[0])
						for _, lhs := range n.Lhs {
							if bind(lhs, keys) {
								changed = true
							}
						}
					}
				case *ast.ValueSpec:
					// A declaration binding aliases exactly as an
					// assignment binding does.
					if len(n.Names) == len(n.Values) {
						for i, name := range n.Names {
							if bind(name, rhsKeys(n.Values[i])) {
								changed = true
							}
						}
					} else if len(n.Values) == 1 {
						keys := rhsKeys(n.Values[0])
						for _, name := range n.Names {
							if bind(name, keys) {
								changed = true
							}
						}
					}
				case *ast.RangeStmt:
					keys := rhsKeys(n.X)
					for _, target := range []ast.Expr{n.Key, n.Value} {
						if target != nil && bind(target, keys) {
							changed = true
						}
					}
				case *ast.CallExpr:
					// A builtin copy aliases the destination's elements to
					// the source's backing without a binding statement -
					// the destination local is the carrier exactly as an
					// assignment-bound alias is.
					if ident, ok := n.Fun.(*ast.Ident); ok && len(n.Args) == 2 {
						if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && ident.Name == "copy" {
							if bind(n.Args[0], rhsKeys(n.Args[1])) {
								changed = true
							}
						}
					}
				}
				return true
			})
		}
		return aliased
	}
	// carrierArgVar resolves a call argument to the alias-handing carrier
	// it names directly - a bare or package-qualified identifier, parens
	// unwrapped; anything else names no deferrable carrier.
	carrierArgVar := func(arg ast.Expr) (*ast.Ident, *types.Var) {
		for {
			paren, ok := arg.(*ast.ParenExpr)
			if !ok {
				break
			}
			arg = paren.X
		}
		var target *ast.Ident
		switch a := arg.(type) {
		case *ast.Ident:
			target = a
		case *ast.SelectorExpr:
			if x, ok := a.X.(*ast.Ident); ok {
				if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
					target = a.Sel
				}
			}
		}
		if target == nil {
			return nil, nil
		}
		obj, ok := resolve(target)
		if !ok {
			return nil, nil
		}
		variable, ok := dynamicPackageVar(obj)
		if !ok {
			return nil, nil
		}
		if !typeHandsOutDynamicAlias(variable.Type(), make(map[types.Type]bool)) {
			// A non-alias-handing carrier (a func-typed hook, a by-value
			// struct) cannot be rebound through the argument - the ident
			// arm already classifies it without an escape, and no
			// leak-free fact exists to resolve a deferral against.
			return nil, nil
		}
		return target, variable
	}
	deferCarrierArgs := func(n *ast.CallExpr, onDeferred func(*ast.Ident)) {
		fn, pkgPath := plainCalleeFunc(p, n.Fun)
		if fn == nil {
			return
		}
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() != nil || sig.Params().Len() == 0 {
			return
		}
		for i, arg := range n.Args {
			target, variable := carrierArgVar(arg)
			if target == nil {
				continue
			}
			idx := i
			if sig.Variadic() && idx >= sig.Params().Len()-1 {
				idx = sig.Params().Len() - 1
			}
			key := dynamicVarKey(variable)
			if paramUses[key] == nil {
				paramUses[key] = map[string]bool{}
			}
			paramUses[key][pkgPath+"\x00"+fn.Name()+"\x00"+strconv.Itoa(idx)] = true
			if onDeferred != nil {
				onDeferred(target)
			}
		}
	}
	// scanExemptCalls covers the call arguments of the init-exempt
	// regions - init bodies, init-only helpers, initializer expressions -
	// whose stores and calls the use walk exempts: a carrier argument to
	// a plain named function defers to that parameter's leak-free fact
	// exactly as in program code (the deferral applies to init flow, the
	// alias outlives initialization), and a carrier argument to any other
	// callee - a method, a func value, a builtin the shapes do not name -
	// escapes fail-closed. Nested literals and go statements are program
	// code, walked separately (REQ-closure-shared-dynamic-state).
	// markExemptEscapes escapes every carrier an exempt-region call
	// argument's subtree reaches - directly or through an init-local
	// alias - the fail-closed twin of the program-code ident arm for the
	// shapes no deferral can resolve.
	markExemptEscapes := func(arg ast.Expr) {
		ast.Inspect(arg, func(inner ast.Node) bool {
			if ident, ok := inner.(*ast.Ident); ok {
				if obj, ok := resolve(ident); ok {
					if variable, ok := dynamicPackageVar(obj); ok {
						if typeHandsOutDynamicAlias(variable.Type(), make(map[types.Type]bool)) {
							escaped[dynamicVarKey(variable)] = true
						}
					} else {
						for key := range aliasedLocals[obj] {
							escaped[key] = true
						}
					}
				}
			}
			return true
		})
	}
	scanExemptCalls := func(body ast.Node) {
		if paramUses == nil || body == nil {
			return
		}
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit, *ast.GoStmt:
				return false
			case *ast.CallExpr:
				if ident, ok := n.Fun.(*ast.Ident); ok {
					if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
						switch ident.Name {
						case "len", "cap", "delete", "clear", "append", "copy":
							// Writeless reads, removals, and the two
							// element-flow shapes judged elsewhere: stores
							// by the registration audit, alias-creating
							// destinations by the init-local alias scan.
							return true
						}
					}
				}
				plain := false
				if fn, _ := plainCalleeFunc(p, n.Fun); fn != nil {
					plain = true
					deferCarrierArgs(n, nil)
				}
				for _, arg := range n.Args {
					if plain {
						if _, variable := carrierArgVar(arg); variable != nil {
							// Directly deferred above.
							continue
						}
					}
					markExemptEscapes(arg)
				}
			}
			return true
		})
	}
	var skipInteriors map[ast.Node]bool
	walkBody := func(body ast.Node) {
		// readContext collects ident occurrences whose enclosing shape is
		// a provably-writeless read: indexing, iteration source,
		// length/capacity, comparison. Inspect visits parents before
		// children, so the shape records its operand idents ahead of the
		// ident visit that would otherwise classify them as escapes.
		readContext := map[*ast.Ident]bool{}
		calledSelectors := map[*ast.SelectorExpr]bool{}
		goCalls := map[*ast.CallExpr]bool{}
		markRead := func(expr ast.Expr) {
			switch expr := expr.(type) {
			case *ast.Ident:
				readContext[expr] = true
			case *ast.SelectorExpr:
				// A cross-package read names the variable through a
				// selector; the selector's field ident is what the
				// escape classification would otherwise see.
				readContext[expr.Sel] = true
			}
		}
		ast.Inspect(body, func(n ast.Node) bool {
			if skipInteriors[n] {
				return false
			}
			switch n := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					markTargets(lhs)
					// The written element's container is read-shaped on
					// the left too: m[k] = v writes the entry through m,
					// which the AssignStmt mark above already records as
					// mutation — the ident visit must not double it as
					// an escape.
					if index, ok := lhs.(*ast.IndexExpr); ok {
						markRead(index.X)
					}
				}
			case *ast.IncDecStmt:
				markTargets(n.X)
			case *ast.RangeStmt:
				if n.Key != nil {
					markTargets(n.Key)
				}
				if n.Value != nil {
					markTargets(n.Value)
				}
				// Ranging a channel receives - mutation, not a read - and
				// the iteration discharge holds when the produced
				// bindings are not themselves alias-handing, or when the
				// alias-handing bindings are proven leak-free over the
				// loop body (REQ-closure-shared-dynamic-state).
				if t := p.TypesInfo.TypeOf(n.X); t != nil {
					if _, isChan := types.Unalias(t).Underlying().(*types.Chan); isChan {
						markTargets(n.X)
					} else if !rangeBindsAlias(t) {
						markRead(n.X)
					} else if n.Key == nil && n.Value == nil {
						// A bare range binds nothing - trivially leak-free.
						markRead(n.X)
					} else if n.Tok == token.DEFINE && n.Body != nil {
						roots := map[types.Object]bool{}
						sound := true
						for _, bind := range []ast.Expr{n.Key, n.Value} {
							if bind == nil {
								continue
							}
							ident, ok := bind.(*ast.Ident)
							if !ok {
								sound = false
								break
							}
							if obj := p.TypesInfo.Defs[ident]; obj != nil && typeHandsOutMutableReach(obj.Type(), make(map[types.Type]bool)) {
								roots[obj] = true
							}
						}
						// The binding proof may defer rooted arguments to
						// plain named parameters (the wants ride the
						// carrier as deferred argument marks, resolved at
						// composition exactly like a direct carrier
						// argument's) and may tolerate return-position
						// handouts when the enclosing function is an
						// eligible returner - the returned-binding
						// disposition judges its callers by package-local
						// fixed point after the walk. A carrier the walk
						// cannot key keeps the strict proof.
						var wants, methodWants map[string]bool
						var returned bool
						var retPtr *bool
						if paramUses != nil {
							wants = map[string]bool{}
							if methodUses != nil {
								methodWants = map[string]bool{}
							}
							if currentFn != nil && currentFn.Recv == nil && currentFn.Name != nil && !currentFn.Name.IsExported() && currentFn.Name.Name != "init" {
								retPtr = &returned
							}
						}
						if sound && (len(roots) == 0 || boundValueLeakFreeJudged(p, roots, n.Body, wants, retPtr, methodWants)) {
							if len(wants) == 0 && len(methodWants) == 0 && !returned {
								markRead(n.X)
							} else {
								var keys []string
								ast.Inspect(n.X, func(inner ast.Node) bool {
									if ident, ok := inner.(*ast.Ident); ok {
										if obj, ok := resolve(ident); ok {
											if variable, ok := dynamicPackageVar(obj); ok {
												keys = append(keys, dynamicVarKey(variable))
											} else {
												for key := range aliasedLocals[obj] {
													keys = append(keys, key)
												}
											}
										}
									}
									return true
								})
								if len(keys) > 0 {
									for _, key := range keys {
										if paramUses[key] == nil {
											paramUses[key] = map[string]bool{}
										}
										for want := range wants {
											paramUses[key][want] = true
										}
										if len(methodWants) > 0 && methodUses[key] == nil {
											methodUses[key] = map[string]bool{}
										}
										for want := range methodWants {
											methodUses[key][want] = true
										}
									}
									if returned {
										pendingReturns = append(pendingReturns, pendingReturnDisposition{
											fn:     currentFn.Name.Name,
											keys:   keys,
											attrFn: currentAttrFn,
										})
									}
									markRead(n.X)
								}
							}
						}
					}
				}
			case *ast.SendStmt:
				markTargets(n.Chan)
			case *ast.UnaryExpr:
				if n.Op == token.AND || n.Op == token.ARROW {
					markTargets(n.X)
				}
			case *ast.IndexExpr:
				// The discharge holds only when the produced element is
				// not itself alias-handing - an indexed-out map or slice
				// still writes through (REQ-closure-shared-dynamic-state).
				if t := p.TypesInfo.TypeOf(n); t == nil || !typeHandsOutMutableReach(t, make(map[types.Type]bool)) {
					markRead(n.X)
				}
			case *ast.BinaryExpr:
				if n.Op == token.EQL || n.Op == token.NEQ {
					markRead(n.X)
					markRead(n.Y)
				}
			case *ast.GoStmt:
				// A goroutine's calls - the direct call and any call
				// nested in its subtree - run concurrently with
				// everything after it: none of their arguments earn the
				// parameter deferral (REQ-closure-shared-dynamic-state).
				ast.Inspect(n, func(inner ast.Node) bool {
					if call, ok := inner.(*ast.CallExpr); ok {
						goCalls[call] = true
					}
					return true
				})
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
					calledSelectors[sel] = true
				}
				if ident, ok := n.Fun.(*ast.Ident); ok {
					if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
						switch ident.Name {
						case "len", "cap":
							for _, arg := range n.Args {
								markRead(arg)
							}
						case "delete", "clear":
							// Deletion is mutation, not an escape.
							if len(n.Args) > 0 {
								markTargets(n.Args[0])
							}
						}
					}
				}
				// A carrier passed as a direct argument to a plain named
				// function defers to that parameter's leak-free proof at
				// composition instead of the fail-closed escape - absence
				// of the proof restores the escape there
				// (REQ-closure-shared-dynamic-state).
				if paramUses != nil && !goCalls[n] {
					deferCarrierArgs(n, func(target *ast.Ident) {
						readContext[target] = true
					})
				}
			case *ast.SelectorExpr:
				// A pointer-receiver method USE — bind or call alike —
				// is an implicit address capture of its receiver chain.
				// A direct CALL on a statically-typed (non-interface)
				// package-var receiver defers to the method's own
				// receiver-effect proof at composition; binds and
				// interface dispatch keep the fail-closed mark
				// (REQ-closure-shared-dynamic-state).
				if selection, ok := p.TypesInfo.Selections[n]; ok && selection.Kind() == types.MethodVal {
					if fn, ok := selection.Obj().(*types.Func); ok {
						if methodUses != nil && calledSelectors[n] && !interfaceReceiver(fn) && instantiatedResultsHandOutNothing(selection.Type()) {
							if ident, ok := n.X.(*ast.Ident); ok {
								if obj, ok := resolve(ident); ok {
									if variable, ok := dynamicPackageVar(obj); ok {
										key := dynamicVarKey(variable)
										if methodUses[key] == nil {
											methodUses[key] = map[string]bool{}
										}
										methodUses[key][methodFactKey(fn)] = true
										readContext[ident] = true
										return true
									}
								}
							}
						}
						if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
							if _, pointer := types.Unalias(sig.Recv().Type()).(*types.Pointer); pointer {
								markTargets(n.X)
							}
						}
					}
				}
			case *ast.Ident:
				// Alias-handing carriers: any use that is neither a
				// demonstrated mutation (the statement shapes above) nor
				// a provably-writeless read hands the value to code that
				// may write it — the escape class.
				if readContext[n] {
					return true
				}
				if obj, ok := resolve(n); ok {
					if variable, ok := dynamicPackageVar(obj); ok && typeHandsOutDynamicAlias(variable.Type(), make(map[types.Type]bool)) {
						escaped[dynamicVarKey(variable)] = true
					} else {
						// An init-flow local aliasing a carrier is the
						// carrier inside program code.
						for key := range aliasedLocals[obj] {
							escaped[key] = true
						}
					}
				}
			}
			return true
		})
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if decl.Recv == nil && decl.Name != nil && attributed != nil && !initOnly[decl.Name.Name] && decl.Name.Name != "init" && decl.Body != nil {
					// A plain named function's carrier uses attribute to
					// it: the cross-package fixed point decides at
					// composition whether they are init flow. Literals
					// and go statements inside stay program code.
					fnKey := ""
					if p.Types != nil {
						fnKey = p.Types.Path() + "\x00" + decl.Name.Name
					}
					// Literals and go statements nested in the body are
					// program code: they walk into the immediate maps
					// first, and the attributed walk skips them.
					interiors := map[ast.Node]bool{}
					ast.Inspect(decl.Body, func(n ast.Node) bool {
						switch n := n.(type) {
						case *ast.FuncLit:
							if n.Body != nil {
								walkBody(n.Body)
								interiors[n] = true
							}
							return false
						case *ast.GoStmt:
							walkBody(n)
							interiors[n] = true
							return false
						}
						return true
					})
					localMutated, localEscaped := map[string]bool{}, map[string]bool{}
					localMethods := map[string]map[string]bool{}
					saveM, saveE, saveMU := mutated, escaped, methodUses
					mutated, escaped, methodUses = localMutated, localEscaped, localMethods
					skipInteriors = interiors
					currentFn, currentAttrFn = decl, fnKey
					walkBody(decl.Body)
					currentFn, currentAttrFn = nil, ""
					skipInteriors = nil
					mutated, escaped, methodUses = saveM, saveE, saveMU
					for key := range localMutated {
						*attributed = append(*attributed, attributedUse{fn: fnKey, key: key})
					}
					for key := range localEscaped {
						*attributed = append(*attributed, attributedUse{fn: fnKey, key: key, escape: true})
					}
					for key, methods := range localMethods {
						for method := range methods {
							*attributed = append(*attributed, attributedUse{fn: fnKey, key: key, method: method})
						}
					}
					continue
				}
				if decl.Recv == nil && decl.Name != nil && initOnly[decl.Name.Name] {
					// An init-only-reachable helper's body is init flow:
					// its mutations are startup-deterministic. Literals
					// nested in it stay program code, exactly as in an
					// init body (REQ-closure-shared-dynamic-state).
					if decl.Body != nil {
						aliasedLocals = initAliasedLocals(decl.Body)
						ast.Inspect(decl.Body, func(n ast.Node) bool {
							switch n := n.(type) {
							case *ast.FuncLit:
								if n.Body != nil {
									walkBody(n.Body)
								}
								return false
							case *ast.GoStmt:
								// A go statement launched from init flow is
								// program code in its entirety - the
								// arguments outlive initialization with
								// the goroutine.
								walkBody(n)
								return false
							}
							return true
						})
						scanExemptCalls(decl.Body)
						aliasedLocals = nil
					}
					continue
				}
				if decl.Recv == nil && decl.Name != nil && decl.Name.Name == "init" {
					// init flow is exempt, but a function literal nested
					// in an init body is callable program code exactly
					// like one nested in a package-level declaration -
					// and an init-local alias of a carrier is the carrier
					// inside it.
					if decl.Body != nil {
						aliasedLocals = initAliasedLocals(decl.Body)
						ast.Inspect(decl.Body, func(n ast.Node) bool {
							switch n := n.(type) {
							case *ast.FuncLit:
								if n.Body != nil {
									walkBody(n.Body)
								}
								return false
							case *ast.GoStmt:
								// Program code in its entirety, exactly as
								// in a qualified helper.
								walkBody(n)
								return false
							}
							return true
						})
						scanExemptCalls(decl.Body)
						aliasedLocals = nil
					}
					continue
				}
				if decl.Body != nil {
					currentFn = decl
					walkBody(decl.Body)
					currentFn = nil
				}
			default:
				// The declaration itself is initialization, but a
				// function literal nested in it is callable program
				// code — a package-level `var rebind = func() {...}`
				// mutator must be walked — and a call in an initializer
				// expression is an init-flow call whose carrier arguments
				// earn the same deferral as an init body's.
				ast.Inspect(decl, func(n ast.Node) bool {
					if lit, ok := n.(*ast.FuncLit); ok && lit.Body != nil {
						walkBody(lit.Body)
						return false
					}
					return true
				})
				scanExemptCalls(decl)
			}
		}
	}
	if len(pendingReturns) > 0 {
		// The returned-binding disposition: every in-package use of a
		// returner must contain the handed-out alias - a call result
		// bound to identifiers proven leak-free over the using body by
		// the same judgment (deferrals included), a discarded result, or
		// return-position propagation chaining the disposition to the
		// propagating function's own callers, resolved to a
		// package-local fixed point; a value reference, an argument- or
		// composite-position result, a binding the walk cannot judge, or
		// propagation through an ineligible function refuses, restoring
		// the recorded escape (REQ-closure-shared-dynamic-state).
		returnerKeys := map[string]map[string]bool{}
		mergeKeys := func(fn string, keys map[string]bool) bool {
			if returnerKeys[fn] == nil {
				returnerKeys[fn] = map[string]bool{}
			}
			changed := false
			for key := range keys {
				if !returnerKeys[fn][key] {
					returnerKeys[fn][key] = true
					changed = true
				}
			}
			return changed
		}
		for _, pending := range pendingReturns {
			set := map[string]bool{}
			for _, key := range pending.keys {
				set[key] = true
			}
			mergeKeys(pending.fn, set)
		}
		bad := map[string]bool{}
		deps := map[string]map[string]bool{}
		scanned := map[string]bool{}
		for {
			var frontier []string
			for fn := range returnerKeys {
				if !scanned[fn] {
					frontier = append(frontier, fn)
					scanned[fn] = true
				}
			}
			if len(frontier) == 0 {
				break
			}
			returnerObjs := map[types.Object]string{}
			for _, file := range p.Syntax {
				for _, decl := range file.Decls {
					if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name != nil {
						if _, tracked := returnerKeys[fd.Name.Name]; tracked {
							if obj := p.TypesInfo.Defs[fd.Name]; obj != nil {
								returnerObjs[obj] = fd.Name.Name
							}
						}
					}
				}
			}
			frontierSet := map[string]bool{}
			for _, fn := range frontier {
				frontierSet[fn] = true
			}
			depend := func(from, to string) {
				if deps[from] == nil {
					deps[from] = map[string]bool{}
				}
				deps[from][to] = true
			}
			// scanSites judges every returner use within one body: the
			// site name and eligibility describe the enclosing plain
			// function when there is one; a package-level literal has
			// neither - its re-returns and unknowable callers refuse.
			scanSites := func(body ast.Node, siteName string, siteEligible bool) {
					var stack []ast.Node
					ast.Inspect(body, func(n ast.Node) bool {
						if n == nil {
							stack = stack[:len(stack)-1]
							return true
						}
						defer func() { stack = append(stack, n) }()
						ident, ok := n.(*ast.Ident)
						if !ok {
							return true
						}
						obj := p.TypesInfo.Uses[ident]
						if obj == nil {
							return true
						}
						fnName, tracked := returnerObjs[obj]
						if !tracked || !frontierSet[fnName] {
							return true
						}
						if len(stack) == 0 {
							bad[fnName] = true
							return true
						}
						call, ok := stack[len(stack)-1].(*ast.CallExpr)
						if !ok || call.Fun != ast.Expr(ident) {
							// A value reference - or an argument position.
							bad[fnName] = true
							return true
						}
						var grand ast.Node
						if len(stack) >= 2 {
							grand = stack[len(stack)-2]
						}
						fnObj, isFunc := obj.(*types.Func)
						if !isFunc {
							bad[fnName] = true
							return true
						}
						sig, ok := fnObj.Type().(*types.Signature)
						if !ok {
							bad[fnName] = true
							return true
						}
						var targets []ast.Expr
						switch g := grand.(type) {
						case *ast.ExprStmt, *ast.GoStmt, *ast.DeferStmt:
							return true
						case *ast.ReturnStmt:
							// A return inside a nested literal exits the
							// literal - its caller is unknowable, never
							// the enclosing function's disposition.
							inLit := false
							for _, frame := range stack {
								if _, isLit := frame.(*ast.FuncLit); isLit {
									inLit = true
									break
								}
							}
							if siteEligible && !inLit {
								if mergeKeys(siteName, returnerKeys[fnName]) {
									scanned[siteName] = false
								}
								depend(fnName, siteName)
							} else {
								bad[fnName] = true
							}
							return true
						case *ast.AssignStmt:
							if len(g.Rhs) != 1 || g.Rhs[0] != ast.Expr(call) {
								bad[fnName] = true
								return true
							}
							targets = g.Lhs
						case *ast.ValueSpec:
							if len(g.Values) != 1 || g.Values[0] != ast.Expr(call) {
								bad[fnName] = true
								return true
							}
							for _, name := range g.Names {
								targets = append(targets, name)
							}
						default:
							bad[fnName] = true
							return true
						}
						results := sig.Results()
						if results.Len() != len(targets) {
							bad[fnName] = true
							return true
						}
						roots := map[types.Object]bool{}
						for i, target := range targets {
							tIdent, ok := target.(*ast.Ident)
							if !ok {
								bad[fnName] = true
								return true
							}
							if !typeHandsOutMutableReach(results.At(i).Type(), make(map[types.Type]bool)) {
								continue
							}
							if tObj := p.TypesInfo.Defs[tIdent]; tObj != nil {
								roots[tObj] = true
							} else if tObj := p.TypesInfo.Uses[tIdent]; tObj != nil {
								roots[tObj] = true
							}
						}
						if len(roots) == 0 {
							return true
						}
						siteWants := map[string]bool{}
						var siteMethodWants map[string]bool
						if methodUses != nil {
							siteMethodWants = map[string]bool{}
						}
						var siteReturned bool
						var siteRet *bool
						if siteEligible {
							siteRet = &siteReturned
						}
						if !boundValueLeakFreeJudged(p, roots, body, siteWants, siteRet, siteMethodWants) {
							bad[fnName] = true
							return true
						}
						for want := range siteWants {
							for key := range returnerKeys[fnName] {
								if paramUses[key] == nil {
									paramUses[key] = map[string]bool{}
								}
								paramUses[key][want] = true
							}
						}
						for want := range siteMethodWants {
							for key := range returnerKeys[fnName] {
								if methodUses[key] == nil {
									methodUses[key] = map[string]bool{}
								}
								methodUses[key][want] = true
							}
						}
						if siteReturned {
							if mergeKeys(siteName, returnerKeys[fnName]) {
								scanned[siteName] = false
							}
							depend(fnName, siteName)
						}
						return true
					})
			}
			for _, file := range p.Syntax {
				for _, decl := range file.Decls {
					switch decl := decl.(type) {
					case *ast.FuncDecl:
						if decl.Body == nil {
							continue
						}
						name := ""
						if decl.Name != nil {
							name = decl.Name.Name
						}
						eligible := decl.Recv == nil && decl.Name != nil && !decl.Name.IsExported() && name != "init"
						scanSites(decl.Body, name, eligible)
					case *ast.GenDecl:
						// Package-level literals hold uses too - each is a
						// site body with no enclosing plain function; a
						// direct initializer-position call binds package
						// variables, contained only when every
						// alias-handing result lands in a blank.
						for _, spec := range decl.Specs {
							vs, ok := spec.(*ast.ValueSpec)
							if !ok {
								continue
							}
							for _, value := range vs.Values {
								ast.Inspect(value, func(n ast.Node) bool {
									if lit, ok := n.(*ast.FuncLit); ok {
										if lit.Body != nil {
											scanSites(lit.Body, "", false)
										}
										return false
									}
									if ident, ok := n.(*ast.Ident); ok {
										if obj := p.TypesInfo.Uses[ident]; obj != nil {
											if fnName, tracked := returnerObjs[obj]; tracked && frontierSet[fnName] {
												contained := false
												if call, isCall := value.(*ast.CallExpr); isCall && call.Fun == ast.Expr(ident) {
													if fnObj, isFunc := obj.(*types.Func); isFunc {
														if sig, isSig := fnObj.Type().(*types.Signature); isSig && sig.Results().Len() == len(vs.Names) {
															contained = true
															for i, nameIdent := range vs.Names {
																if nameIdent.Name != "_" && typeHandsOutMutableReach(sig.Results().At(i).Type(), make(map[types.Type]bool)) {
																	contained = false
																	break
																}
															}
														}
													}
												}
												if !contained {
													bad[fnName] = true
												}
											}
										}
									}
									return true
								})
							}
						}
					}
				}
			}
		}
		for changed := true; changed; {
			changed = false
			for from, tos := range deps {
				if bad[from] {
					continue
				}
				for to := range tos {
					if bad[to] {
						bad[from] = true
						changed = true
						break
					}
				}
			}
		}
		restored := map[string]bool{}
		for _, pending := range pendingReturns {
			if !bad[pending.fn] {
				continue
			}
			for _, key := range pending.keys {
				if pending.attrFn != "" {
					if !restored[pending.attrFn+"\x00"+key] {
						restored[pending.attrFn+"\x00"+key] = true
						*attributed = append(*attributed, attributedUse{fn: pending.attrFn, key: key, escape: true})
					}
				} else {
					escaped[key] = true
				}
			}
		}
	}
}

// typeCarriesSignature reports whether a value of the type can hand out a
// function value a holder could extract and call: a signature, or a
// container reaching one through struct fields, array/slice/map elements,
// pointers, or channels. Interfaces report false - a method call through a
// carrier-held interface value refuses in the use-shape engine, and a type
// assertion extracting a function is an unrecognized use there too, so the
// environment audit owes interfaces nothing.
func typeCarriesSignature(t types.Type, seen map[types.Type]bool) bool {
	if t == nil || seen[t] {
		return false
	}
	seen[t] = true
	switch t := types.Unalias(t).(type) {
	case *types.Signature:
		return true
	case *types.Basic, *types.Interface:
		return false
	case *types.Named:
		return typeCarriesSignature(t.Underlying(), seen)
	case *types.Pointer:
		return typeCarriesSignature(t.Elem(), seen)
	case *types.Slice:
		return typeCarriesSignature(t.Elem(), seen)
	case *types.Array:
		return typeCarriesSignature(t.Elem(), seen)
	case *types.Chan:
		return typeCarriesSignature(t.Elem(), seen)
	case *types.Map:
		return typeCarriesSignature(t.Elem(), seen)
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if typeCarriesSignature(t.Field(i).Type(), seen) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

// environmentFreeFuncLit reports whether a function literal registered into
// a carrier is provably environment-free: every variable it references from
// an enclosing function scope proves leak-free under the use-shape engine -
// writeless, handing nothing of mutable reach to a caller or callee, every
// unrecognized use refusing - over the literal's own body AND over every
// sibling literal in the enclosing body that references the variable, since
// a shared environment is one object however many carriers its closures
// reach; a reference from a go statement's call outside any literal refuses
// outright, because the goroutine outlives initialization. A read-only
// capture of settled init state passes; a written captured scalar refuses
// exactly as a written captured slice does. Package-level referents are not
// captures: their uses attribute at this site like any program code
// (REQ-closure-shared-dynamic-state).
func environmentFreeFuncLit(p *packages.Package, lit *ast.FuncLit, enclosing ast.Node) bool {
	return environmentFreeFuncLitJudged(p, lit, enclosing, nil, nil)
}

// environmentFreeFuncLitJudged additionally collects parameter and
// method wants when the caller supplies sinks, instead of refusing the
// deferrable shapes outright - the constructor-result proof resolves the
// collected wants against its own package's facts
// (REQ-closure-shared-dynamic-state).
func environmentFreeFuncLitJudged(p *packages.Package, lit *ast.FuncLit, enclosing ast.Node, wants, methodWants map[string]bool) bool {
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
		// Alias closure: an enclosing-body binding chained from a captured
		// variable by assignment, range, address, or reslice shares its
		// backing - the environment is one object under every name it
		// carries, so the alias joins the root set before any judgment.
		var edges [][2]types.Object
		aliasEdges := func(target ast.Expr, sources ast.Expr) {
			for {
				paren, ok := target.(*ast.ParenExpr)
				if !ok {
					break
				}
				target = paren.X
			}
			ident, ok := target.(*ast.Ident)
			if !ok {
				return
			}
			obj := p.TypesInfo.Defs[ident]
			if obj == nil {
				obj = p.TypesInfo.Uses[ident]
			}
			v, ok := obj.(*types.Var)
			if !ok || v.Pkg() == nil || v.Parent() == v.Pkg().Scope() {
				return
			}
			if !typeHandsOutMutableReach(v.Type(), make(map[types.Type]bool)) {
				return
			}
			// Every mutable-reach source in the expression joins the
			// target's alias set - a multi-source binding (an append of
			// one slice onto another) shares each source's backing.
			ast.Inspect(sources, func(n ast.Node) bool {
				if src, ok := n.(*ast.Ident); ok {
					if o, ok := p.TypesInfo.Uses[src].(*types.Var); ok && o.Pkg() != nil && o.Parent() != o.Pkg().Scope() && !o.IsField() {
						if typeHandsOutMutableReach(o.Type(), make(map[types.Type]bool)) {
							edges = append(edges, [2]types.Object{v, o})
						}
					}
				}
				return true
			})
		}
		ast.Inspect(enclosing, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				if len(n.Lhs) == len(n.Rhs) {
					for i, lhs := range n.Lhs {
						aliasEdges(lhs, n.Rhs[i])
					}
				} else if len(n.Rhs) == 1 {
					for _, lhs := range n.Lhs {
						aliasEdges(lhs, n.Rhs[0])
					}
				}
			case *ast.ValueSpec:
				// A declaration binding aliases exactly as an assignment
				// binding does.
				if len(n.Names) == len(n.Values) {
					for i, name := range n.Names {
						aliasEdges(name, n.Values[i])
					}
				} else if len(n.Values) == 1 {
					for _, name := range n.Names {
						aliasEdges(name, n.Values[0])
					}
				}
			case *ast.RangeStmt:
				for _, bind := range []ast.Expr{n.Key, n.Value} {
					if bind != nil {
						aliasEdges(bind, n.X)
					}
				}
			case *ast.CallExpr:
				// A builtin copy aliases the destination's elements to the
				// source's backing without a binding statement.
				if ident, ok := n.Fun.(*ast.Ident); ok && len(n.Args) == 2 {
					if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && ident.Name == "copy" {
						aliasEdges(n.Args[0], n.Args[1])
					}
				}
			}
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
	if !boundValueLeakFreeJudged(p, roots, lit.Body, wants, nil, methodWants) {
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
			if shared && !boundValueLeakFreeJudged(p, roots, n.Body, wants, nil, methodWants) {
				sound = false
			}
			return false
		case *ast.GoStmt:
			ast.Inspect(n.Call, func(inner ast.Node) bool {
				if _, isLit := inner.(*ast.FuncLit); isLit {
					// Judged as a sibling literal by the enclosing walk.
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

// recordEnvCarryingRegistrations records, per dynamic-capable package
// variable (own or foreign), whether this package's direct code stores a
// function-carrying value into it that is not provably environment-free.
// A plain named function or a method expression carries no environment; a
// function literal is audited by environmentFreeFuncLit; nil carries
// nothing. Every other function-carrying value shape - a bound method
// value, a call result, a parameter, an opaque local or foreign variable -
// is beyond the audit and marks the carrier, fail-closed
// (REQ-closure-shared-dynamic-state). Stores inside nested literals and go
// statements are program code whose mutation marks refuse independently,
// so the audit walks only direct store sites; a store the mutation rules
// refuse anyway may record here too - the mutation culprit outranks this
// one at composition. One call shape defers instead of poisoning: a call
// of a plain named function records the callee against every store
// target in envCalls, its arguments judged recursively, for composition
// to resolve against the callee's return-environment-free proof -
// absence keeping the poison (REQ-closure-shared-dynamic-state).
func recordEnvCarryingRegistrations(p *packages.Package, envCarrying map[string]bool, envCalls map[string]map[string]bool) {
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
		if !typeMayCarryUnknownDynamic(variable.Type(), make(map[types.Type]bool)) {
			return nil, false
		}
		return variable, true
	}
	// localAliases maps, per walked body, each local binding chained from
	// a carrier - by assignment, declaration, range, address, or builtin
	// copy - to the carrier variables it may share backing with, so a
	// store through the alias is a store into the carrier.
	var localAliases map[types.Object][]*types.Var
	// targetVars collects every dynamic-capable package variable a store
	// target's subtree reaches - directly or through a local alias -
	// over-approximate exactly as the mutation marking is; a spurious
	// entry only keeps a carrier's conservative disposition.
	targetVars := func(expr ast.Expr) []*types.Var {
		var vars []*types.Var
		ast.Inspect(expr, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok {
				if obj, ok := resolve(ident); ok {
					if variable, ok := carrierVar(obj); ok {
						vars = append(vars, variable)
					} else {
						vars = append(vars, localAliases[obj]...)
					}
				}
			}
			return true
		})
		return vars
	}
	unparen := func(expr ast.Expr) ast.Expr {
		for {
			paren, ok := expr.(*ast.ParenExpr)
			if !ok {
				return expr
			}
			expr = paren.X
		}
	}
	computeLocalAliases := func(body ast.Node) map[types.Object][]*types.Var {
		aliased := map[types.Object][]*types.Var{}
		sourceVars := func(expr ast.Expr) []*types.Var {
			var vars []*types.Var
			ast.Inspect(expr, func(n ast.Node) bool {
				if _, isLit := n.(*ast.FuncLit); isLit {
					return false
				}
				if ident, ok := n.(*ast.Ident); ok {
					if obj, ok := resolve(ident); ok {
						if variable, ok := carrierVar(obj); ok {
							vars = append(vars, variable)
						} else {
							vars = append(vars, aliased[obj]...)
						}
					}
				}
				return true
			})
			return vars
		}
		bind := func(target ast.Expr, sources []*types.Var) bool {
			if len(sources) == 0 {
				return false
			}
			ident, ok := unparen(target).(*ast.Ident)
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
			if !typeHandsOutDynamicAlias(obj.Type(), make(map[types.Type]bool)) {
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
				switch n := n.(type) {
				case *ast.FuncLit, *ast.GoStmt:
					return false
				case *ast.AssignStmt:
					if len(n.Lhs) == len(n.Rhs) {
						for i, lhs := range n.Lhs {
							if bind(lhs, sourceVars(n.Rhs[i])) {
								changed = true
							}
						}
					} else if len(n.Rhs) == 1 {
						sources := sourceVars(n.Rhs[0])
						for _, lhs := range n.Lhs {
							if bind(lhs, sources) {
								changed = true
							}
						}
					}
				case *ast.ValueSpec:
					if len(n.Names) == len(n.Values) {
						for i, name := range n.Names {
							if bind(name, sourceVars(n.Values[i])) {
								changed = true
							}
						}
					} else if len(n.Values) == 1 {
						sources := sourceVars(n.Values[0])
						for _, name := range n.Names {
							if bind(name, sources) {
								changed = true
							}
						}
					}
				case *ast.RangeStmt:
					sources := sourceVars(n.X)
					for _, target := range []ast.Expr{n.Key, n.Value} {
						if target != nil && bind(target, sources) {
							changed = true
						}
					}
				case *ast.CallExpr:
					if ident, ok := unparen(n.Fun).(*ast.Ident); ok && len(n.Args) == 2 {
						if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && ident.Name == "copy" {
							if bind(n.Args[0], sourceVars(n.Args[1])) {
								changed = true
							}
						}
					}
				}
				return true
			})
		}
		return aliased
	}
	// enclosingBody is the function body whose direct stores are being
	// walked - the sibling-literal scope for the environment audit; nil
	// for package-level initializers, whose literals can capture nothing
	// function-scoped.
	var enclosingBody ast.Node
	// pendingEnvCalls collects, per store judgment, the plain named
	// callees whose return-environment-free proofs the store defers to.
	var pendingEnvCalls map[string]bool
	var carrying func(expr ast.Expr) bool
	carrying = func(expr ast.Expr) bool {
		switch e := unparen(expr).(type) {
		case *ast.CompositeLit:
			for _, elt := range e.Elts {
				value := elt
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					// Map keys cannot be function-typed (not comparable);
					// struct field keys are names, not values.
					value = kv.Value
				}
				if carrying(value) {
					return true
				}
			}
			return false
		case *ast.UnaryExpr:
			if e.Op == token.AND {
				return carrying(e.X)
			}
		case *ast.FuncLit:
			return !environmentFreeFuncLit(p, e, enclosingBody)
		case *ast.BasicLit:
			return false
		case *ast.CallExpr:
			// Builtin make and new construct empty or zero values - no
			// function value rides them; a plain named callee whose
			// result type carries a signature defers to the callee's
			// return-environment-free proof, its arguments judged
			// recursively (a carrying argument poisons the store); every
			// other call result stays an opaque source.
			if ident, ok := unparen(e.Fun).(*ast.Ident); ok {
				if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && (ident.Name == "make" || ident.Name == "new") {
					return false
				}
			}
			if pendingEnvCalls != nil && typeCarriesSignature(p.TypesInfo.TypeOf(unparen(expr)), make(map[types.Type]bool)) {
				if fn := plainNamedCalleeFn(p, e); fn != nil {
					for _, arg := range e.Args {
						if carrying(arg) {
							return true
						}
					}
					pendingEnvCalls[fn.Pkg().Path()+"\x00"+fn.Name()] = true
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
					// The receiver rides the value - an environment by
					// construction.
					return true
				}
				break
			}
			// A qualified identifier: pkg.Func carries no environment.
			if obj, ok := p.TypesInfo.Uses[e.Sel]; ok {
				if _, isFunc := obj.(*types.Func); isFunc {
					return false
				}
			}
		}
		// Everything else - a local, a parameter, a package variable, a
		// call result, an index or field read, a conversion - is an opaque
		// source: it carries exactly when its type can hand out a function
		// value.
		return typeCarriesSignature(p.TypesInfo.TypeOf(unparen(expr)), make(map[types.Type]bool))
	}
	handleStore := func(lhs, rhs ast.Expr, rebindable bool) {
		// A bare local identifier on the left of an assignment or
		// declaration is a rebinding of the local - the alias-creation
		// shape, not a store through the alias; only writes THROUGH an
		// alias (an index, field, or dereference whose base aliases a
		// carrier, a send, a copy destination, an append base) store
		// into it. Append and copy flows into the old binding's backing
		// are judged by their own store arms, never through this
		// exemption.
		if rebindable {
			if ident, ok := unparen(lhs).(*ast.Ident); ok {
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
		if call, ok := unparen(rhs).(*ast.CallExpr); ok && len(call.Args) > 0 {
			if ident, ok := unparen(call.Fun).(*ast.Ident); ok {
				if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && ident.Name == "append" {
					// Appending a carrier onto itself - bare or
					// package-qualified - flows only the new elements: the
					// existing contents were judged at their own store
					// sites. Appending anything else stays an opaque
					// source.
					var baseIdent *ast.Ident
					switch base := unparen(call.Args[0]).(type) {
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
		pendingEnvCalls = map[string]bool{}
		for _, flow := range flows {
			if carrying(flow) {
				poison = true
				break
			}
		}
		if poison {
			for _, variable := range targets {
				envCarrying[dynamicVarKey(variable)] = true
			}
		} else if envCalls != nil {
			for callee := range pendingEnvCalls {
				for _, variable := range targets {
					key := dynamicVarKey(variable)
					if envCalls[key] == nil {
						envCalls[key] = map[string]bool{}
					}
					envCalls[key][callee] = true
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
				if ident, ok := unparen(n.Fun).(*ast.Ident); ok {
					if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
						// A builtin copy into a carrier stores the copied
						// elements exactly as an assignment would; an
						// append writes its new elements into the base's
						// backing whenever capacity allows, whatever the
						// result is bound to - both judged at the call,
						// with the destination resolved through its
						// aliases.
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
						handleStore(lhs, n.Rhs[i], true)
					}
				} else if len(n.Rhs) == 1 {
					for _, lhs := range n.Lhs {
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

// plainNamedCalleeFn resolves a call's callee to a plain named function -
// a bare identifier or a package-qualified selector, receiverless,
// explicit generic instantiations included (the dependency key is
// instantiation-independent: the proof judges the generic body, type
// parameters falling to the signature walk's fail-closed default) - the
// one callee shape whose returns a persisted proof can audit.
func plainNamedCalleeFn(p *packages.Package, call *ast.CallExpr) *types.Func {
	fun := call.Fun
	for {
		switch f := fun.(type) {
		case *ast.ParenExpr:
			fun = f.X
			continue
		case *ast.IndexExpr:
			fun = f.X
			continue
		case *ast.IndexListExpr:
			fun = f.X
			continue
		}
		break
	}
	var obj types.Object
	switch fun := fun.(type) {
	case *ast.Ident:
		obj = p.TypesInfo.Uses[fun]
	case *ast.SelectorExpr:
		if x, ok := fun.X.(*ast.Ident); ok {
			if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
				obj = p.TypesInfo.Uses[fun.Sel]
			}
		}
	}
	fn, ok := obj.(*types.Func)
	if !ok || fn.Pkg() == nil {
		return nil
	}
	if sig, ok := fn.Type().(*types.Signature); !ok || sig.Recv() != nil {
		return nil
	}
	return fn
}

// returnEnvFreeFunctions proves, per plain named function of the
// package, that every value its return expressions can carry into a
// carrier is environment-free provided the call's arguments are - the
// constructor-result admission of the environment-free registration
// audit. Parameters judge free (the caller's obligation); a
// signature-carrying local judges by every source that binds it and
// every value stored into it, the derivation class admitting range
// bindings, field reads, appends, conversions, and multi-value binds,
// with names sharing mutable backing linked so breaks and stores
// propagate across them; a returned literal is audited exactly as a
// registered literal with the constructor body as its enclosing scope,
// its collected parameter and method wants resolving against this
// package's own facts only; a call of a plain named callee records a
// dependency edge resolved at composition, its arguments judged
// recursively. Naked returns and every unrecognized signature-carrying
// shape refuse the proof - absence keeps the poison
// (REQ-closure-shared-dynamic-state).
func returnEnvFreeFunctions(p *packages.Package, paramLeakFree, readOnly map[string]bool) (map[string]bool, map[string]map[string]bool) {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return nil, nil
	}
	ownPath := p.Types.Path()
	carries := func(t types.Type) bool {
		return typeCarriesSignature(t, make(map[types.Type]bool))
	}
	unparen := func(expr ast.Expr) ast.Expr {
		for {
			paren, ok := expr.(*ast.ParenExpr)
			if !ok {
				return expr
			}
			expr = paren.X
		}
	}
	wantsResolve := func(wants, methodWants map[string]bool) bool {
		for want := range wants {
			pkgPath, rest, ok := strings.Cut(want, "\x00")
			if !ok || pkgPath != ownPath || !paramLeakFree[rest] {
				return false
			}
		}
		for want := range methodWants {
			pkgPath, rest, ok := strings.Cut(want, "\x00")
			if !ok || pkgPath != ownPath || !readOnly[rest] {
				return false
			}
		}
		return true
	}
	proven := map[string]bool{}
	deps := map[string]map[string]bool{}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name == nil || fd.Body == nil || fd.Name.Name == "init" {
				continue
			}
			fnKey := fd.Name.Name
			params := map[types.Object]bool{}
			if fd.Type.Params != nil {
				for _, field := range fd.Type.Params.List {
					for _, name := range field.Names {
						if obj := p.TypesInfo.Defs[name]; obj != nil {
							params[obj] = true
						}
					}
				}
			}
			// Signature-carrying locals: collect whole-identifier binding
			// sources; container ranges and element, field, and
			// dereference writes have their own arms; copy refuses the
			// target outright. localBroken covers parameters too: a
			// reassigned parameter no longer holds the value the caller
			// judged, so the assumption breaks with it.
			localSources := map[types.Object][]ast.Expr{}
			// writeSources holds values stored through element, field,
			// or dereference writes into a tracked local's storage: the
			// local stays judged exactly when everything stored into it
			// judges. Keyed by the written chain's root; unioned across
			// each alias component before judgment, because a store
			// through any alias is a store into the same storage.
			writeSources := map[types.Object][]ast.Expr{}
			localBroken := map[types.Object]bool{}
			// aliasPairs links bindings that share mutable backing (a
			// whole-identifier bind of a reach-bearing tracked value):
			// a break through either name is a break of the storage, so
			// breaks propagate across the pairs to a fixed point.
			var aliasPairs [][2]types.Object
			trackedVar := func(obj types.Object) (*types.Var, bool) {
				v, ok := obj.(*types.Var)
				if !ok || v.Pkg() == nil || v.Parent() == v.Pkg().Scope() || !carries(v.Type()) {
					return nil, false
				}
				return v, true
			}
			// breakTargets breaks every tracked local or parameter an
			// expression subtree reaches - the fail-closed disposition
			// for address captures, whose write path the binding walk
			// cannot see.
			breakTargets := func(expr ast.Expr) {
				ast.Inspect(expr, func(n ast.Node) bool {
					if ident, ok := n.(*ast.Ident); ok {
						obj := p.TypesInfo.Uses[ident]
						if obj == nil {
							obj = p.TypesInfo.Defs[ident]
						}
						if obj != nil {
							if _, ok := trackedVar(obj); ok || params[obj] {
								localBroken[obj] = true
							}
						}
					}
					return true
				})
			}
			// chainRoot walks a written or addressed chain to its
			// terminal expression: selector, index, slice, and
			// dereference steps reach the base's storage, while their
			// operands are reads and stay judged.
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
			// breakBase breaks the written target's base binding. A
			// chain rooted at a non-ident (a call result, a composite)
			// still writes storage the root expression may reach -
			// fail-closed: every tracked name within the root breaks.
			breakBase := func(target ast.Expr) {
				breakTargets(chainRoot(target))
			}
			// linkBacking links a bound or written name to each
			// reach-bearing tracked name its source expression reaches -
			// whole identifiers, element reads, conversions, call
			// results, appends, and literals embedding a tracked value
			// alike. Conservative pairing is fail-closed: links feed
			// only break propagation, the store union, and the
			// parameter-component refusal - a spurious refusal at worst,
			// never a false Valid. Reach-free sources (a struct value's
			// scalar copy) stay unlinked as independent storage.
			linkBacking := func(obj types.Object, source ast.Expr) {
				ast.Inspect(source, func(m ast.Node) bool {
					id, ok := m.(*ast.Ident)
					if !ok {
						return true
					}
					sobj := p.TypesInfo.Uses[id]
					if sobj == nil {
						return true
					}
					// A selector's or literal key's field object denotes
					// no runtime value - linking it would conflate every
					// user of the field's struct type into one component.
					if v, ok := sobj.(*types.Var); ok && v.IsField() {
						return true
					}
					// Carrying parameters are themselves tracked, so
					// tracked alone covers every reach-relevant name.
					_, tracked := trackedVar(sobj)
					if tracked && typeHandsOutMutableReach(sobj.Type(), make(map[types.Type]bool)) {
						aliasPairs = append(aliasPairs, [2]types.Object{obj, sobj})
					}
					return true
				})
			}
			bindLocal := func(target ast.Expr, source ast.Expr, broken bool) {
				ident, ok := unparen(target).(*ast.Ident)
				if !ok {
					// An element, field, or dereference write of a
					// present value stores into the root's storage: the
					// value joins the root's write sources instead of
					// breaking it. A valueless or already-broken write
					// keeps the break; parameter storage - reached
					// directly or through any alias - breaks in the
					// component pass after the walk, the one
					// enforcement point for the parameter-write clause.
					if source != nil && !broken {
						if rootIdent, ok := chainRoot(target).(*ast.Ident); ok {
							robj := p.TypesInfo.Uses[rootIdent]
							if robj == nil {
								robj = p.TypesInfo.Defs[rootIdent]
							}
							if robj != nil {
								if _, tracked := trackedVar(robj); tracked {
									writeSources[robj] = append(writeSources[robj], source)
									// The store also makes the base's
									// storage reach the stored value's
									// backing - a later write through the
									// base's elements lands there.
									linkBacking(robj, source)
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
					// A parameter standing in any bind position no
					// longer holds the caller-judged value.
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
				// Append onto the binding itself flows only the new
				// elements: the existing contents were judged at their
				// own bind sites - the self-reference must not feed the
				// judgment cycle.
				if call, ok := unparen(source).(*ast.CallExpr); ok {
					if fnIdent, ok := unparen(call.Fun).(*ast.Ident); ok {
						if _, builtin := p.TypesInfo.Uses[fnIdent].(*types.Builtin); builtin && fnIdent.Name == "append" && len(call.Args) > 0 {
							if base, ok := unparen(call.Args[0]).(*ast.Ident); ok {
								if p.TypesInfo.Uses[base] == obj {
									// The appended elements' backing joins
									// the binding's storage exactly as any
									// bind source; only the self-reference
									// stays out of the judgment cycle.
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
					// An address capture opens a write path the binding
					// walk cannot see - the operand's base binding
					// breaks. A composite-literal operand addresses
					// fresh storage and breaks nothing.
					if n.Op == token.AND {
						if ident, ok := chainRoot(n.X).(*ast.Ident); ok {
							breakTargets(ident)
						}
					}
				case *ast.AssignStmt:
					if len(n.Lhs) == len(n.Rhs) {
						for i, lhs := range n.Lhs {
							bindLocal(lhs, n.Rhs[i], false)
						}
					} else if len(n.Rhs) == 1 {
						// A multi-value bind shares the one source: a
						// judged call's every result is judged.
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
					// A zero-valued declaration carries nothing.
				case *ast.RangeStmt:
					// A range binding derives from the ranged value only
					// for containers whose elements ARE the value -
					// slices, arrays, maps, strings, integers. A channel
					// receives sender-supplied values and a function
					// range receives yield-supplied ones; neither is part
					// of the judged operand, so those bindings break.
					// Writes through the binding still break it.
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
					// A pointer-receiver method use addresses its
					// receiver with no & in the syntax - a write path or
					// capture the binding walk cannot see. An in-package
					// receiver-read-only proof exempts it; everything
					// else breaks the base.
					if selection, ok := p.TypesInfo.Selections[n]; ok && selection.Kind() == types.MethodVal {
						if fn, ok := selection.Obj().(*types.Func); ok {
							if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
								if _, ptr := types.Unalias(sig.Recv().Type()).(*types.Pointer); ptr {
									pkgPath, rest, ok := strings.Cut(methodFactKey(fn), "\x00")
									if !ok || pkgPath != ownPath || !readOnly[rest] {
										breakBase(n.X)
									}
								}
							}
						}
					}
				case *ast.CallExpr:
					if ident, ok := unparen(n.Fun).(*ast.Ident); ok && len(n.Args) == 2 {
						if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && ident.Name == "copy" {
							bindLocal(n.Args[0], nil, true)
						}
					}
				}
				return true
			})
			// Breaks propagate across shared backing before any
			// judgment reads the map.
			for changed := true; changed; {
				changed = false
				for _, pair := range aliasPairs {
					if localBroken[pair[0]] != localBroken[pair[1]] {
						localBroken[pair[0]], localBroken[pair[1]] = true, true
						changed = true
					}
				}
			}
			// Stored values union across shared backing the same way: a
			// store through any alias is a store into the same storage,
			// so every member of an alias component answers for the
			// component's whole store set.
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
			// A store into a parameter's storage breaks outright - the
			// caller's storage mutates under the caller's judgment - and
			// the storage is reached through any alias of the parameter,
			// not only its own name. A component that contains a
			// parameter and received any store breaks whole; the
			// parameter's own judgment reads localBroken, so every
			// member is marked directly (components are maximal - no
			// further propagation exists).
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
			fnDeps := map[string]bool{}
			var free func(expr ast.Expr) bool
			localFree := map[types.Object]int{} // 0 unknown, 1 proving, 2 free, 3 refused
			var judgeLocal func(obj types.Object) bool
			judgeLocal = func(obj types.Object) bool {
				switch localFree[obj] {
				case 2:
					return true
				case 3:
					return false
				case 1:
					// A cyclic binding cannot ground - fail-closed.
					return false
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
				// A signature-free value carries nothing; the signature
				// walk is fail-closed on unfamiliar kinds (a multi-value
				// call's tuple included), which keeps those falling
				// through to the shape arms below.
				if t := p.TypesInfo.TypeOf(e); t != nil && !carries(t) {
					return true
				}
				switch e := e.(type) {
				case *ast.BasicLit:
					return true
				case *ast.CompositeLit:
					for _, elt := range e.Elts {
						value := elt
						if kv, ok := elt.(*ast.KeyValueExpr); ok {
							value = kv.Value
						}
						if !free(value) {
							return false
						}
					}
					return true
				case *ast.UnaryExpr:
					if e.Op == token.AND {
						return free(e.X)
					}
				case *ast.FuncLit:
					wants := map[string]bool{}
					methodWants := map[string]bool{}
					if !environmentFreeFuncLitJudged(p, e, fd.Body, wants, methodWants) {
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
							// The caller judged the entry value; a broken
							// parameter (reassigned, address-captured)
							// no longer holds it.
							return !localBroken[obj]
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
						// A field read of a judged value is judged: the
						// field is part of what the caller or the source
						// judgment already covered.
						return free(e.X)
					}
					if obj, ok := p.TypesInfo.Uses[e.Sel]; ok {
						if _, isFunc := obj.(*types.Func); isFunc {
							return true
						}
					}
					return false
				case *ast.IndexExpr:
					// An instantiated function reference (a generic named
					// function used as a value) carries no environment;
					// element reads are not a chartered derivation and
					// keep the refusal.
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
				case *ast.IndexListExpr:
					// The multi-type-argument spelling of the same
					// instantiated reference.
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
								// Judged elements onto a judged base stay
								// judged.
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
						// A conversion of a judged value is judged: the
						// value is the same, under a different name.
						return len(e.Args) == 1 && free(e.Args[0])
					}
					if fn := plainNamedCalleeFn(p, e); fn != nil {
						for _, arg := range e.Args {
							if !free(arg) {
								return false
							}
						}
						fnDeps[fn.Pkg().Path()+"\x00"+fn.Name()] = true
						return true
					}
					return false
				}
				return false
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
					// A naked return hands out the named result variables
					// past this judgment's flow - refuse.
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
		}
	}
	return proven, deps
}

// initOnlyReachableHelpers computes, by package-local fixed point, the
// unexported plain functions whose every reference in the package is a
// call from an initializer expression, an init body, or another
// qualified helper - functions no non-init root can reach, so their
// bodies are init flow (REQ-closure-shared-dynamic-state). Any value
// reference, any receiver, any export, any generic reference shape the
// scan does not recognize as a direct call, or any reference from
// ordinary program code refuses the class - fail-closed.
func initOnlyReachableHelpers(p *packages.Package) map[string]bool {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return nil
	}
	candidates := map[string]bool{}
	bodies := map[string]*ast.FuncDecl{}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name == nil || fd.Name.Name == "init" {
				continue
			}
			if fd.Name.IsExported() {
				continue
			}
			candidates[fd.Name.Name] = true
			bodies[fd.Name.Name] = fd
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	isCandidateFunc := func(ident *ast.Ident) (string, bool) {
		obj, ok := p.TypesInfo.Uses[ident]
		if !ok {
			return "", false
		}
		fn, ok := obj.(*types.Func)
		if !ok || fn.Pkg() == nil || fn.Pkg() != p.Types || fn.Type().(*types.Signature).Recv() != nil {
			return "", false
		}
		if !candidates[fn.Name()] {
			return "", false
		}
		return fn.Name(), true
	}
	// references[caller] lists candidate names referenced from region
	// caller; "" is the init region (initializer expressions and init
	// bodies), "!" the ordinary-program region. A non-call reference
	// anywhere disqualifies immediately.
	disqualified := map[string]bool{}
	references := map[string]map[string]bool{}
	addRef := func(region, name string) {
		if references[region] == nil {
			references[region] = map[string]bool{}
		}
		references[region][name] = true
	}
	var scanRegion func(region string, root ast.Node)
	scanRegion = func(region string, root ast.Node) {
		calls := map[*ast.Ident]bool{}
		ast.Inspect(root, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit:
				// A nested literal is program code whatever encloses
				// it - its references never count as init flow.
				if n != root && n.Body != nil {
					scanRegion("!", n.Body)
					return false
				}
			case *ast.GoStmt:
				// A go-statement callee runs concurrently with program
				// code even when launched from init - never init flow.
				scanRegion("!", n.Call)
				return false
			case *ast.CallExpr:
				if ident, ok := n.Fun.(*ast.Ident); ok {
					if _, is := isCandidateFunc(ident); is {
						calls[ident] = true
					}
				}
			case *ast.Ident:
				if name, is := isCandidateFunc(n); is {
					if calls[n] {
						addRef(region, name)
					} else {
						disqualified[name] = true
					}
				}
			}
			return true
		})
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				switch {
				case decl.Recv == nil && decl.Name != nil && decl.Name.Name == "init":
					if decl.Body != nil {
						scanRegion("", decl.Body)
					}
				case decl.Recv == nil && decl.Name != nil && candidates[decl.Name.Name]:
					if decl.Body != nil {
						scanRegion(decl.Name.Name, decl.Body)
					}
				default:
					if decl.Body != nil {
						scanRegion("!", decl.Body)
					}
				}
			default:
				scanRegion("", decl)
			}
		}
	}
	for name := range references["!"] {
		disqualified[name] = true
	}
	// Fixed point: a disqualified helper's body is ordinary program
	// code, so its references disqualify in turn.
	for changed := true; changed; {
		changed = false
		for caller, refs := range references {
			if caller == "" || caller == "!" || !disqualified[caller] {
				continue
			}
			for name := range refs {
				if !disqualified[name] {
					disqualified[name] = true
					changed = true
				}
			}
		}
	}
	qualified := map[string]bool{}
	for name := range candidates {
		if disqualified[name] {
			continue
		}
		// Only helpers actually referenced from init flow (directly or
		// through qualified helpers) matter; an unreferenced helper is
		// dead code either way and stays program code fail-closed.
		qualified[name] = true
	}
	// Keep only helpers reachable from the init region through
	// qualified callers - an unexported helper called from nowhere
	// stays ordinary program code.
	reachable := map[string]bool{}
	var mark func(region string)
	mark = func(region string) {
		for name := range references[region] {
			if qualified[name] && !reachable[name] {
				reachable[name] = true
				mark(name)
			}
		}
	}
	mark("")
	return reachable
}

// boundValueLeakFree proves that every value bound from the given root
// objects stays inside body: no write through a root-reachable binding,
// no address capture, send, or channel receive, no method call except
// the audited synchronization set, no call-argument handout, no return,
// and — unlike the receiver engine's enumerated arms — a catch-all
// ident visit that disqualifies any appearance no allowed shape
// consumed, so an unrecognized use fails closed rather than open.
// Field and index reads are allowed when the produced type hands out no
// mutable reach, or in a tainting assignment where the binding stays
// tracked; len, cap, and comparison are writeless reads.
// boundValueLeakFree proves with every unproven shape refusing outright;
// boundValueLeakFreeDeferred additionally lets a rooted argument to a
// plain named function defer to that parameter's leak-free fact - the
// wants set collects the parameter keys (package path, function name,
// zero-based index NUL-joined) the proof relies on, for the caller to
// resolve or carry as deferred marks; a go statement's arguments never
// defer, the goroutine runs concurrently
// (REQ-closure-shared-dynamic-state).
func boundValueLeakFree(p *packages.Package, roots map[types.Object]bool, body ast.Node) bool {
	return boundValueLeakFreeJudged(p, roots, body, nil, nil, nil)
}

func boundValueLeakFreeDeferred(p *packages.Package, roots map[types.Object]bool, body ast.Node, wants map[string]bool) bool {
	return boundValueLeakFreeJudged(p, roots, body, wants, nil, nil)
}

// boundValueLeakFreeJudged additionally tolerates return-position handouts
// when the caller supplies a returns collector - a rooted alias-handing
// result consumes and sets the flag instead of refusing, for the
// returned-binding disposition to judge the function's own callers - and,
// when the caller supplies a methodWants collector, defers a method call
// on a bound value to that method's receiver-read-only fact: non-interface
// receivers only, the call's instantiated results handing out no mutable
// reach, never from a go statement's subtree; the collected method keys
// ride the carrier's deferred method-use marks, an unproven method marking
// mutation fail-closed at composition.
func boundValueLeakFreeJudged(p *packages.Package, roots map[types.Object]bool, body ast.Node, wants map[string]bool, returns *bool, methodWants map[string]bool) bool {
	if p == nil || p.TypesInfo == nil || body == nil || len(roots) == 0 {
		return false
	}
	// Every call within a go statement's subtree runs concurrently with
	// the walked body - a call wrapped in a goroutine literal exactly as
	// the direct spelling - so none of them defers.
	goCalls := map[*ast.CallExpr]bool{}
	litReturns := map[*ast.ReturnStmt]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.GoStmt:
			ast.Inspect(n, func(inner ast.Node) bool {
				if call, ok := inner.(*ast.CallExpr); ok {
					goCalls[call] = true
				}
				return true
			})
		case *ast.FuncLit:
			// A return inside a nested literal exits the literal, not
			// the judged function - its handout goes to whoever calls
			// the literal, never to the returned-binding disposition.
			ast.Inspect(n, func(inner ast.Node) bool {
				if ret, ok := inner.(*ast.ReturnStmt); ok {
					litReturns[ret] = true
				}
				return true
			})
			return false
		}
		return true
	})
	tainted := map[types.Object]bool{}
	isRoot := func(expr ast.Expr) bool {
		ident, ok := expr.(*ast.Ident)
		if !ok {
			return false
		}
		obj := p.TypesInfo.Uses[ident]
		if obj == nil {
			obj = p.TypesInfo.Defs[ident]
		}
		return obj != nil && (roots[obj] || tainted[obj])
	}
	var rooted func(expr ast.Expr) bool
	rooted = func(expr ast.Expr) bool {
		switch expr := expr.(type) {
		case *ast.Ident:
			return isRoot(expr)
		case *ast.SelectorExpr:
			return rooted(expr.X)
		case *ast.IndexExpr:
			return rooted(expr.X)
		case *ast.StarExpr:
			return rooted(expr.X)
		case *ast.ParenExpr:
			return rooted(expr.X)
		default:
			return false
		}
	}
	bindObj := func(ident *ast.Ident) types.Object {
		if obj := p.TypesInfo.Defs[ident]; obj != nil {
			return obj
		}
		return p.TypesInfo.Uses[ident]
	}
	for changed := true; changed; {
		changed = false
		taint := func(ident *ast.Ident) {
			obj := bindObj(ident)
			if obj == nil || roots[obj] || tainted[obj] {
				return
			}
			if !typeHandsOutMutableReach(obj.Type(), make(map[types.Type]bool)) {
				return
			}
			tainted[obj] = true
			changed = true
		}
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				if len(n.Lhs) == len(n.Rhs) {
					for i, rhs := range n.Rhs {
						if !rooted(rhs) {
							continue
						}
						if ident, ok := n.Lhs[i].(*ast.Ident); ok {
							taint(ident)
						}
					}
				} else if len(n.Rhs) == 1 && rooted(n.Rhs[0]) {
					for _, lhs := range n.Lhs {
						if ident, ok := lhs.(*ast.Ident); ok {
							taint(ident)
						}
					}
				}
			case *ast.RangeStmt:
				if rooted(n.X) {
					for _, bind := range []ast.Expr{n.Key, n.Value} {
						if ident, ok := bind.(*ast.Ident); ok {
							taint(ident)
						}
					}
				}
			case *ast.ValueSpec:
				if len(n.Names) == len(n.Values) {
					for i, rhs := range n.Values {
						if rooted(rhs) {
							taint(n.Names[i])
						}
					}
				} else if len(n.Values) == 1 && rooted(n.Values[0]) {
					for _, name := range n.Names {
						taint(name)
					}
				}
			}
			return true
		})
	}
	allowed := map[ast.Node]bool{}
	var rootIdent func(expr ast.Expr) *ast.Ident
	rootIdent = func(expr ast.Expr) *ast.Ident {
		switch expr := expr.(type) {
		case *ast.Ident:
			return expr
		case *ast.SelectorExpr:
			return rootIdent(expr.X)
		case *ast.IndexExpr:
			return rootIdent(expr.X)
		case *ast.StarExpr:
			return rootIdent(expr.X)
		case *ast.ParenExpr:
			return rootIdent(expr.X)
		default:
			return nil
		}
	}
	consume := func(expr ast.Expr) {
		if ident := rootIdent(expr); ident != nil {
			allowed[ident] = true
		}
	}
	// methodValueBind reports a method-value selector: binding one captures
	// its receiver inside a func value the reach classification cannot see
	// (Signature hands out nothing), so every position except the immediate
	// call refuses (REQ-closure-shared-dynamic-state).
	methodValueBind := func(expr ast.Expr) bool {
		for {
			paren, ok := expr.(*ast.ParenExpr)
			if !ok {
				break
			}
			expr = paren.X
		}
		sel, ok := expr.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		selection, ok := p.TypesInfo.Selections[sel]
		return ok && selection.Kind() == types.MethodVal
	}
	leaky := false
	ast.Inspect(body, func(n ast.Node) bool {
		if leaky {
			return false
		}
		switch n := n.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) == len(n.Rhs) {
				for i, rhs := range n.Rhs {
					if rooted(rhs) {
						if methodValueBind(rhs) {
							leaky = true
						} else if _, ok := n.Lhs[i].(*ast.Ident); ok {
							consume(rhs)
						}
					}
				}
			} else if len(n.Rhs) == 1 && rooted(n.Rhs[0]) {
				if methodValueBind(n.Rhs[0]) {
					leaky = true
				} else {
					allIdent := true
					for _, lhs := range n.Lhs {
						if _, ok := lhs.(*ast.Ident); !ok {
							allIdent = false
						}
					}
					if allIdent {
						consume(n.Rhs[0])
					}
				}
			}
			for _, lhs := range n.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok {
					// A tracked binding into an object declared inside
					// the walked body stays inside the proof - every
					// later use keeps the arms. Anything else - a
					// package variable, or a local declared outside a
					// walked loop body - retains the alias beyond the
					// arms' view, fail-closed.
					if obj := bindObj(ident); obj != nil && (roots[obj] || tainted[obj]) {
						if obj.Pos() < body.Pos() || obj.Pos() > body.End() {
							leaky = true
						}
					}
					consume(ident)
					continue
				}
				if rooted(lhs) {
					leaky = true
				}
			}
		case *ast.ValueSpec:
			// A declaration binding inside the body tracks exactly like
			// an assignment binding - the names are fresh in-body
			// objects, so no retention check applies.
			if len(n.Names) == len(n.Values) {
				for i, rhs := range n.Values {
					if rooted(rhs) {
						if methodValueBind(rhs) {
							leaky = true
							continue
						}
						consume(rhs)
						allowed[n.Names[i]] = true
					}
				}
			} else if len(n.Values) == 1 && rooted(n.Values[0]) {
				if methodValueBind(n.Values[0]) {
					leaky = true
				} else {
					consume(n.Values[0])
					for _, name := range n.Names {
						allowed[name] = true
					}
				}
			}
		case *ast.IncDecStmt:
			if rooted(n.X) {
				leaky = true
			}
		case *ast.SendStmt:
			if rooted(n.Chan) {
				leaky = true
			}
		case *ast.UnaryExpr:
			if (n.Op == token.AND || n.Op == token.ARROW) && rooted(n.X) {
				leaky = true
			}
		case *ast.RangeStmt:
			if rooted(n.X) {
				if t := p.TypesInfo.TypeOf(n.X); t == nil {
					leaky = true
				} else if _, isChan := types.Unalias(t).Underlying().(*types.Chan); isChan {
					leaky = true
				} else {
					for _, bind := range []ast.Expr{n.Key, n.Value} {
						if ident, ok := bind.(*ast.Ident); ok {
							consume(ident)
						} else if bind != nil {
							leaky = true
						}
					}
					consume(n.X)
				}
			}
		case *ast.ReturnStmt:
			// A rooted result whose type hands out no mutable reach is a
			// copied scalar - it cannot alias the carrier; anything else
			// hands the alias to the caller - refused outright, or
			// collected for the returned-binding disposition when the
			// caller judges the handout's own consumers.
			for _, result := range n.Results {
				if rooted(result) {
					if t := p.TypesInfo.TypeOf(result); t == nil || typeHandsOutMutableReach(t, make(map[types.Type]bool)) {
						if returns != nil && t != nil && !litReturns[n] && !methodValueBind(result) {
							*returns = true
							consume(result)
						} else {
							leaky = true
						}
					} else if methodValueBind(result) {
						leaky = true
					} else {
						consume(result)
					}
				}
			}
		case *ast.CallExpr:
			if ident, ok := n.Fun.(*ast.Ident); ok {
				if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && (ident.Name == "len" || ident.Name == "cap") {
					for _, arg := range n.Args {
						if rooted(arg) {
							consume(arg)
						}
					}
					break
				}
			}
			if sel, ok := n.Fun.(*ast.SelectorExpr); ok && rooted(sel.X) {
				selection, selOK := p.TypesInfo.Selections[sel]
				if selOK && selection.Kind() == types.MethodVal {
					fn, isFunc := selection.Obj().(*types.Func)
					if isFunc && auditedSynchronization(fn) {
						consume(sel.X)
						break
					}
					// A method call on a bound value defers to the
					// method's receiver-read-only fact: statically
					// dispatched, results handing out no mutable reach,
					// never concurrently - mirroring the carrier-receiver
					// deferral, resolved through the same marks.
					if isFunc && methodWants != nil && !goCalls[n] && fn.Pkg() != nil && !interfaceReceiver(fn) && instantiatedResultsHandOutNothing(selection.Type()) {
						methodWants[methodFactKey(fn)] = true
						consume(sel.X)
					} else {
						leaky = true
					}
				} else if selOK && selection.Kind() == types.FieldVal {
					// A func-typed field invoked through the binding hands
					// the callee only its arguments - judged by the
					// argument loop below like any call; the target itself
					// is a field read, judged by the selector arm on the
					// child visit. The callee's own effects, including
					// writes through its closure environment, are priced by
					// the observation composition's callee enumeration, not
					// by this binding proof.
				} else {
					leaky = true
				}
			}
			// A rooted argument whose type hands out no mutable reach is
			// a copied scalar - the callee cannot reach the carrier
			// through it; an alias-handing rooted argument to a plain
			// named function defers to that parameter's leak-free fact
			// when the caller collects wants - never from a go
			// statement's call, the goroutine runs concurrently.
			for i, arg := range n.Args {
				if rooted(arg) {
					if t := p.TypesInfo.TypeOf(arg); t == nil || typeHandsOutMutableReach(t, make(map[types.Type]bool)) {
						deferred := false
						if wants != nil && !goCalls[n] {
							if fn, pkgPath := plainCalleeFunc(p, n.Fun); fn != nil {
								if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() == nil && sig.Params().Len() > 0 {
									idx := i
									if sig.Variadic() && idx >= sig.Params().Len()-1 {
										idx = sig.Params().Len() - 1
									}
									wants[pkgPath+"\x00"+fn.Name()+"\x00"+strconv.Itoa(idx)] = true
									consume(arg)
									deferred = true
								}
							}
						}
						if !deferred {
							leaky = true
						}
					} else if methodValueBind(arg) {
						leaky = true
					} else {
						consume(arg)
					}
				}
			}
		case *ast.IndexExpr:
			if rooted(n.X) && !allowed[rootIdent(n.X)] {
				if t := p.TypesInfo.TypeOf(n); t == nil || typeHandsOutMutableReach(t, make(map[types.Type]bool)) {
					leaky = true
				} else {
					consume(n.X)
				}
			}
		case *ast.SelectorExpr:
			if isRoot(n.X) && !allowed[rootIdent(n.X)] {
				if selection, ok := p.TypesInfo.Selections[n]; ok && selection.Kind() == types.MethodVal {
					break
				}
				if t := p.TypesInfo.TypeOf(n); t == nil || typeHandsOutMutableReach(t, make(map[types.Type]bool)) {
					leaky = true
				} else {
					consume(n.X)
				}
			}
		case *ast.BinaryExpr:
			if n.Op == token.EQL || n.Op == token.NEQ {
				if rooted(n.X) {
					consume(n.X)
				}
				if rooted(n.Y) {
					consume(n.Y)
				}
			}
		case *ast.Ident:
			// The catch-all: any tracked appearance no allowed shape
			// consumed is an unrecognized use - fail-closed.
			if !allowed[n] && isRoot(n) {
				leaky = true
			}
		}
		return true
	})
	return !leaky
}

// paramLeakFreeFunctions proves, per plain named function, which
// parameters demonstrably leak nothing: the bound value never writes,
// escapes, or outlives the call per boundValueLeakFree. Keys are
// "name\x00index"; the fact layer prefixes the package path. Blank and
// unnamed parameters cannot be referenced and are leak-free by
// construction; parameters whose type hands out no mutable reach are
// omitted - no carrier can flow into them.
func paramLeakFreeFunctions(p *packages.Package, readOnlyLocal map[string]bool) map[string]bool {
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	proven := map[string]bool{}
	// A parameter's proof may rely on sibling parameters: a rooted
	// argument handed to another plain named function in the same
	// package chains when that parameter proves leak-free - an
	// intra-package fixed point, mutual recursion refusing, any
	// cross-package want unproven at fact time (the range discharge
	// carries those as deferred marks instead; a fact-side chain stays
	// package-local, fail-closed).
	conditional := map[string]map[string]bool{}
	ownPath := ""
	if p.Types != nil {
		ownPath = p.Types.Path()
	}
	// Method wants at fact time resolve against the package's own
	// receiver-read-only fixed point, computed once by the fact assembly;
	// a cross-package method want leaves the parameter unproven exactly
	// as a cross-package parameter want does - the range discharge
	// carries those as deferred marks instead.
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name == nil || fd.Body == nil || fd.Type.Params == nil {
				continue
			}
			index := 0
			for _, field := range fd.Type.Params.List {
				names := field.Names
				if len(names) == 0 {
					names = []*ast.Ident{nil}
				}
				for _, name := range names {
					idx := index
					index++
					if name == nil || name.Name == "_" {
						proven[fd.Name.Name+"\x00"+strconv.Itoa(idx)] = true
						continue
					}
					obj := p.TypesInfo.Defs[name]
					if obj == nil {
						continue
					}
					if !typeHandsOutMutableReach(obj.Type(), make(map[types.Type]bool)) {
						continue
					}
					wants := map[string]bool{}
					methodWants := map[string]bool{}
					if !boundValueLeakFreeJudged(p, map[types.Object]bool{obj: true}, fd.Body, wants, nil, methodWants) {
						continue
					}
					methodsProven := true
					for want := range methodWants {
						pkgPath, rest, ok := strings.Cut(want, "\x00")
						if !ok || pkgPath != ownPath || !readOnlyLocal[rest] {
							methodsProven = false
							break
						}
					}
					if !methodsProven {
						continue
					}
					key := fd.Name.Name + "\x00" + strconv.Itoa(idx)
					if len(wants) == 0 {
						proven[key] = true
						continue
					}
					local := map[string]bool{}
					crossPackage := false
					for want := range wants {
						pkgPath, rest, ok := strings.Cut(want, "\x00")
						if !ok || pkgPath != ownPath {
							crossPackage = true
							break
						}
						local[rest] = true
					}
					if !crossPackage {
						conditional[key] = local
					}
				}
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for key, needs := range conditional {
			if proven[key] {
				continue
			}
			ok := true
			for need := range needs {
				if !proven[need] {
					ok = false
					break
				}
			}
			if ok {
				proven[key] = true
				changed = true
			}
		}
	}
	return proven
}

// receiverReadOnlyMethods proves, in the declaring package alone, which
// methods cannot write receiver-reachable state: the receiver never
// stands in a write position (assignment target, inc/dec, send,
// address capture), never escapes (argument, return, store, binding,
// or any unrecognized use), and chains only into sibling methods
// already proven read-only - an intra-package fixed point, fail-closed
// on every other shape, cross-package chains included
// (REQ-closure-shared-dynamic-state). Keys are "Recv.Method"; the fact
// layer prefixes the package path.
func receiverReadOnlyMethods(p *packages.Package) map[string]bool {
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	type methodBody struct {
		decl *ast.FuncDecl
		recv *ast.Ident
	}
	methods := map[string]methodBody{}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Name == nil || fd.Body == nil || len(fd.Recv.List) != 1 {
				continue
			}
			recvName := recvTypeName(fd)
			if recvName == "" {
				continue
			}
			var recvIdent *ast.Ident
			if names := fd.Recv.List[0].Names; len(names) == 1 && names[0].Name != "_" {
				recvIdent = names[0]
			}
			// A blank or anonymous receiver cannot be referenced: the
			// body cannot write receiver state at all.
			methods[recvName+"."+fd.Name.Name] = methodBody{decl: fd, recv: recvIdent}
		}
	}
	if len(methods) == 0 {
		return nil
	}
	// chains[m] lists sibling method keys m's receiver chains into;
	// disqualified[m] marks a demonstrated write or escape.
	disqualified := map[string]bool{}
	chains := map[string]map[string]bool{}
	for key, m := range methods {
		if m.recv == nil {
			continue
		}
		recvObj := p.TypesInfo.Defs[m.recv]
		if recvObj == nil {
			disqualified[key] = true
			continue
		}
		// tainted tracks locals bound from receiver-reachable values:
		// writes through them are receiver writes, escapes of them are
		// receiver escapes, and only return position hands them out -
		// where the call site judges the instantiated result types
		// (REQ-closure-shared-dynamic-state).
		tainted := map[types.Object]bool{}
		isRecv := func(expr ast.Expr) bool {
			ident, ok := expr.(*ast.Ident)
			if !ok {
				return false
			}
			obj := p.TypesInfo.Uses[ident]
			return obj == recvObj || (obj != nil && tainted[obj])
		}
		// recvRooted reports whether the expression is the receiver or
		// a field-selector chain rooted at it.
		var recvRooted func(expr ast.Expr) bool
		recvRooted = func(expr ast.Expr) bool {
			switch expr := expr.(type) {
			case *ast.Ident:
				return isRecv(expr)
			case *ast.SelectorExpr:
				return recvRooted(expr.X)
			case *ast.IndexExpr:
				return recvRooted(expr.X)
			case *ast.StarExpr:
				return recvRooted(expr.X)
			case *ast.ParenExpr:
				return recvRooted(expr.X)
			default:
				return false
			}
		}
		// Pass 1 - taint collection to a fixpoint, flow-insensitive:
		// a loop-carried binding taints regardless of source order, an
		// assign-form range binding resolves through Uses, and a
		// sibling-chain call whose instantiated results hand out
		// mutable reach taints what binds it
		// (REQ-closure-shared-dynamic-state).
		siblingLeaky := func(sel *ast.SelectorExpr) (bool, bool) {
			selection, ok := p.TypesInfo.Selections[sel]
			if !ok || selection.Kind() != types.MethodVal {
				return false, false
			}
			fn, ok := selection.Obj().(*types.Func)
			if !ok || fn.Pkg() != p.Types {
				return false, false
			}
			if _, sibling := methods[recvTypeNameOf(p, sel)+"."+fn.Name()]; !sibling {
				return false, false
			}
			return true, !instantiatedResultsHandOutNothing(selection.Type())
		}
		// rhsHandsReceiverValue reports whether the expression hands a
		// receiver-reachable value to its binding: a receiver-rooted
		// chain, or a leaky sibling call.
		rhsHandsReceiverValue := func(rhs ast.Expr) bool {
			if recvRooted(rhs) {
				return true
			}
			if call, ok := rhs.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && recvRooted(sel.X) {
					if _, leaky := siblingLeaky(sel); leaky {
						return true
					}
				}
			}
			return false
		}
		bindObj := func(ident *ast.Ident) types.Object {
			if obj := p.TypesInfo.Defs[ident]; obj != nil {
				return obj
			}
			return p.TypesInfo.Uses[ident]
		}
		for changed := true; changed; {
			changed = false
			taint := func(ident *ast.Ident) {
				// A binding whose type hands out no mutable reach can
				// never write receiver state - it stays untainted, so
				// value reads flow freely (REQ-closure-shared-dynamic-state).
				obj := bindObj(ident)
				if obj == nil || obj == recvObj || tainted[obj] {
					return
				}
				if !typeHandsOutMutableReach(obj.Type(), make(map[types.Type]bool)) {
					return
				}
				tainted[obj] = true
				changed = true
			}
			ast.Inspect(m.decl.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.AssignStmt:
					// Per-position pairing: each receiver-reachable RHS
					// taints exactly its own binding; a multi-value
					// leaky sibling call taints every binding.
					if len(n.Lhs) == len(n.Rhs) {
						for i, rhs := range n.Rhs {
							if !rhsHandsReceiverValue(rhs) {
								continue
							}
							if ident, ok := n.Lhs[i].(*ast.Ident); ok {
								taint(ident)
							}
						}
					} else if len(n.Rhs) == 1 && rhsHandsReceiverValue(n.Rhs[0]) {
						for _, lhs := range n.Lhs {
							if ident, ok := lhs.(*ast.Ident); ok {
								taint(ident)
							}
						}
					}
				case *ast.RangeStmt:
					if recvRooted(n.X) {
						for _, bind := range []ast.Expr{n.Key, n.Value} {
							if ident, ok := bind.(*ast.Ident); ok {
								taint(ident)
							}
						}
					}
				}
				return true
			})
		}
		allowed := map[ast.Node]bool{}
		governedCalls := map[*ast.CallExpr]bool{}
		var rootIdent func(expr ast.Expr) *ast.Ident
		rootIdent = func(expr ast.Expr) *ast.Ident {
			switch expr := expr.(type) {
			case *ast.Ident:
				return expr
			case *ast.SelectorExpr:
				return rootIdent(expr.X)
			case *ast.IndexExpr:
				return rootIdent(expr.X)
			case *ast.StarExpr:
				return rootIdent(expr.X)
			case *ast.ParenExpr:
				return rootIdent(expr.X)
			default:
				return nil
			}
		}
		consume := func(expr ast.Expr) {
			if ident := rootIdent(expr); ident != nil {
				allowed[ident] = true
			}
		}
		methodValueBind := func(expr ast.Expr) bool {
			for {
				paren, ok := expr.(*ast.ParenExpr)
				if !ok {
					break
				}
				expr = paren.X
			}
			sel, ok := expr.(*ast.SelectorExpr)
			if !ok {
				return false
			}
			selection, ok := p.TypesInfo.Selections[sel]
			return ok && selection.Kind() == types.MethodVal
		}
		// escapingSink reports whether a bind target outlives the body
		// with mutable reach: a package-level variable retains its value
		// past the proof's horizon, so a reach-bearing bind there is an
		// escape however the value arrived - the tracked-binding
		// discipline covers only sinks that die with the body. A
		// reach-free sink keeps a copy that cannot write back and flows
		// freely.
		escapingSink := func(ident *ast.Ident) bool {
			if p.Types == nil {
				return true
			}
			obj := bindObj(ident)
			// Any package's scope, not just the loading package's: a
			// dot-imported variable is the same outliving sink under a
			// bare name.
			return obj != nil && obj.Pkg() != nil && obj.Parent() == obj.Pkg().Scope() && typeHandsOutMutableReach(obj.Type(), make(map[types.Type]bool))
		}
		// A return inside a nested function literal is not the method's
		// return position: the literal value outlives the body carrying
		// what it captured, and the call-site result judgment cannot see
		// through a signature, so a receiver-reachable result there is
		// an escape (REQ-closure-shared-dynamic-state).
		innerReturns := map[*ast.ReturnStmt]bool{}
		ast.Inspect(m.decl.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.FuncLit)
			if !ok {
				return true
			}
			ast.Inspect(lit.Body, func(inner ast.Node) bool {
				if r, ok := inner.(*ast.ReturnStmt); ok {
					innerReturns[r] = true
				}
				return true
			})
			return false
		})
		ast.Inspect(m.decl.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				// Taint was collected to a fixpoint in pass 1; here the
				// tainting shapes only consume - the value stays
				// tracked, so writes through it and escapes of it are
				// still the receiver's (REQ-closure-shared-dynamic-state).
				// A sibling call is governed only when its binding is
				// an ident that pass 1 actually tainted (blank
				// included - the value is discarded); any other LHS
				// shape leaves the call ungoverned and the sibling
				// arm's escape refusal fires.
				governRHS := func(i int, rhs ast.Expr) {
					call, ok := rhs.(*ast.CallExpr)
					if !ok {
						return
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || !recvRooted(sel.X) {
						return
					}
					if sibling, _ := siblingLeaky(sel); !sibling {
						return
					}
					// A sink target must not be governed into a consume: an
					// ungoverned leaky sibling call keeps the escape
					// refusal, which is exactly what a reach-bearing bind
					// to an outliving target is.
					if i >= 0 {
						ident, ok := n.Lhs[i].(*ast.Ident)
						if !ok || escapingSink(ident) {
							return
						}
					} else {
						for _, lhs := range n.Lhs {
							ident, ok := lhs.(*ast.Ident)
							if !ok || escapingSink(ident) {
								return
							}
						}
					}
					governedCalls[call] = true
				}
				if len(n.Lhs) == len(n.Rhs) {
					for i, rhs := range n.Rhs {
						governRHS(i, rhs)
						if recvRooted(rhs) {
							// A method-value bind captures the receiver
							// inside a func value the reach classification
							// cannot see - fail-closed.
							if methodValueBind(rhs) {
								disqualified[key] = true
							} else if ident, ok := n.Lhs[i].(*ast.Ident); ok {
								if escapingSink(ident) {
									disqualified[key] = true
								} else {
									consume(rhs)
								}
							}
						}
					}
				} else if len(n.Rhs) == 1 {
					governRHS(-1, n.Rhs[0])
					if recvRooted(n.Rhs[0]) {
						if methodValueBind(n.Rhs[0]) {
							disqualified[key] = true
						}
						allIdent := true
						sink := false
						for _, lhs := range n.Lhs {
							ident, ok := lhs.(*ast.Ident)
							if !ok {
								allIdent = false
							} else if escapingSink(ident) {
								sink = true
							}
						}
						if allIdent && !methodValueBind(n.Rhs[0]) {
							if sink {
								disqualified[key] = true
							} else {
								consume(n.Rhs[0])
							}
						}
					}
				}
				for _, lhs := range n.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok {
						// Rebinding a local is not a receiver write.
						if p.TypesInfo.Uses[ident] == recvObj || p.TypesInfo.Defs[ident] == recvObj {
							disqualified[key] = true
						}
						consume(ident)
						continue
					}
					if recvRooted(lhs) {
						disqualified[key] = true
					}
				}

			case *ast.IncDecStmt:
				if recvRooted(n.X) {
					disqualified[key] = true
				}
			case *ast.SendStmt:
				if recvRooted(n.Chan) {
					disqualified[key] = true
				}
			case *ast.UnaryExpr:
				if n.Op == token.AND && recvRooted(n.X) {
					disqualified[key] = true
				}
			case *ast.RangeStmt:
				// Ranging the receiver or a field chain taints the
				// bindings - tracked like any receiver-bound local; a
				// channel receiver receives and disqualifies.
				if recvRooted(n.X) {
					t := p.TypesInfo.TypeOf(n.X)
					if t == nil {
						disqualified[key] = true
					} else if _, isChan := types.Unalias(t).Underlying().(*types.Chan); isChan {
						disqualified[key] = true
					} else {
						for _, bind := range []ast.Expr{n.Key, n.Value} {
							if ident, ok := bind.(*ast.Ident); ok && ident != nil {
								if escapingSink(ident) {
									disqualified[key] = true
									continue
								}
								if obj := p.TypesInfo.Defs[ident]; obj != nil {
									tainted[obj] = true
								}
								consume(ident)
							}
						}
						consume(n.X)
					}
				}
			case *ast.ReturnStmt:
				// A chain-shaped result hands its value to the caller,
				// whose deferral judges the instantiated result types;
				// a sibling call in return position is governed the
				// same way; any other result shape keeps the normal
				// escape rules for its inner uses (a call in return
				// position still escapes its arguments). A return inside
				// a nested literal is an escape position instead: the
				// literal outlives the body and the caller's result
				// judgment never sees what it hands out.
				if innerReturns[n] {
					for _, result := range n.Results {
						if recvRooted(result) {
							disqualified[key] = true
						}
					}
					break
				}
				for _, result := range n.Results {
					if recvRooted(result) {
						// A method-value result captures the receiver
						// inside a func value the caller's result check
						// cannot see - fail-closed.
						if methodValueBind(result) {
							disqualified[key] = true
							continue
						}
						consume(result)
					}
					if call, ok := result.(*ast.CallExpr); ok {
						if sel, ok := call.Fun.(*ast.SelectorExpr); ok && recvRooted(sel.X) {
							if sibling, _ := siblingLeaky(sel); sibling {
								governedCalls[call] = true
							}
						}
					}
				}
			case *ast.CallExpr:
				// len and cap of receiver-reachable values are writeless
				// reads; a sibling-method call on the receiver chain
				// defers to that method's own proof; the receiver in any
				// other call-ARG position is an escape, handled by the
				// ident visit.
				if ident, ok := n.Fun.(*ast.Ident); ok {
					if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && (ident.Name == "len" || ident.Name == "cap") {
						for _, arg := range n.Args {
							if recvRooted(arg) {
								consume(arg)
							}
						}
						break
					}
				}
				if tv, ok := p.TypesInfo.Types[n.Fun]; ok && tv.IsType() {
					// A conversion of a receiver-reachable value is a
					// value read judged by its result type: a reach-free
					// result is a fresh copy that cannot write back; a
					// result handing out mutable reach may alias the
					// operand (slice-to-named, slice-to-array-pointer)
					// and keeps the escape (REQ-closure-shared-dynamic-state).
					// A method-value operand carries its receiver whatever
					// the result type says - a func-typed conversion result
					// hands out no reach yet executes receiver writes when
					// invoked - so it never consumes and the selector arm
					// refuses it.
					if len(n.Args) == 1 && recvRooted(n.Args[0]) && !methodValueBind(n.Args[0]) {
						if t := p.TypesInfo.TypeOf(n); t != nil && !typeHandsOutMutableReach(t, make(map[types.Type]bool)) {
							consume(n.Args[0])
						}
					}
					break
				}
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok && recvRooted(sel.X) {
					if selection, ok := p.TypesInfo.Selections[sel]; ok && selection.Kind() == types.MethodVal {
						if fn, ok := selection.Obj().(*types.Func); ok && auditedSynchronization(fn) {
							// The audited synchronization set: lock state
							// cannot change dispatch, so a lock operation
							// on a receiver-reachable mutex is
							// receiver-neutral by source audit
							// (REQ-closure-shared-dynamic-state).
							consume(sel.X)
							break
						}
						if fn, ok := selection.Obj().(*types.Func); ok && fn.Pkg() == p.Types {
							target := recvTypeNameOf(p, sel) + "." + fn.Name()
							if _, sibling := methods[target]; sibling {
								if chains[key] == nil {
									chains[key] = map[string]bool{}
								}
								chains[key][target] = true
								consume(sel.X)
								// A sibling call whose instantiated
								// results hand out mutable reach is a
								// call site under the spec's proviso:
								// outside a tainting assignment or a
								// return, the value escapes ungoverned.
								if _, leaky := siblingLeaky(sel); leaky && !governedCalls[n] {
									disqualified[key] = true
								}
								break
							}
						}
					}
					disqualified[key] = true
				}
			case *ast.IndexExpr:
				if recvRooted(n.X) && !allowed[rootIdent(n.X)] {
					// Outside a tainting assignment or a return, an
					// indexed-out value escapes: it is judged by mutable
					// reach exactly as before the taint paths existed.
					if t := p.TypesInfo.TypeOf(n); t == nil || typeHandsOutMutableReach(t, make(map[types.Type]bool)) {
						disqualified[key] = true
					} else {
						consume(n.X)
					}
				}
			case *ast.SelectorExpr:
				// A field read off the receiver is judged at the
				// outermost node of the receiver-rooted chain by the
				// value it produces: an intermediate step is
				// evaluation, not a handout, so a reach-free leaf read
				// through a reach-bearing field is a value copy that
				// cannot write back. An alias-handing produced value
				// refuses; a method VALUE bind is an escape.
				if recvRooted(n.X) && !allowed[rootIdent(n.X)] {
					if selection, ok := p.TypesInfo.Selections[n]; ok && selection.Kind() == types.MethodVal {
						// A method value reaching this arm was not consumed
						// by a governing call: the value carries its
						// receiver - an address for pointer-receiver
						// methods - whatever position it flows to, and an
						// inner chain step must not launder it, so the
						// refusal is immediate rather than deferred to the
						// ident backstop.
						disqualified[key] = true
						break
					}
					if t := p.TypesInfo.TypeOf(n); t == nil || typeHandsOutMutableReach(t, make(map[types.Type]bool)) {
						disqualified[key] = true
					} else {
						consume(n.X)
					}
				}
			case *ast.BinaryExpr:
				if n.Op == token.EQL || n.Op == token.NEQ {
					if recvRooted(n.X) {
						consume(n.X)
					}
					if recvRooted(n.Y) {
						consume(n.Y)
					}
				}
			case *ast.Ident:
				if isRecv(n) && !allowed[n] {
					// Any receiver use not consumed by an allowed shape
					// above - argument, return, store, bare bind - is
					// an escape.
					disqualified[key] = true
				}
			}
			return true
		})
	}
	// Fixed point: chaining into a disqualified sibling disqualifies.
	for changed := true; changed; {
		changed = false
		for key, targets := range chains {
			if disqualified[key] {
				continue
			}
			for target := range targets {
				if disqualified[target] {
					disqualified[key] = true
					changed = true
					break
				}
			}
		}
	}
	readOnly := map[string]bool{}
	for key, m := range methods {
		if m.recv == nil || !disqualified[key] {
			readOnly[key] = true
		}
	}
	return readOnly
}

// instantiatedResultsHandOutNothing reports whether every result of
// the call site's instantiated signature hands out no mutable reach or
// is an audited-immutable type - the caller-side half of the
// receiver-effect discharge: the declaring proof allows returns, the
// call site judges what actually comes back
// (REQ-closure-shared-dynamic-state).
func instantiatedResultsHandOutNothing(t types.Type) bool {
	sig, ok := types.Unalias(t).(*types.Signature)
	if !ok {
		return false
	}
	results := sig.Results()
	for i := 0; results != nil && i < results.Len(); i++ {
		rt := results.At(i).Type()
		if auditedImmutableType(rt) {
			continue
		}
		if typeHandsOutMutableReach(rt, make(map[types.Type]bool)) {
			return false
		}
	}
	return true
}

// auditedImmutableType is the audited set of types whose values are
// immutable by construction even though their kind hands out reach:
// reflect.Type is runtime-canonical and never written after
// construction. Grows only by source audit
// (REQ-closure-shared-dynamic-state).
func auditedImmutableType(t types.Type) bool {
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == "reflect" && named.Obj().Name() == "Type"
}

// interfaceReceiver reports whether the method's receiver is an
// interface - dispatch the per-package proof cannot resolve.
func interfaceReceiver(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return true
	}
	t := types.Unalias(sig.Recv().Type())
	if pointer, ok := t.(*types.Pointer); ok {
		t = types.Unalias(pointer.Elem())
	}
	_, isInterface := t.Underlying().(*types.Interface)
	return isInterface
}

// methodFactKey is the cross-package identity of a method's
// receiver-effect proof: declaring package path, receiver type name,
// method name.
func methodFactKey(fn *types.Func) string {
	sig, _ := fn.Type().(*types.Signature)
	recvName := ""
	if sig != nil && sig.Recv() != nil {
		t := types.Unalias(sig.Recv().Type())
		if pointer, ok := t.(*types.Pointer); ok {
			t = types.Unalias(pointer.Elem())
		}
		if named, ok := t.(*types.Named); ok && named.Obj() != nil {
			recvName = named.Obj().Name()
		}
	}
	pkg := ""
	if fn.Pkg() != nil {
		pkg = fn.Pkg().Path()
	}
	return pkg + "\x00" + recvName + "." + fn.Name()
}

// auditedSynchronization reports whether the method is in the audited
// synchronization set: sync.Mutex and sync.RWMutex lock operations,
// receiver-neutral because lock state cannot change dispatch. Grows
// only by source audit (REQ-closure-shared-dynamic-state).
func auditedSynchronization(fn *types.Func) bool {
	if fn.Pkg() == nil || fn.Pkg().Path() != "sync" {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	t := types.Unalias(sig.Recv().Type())
	if pointer, ok := t.(*types.Pointer); ok {
		t = types.Unalias(pointer.Elem())
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj() == nil {
		return false
	}
	switch named.Obj().Name() {
	case "Mutex", "RWMutex":
	default:
		return false
	}
	switch fn.Name() {
	case "Lock", "Unlock", "RLock", "RUnlock", "TryLock", "TryRLock":
		return true
	default:
		return false
	}
}

// recvTypeNameOf resolves the receiver type name of a selection's
// method through its declaring type, mirroring recvTypeName's shape.
func recvTypeNameOf(p *packages.Package, sel *ast.SelectorExpr) string {
	selection, ok := p.TypesInfo.Selections[sel]
	if !ok {
		return ""
	}
	fn, ok := selection.Obj().(*types.Func)
	if !ok {
		return ""
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return ""
	}
	t := types.Unalias(sig.Recv().Type())
	if pointer, ok := t.(*types.Pointer); ok {
		t = types.Unalias(pointer.Elem())
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj() == nil {
		return ""
	}
	return named.Obj().Name()
}

// recordFunctionReferenceRegions records, for every plain named
// function this package references - its own and foreign, exported
// included - the strongest region class of those references:
// "prog" when any reference is program code, a value reference, or a
// go-statement callee; otherwise the reference edges from init flow
// ("init") and from other plain named functions (the caller's own
// function key), which composition resolves to a graph-wide init-only
// fixed point (REQ-closure-shared-dynamic-state's cross-package
// init-only class). Keys are pkgPath NUL name; edges are joined
// caller NUL callee at composition via the fact schema.
func recordFunctionReferenceRegions(p *packages.Package, initOnly map[string]bool, refs map[string]map[string]bool) {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return
	}
	funcKeyOf := func(obj types.Object) (string, bool) {
		fn, ok := obj.(*types.Func)
		if !ok || fn.Pkg() == nil {
			return "", false
		}
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() != nil {
			return "", false
		}
		return fn.Pkg().Path() + "\x00" + fn.Name(), true
	}
	add := func(callee, region string) {
		if refs[callee] == nil {
			refs[callee] = map[string]bool{}
		}
		refs[callee][region] = true
	}
	var scan func(region string, root ast.Node)
	scan = func(region string, root ast.Node) {
		calls := map[*ast.Ident]bool{}
		ast.Inspect(root, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit:
				if n != root && n.Body != nil {
					scan("prog", n.Body)
					return false
				}
			case *ast.GoStmt:
				scan("prog", n.Call)
				return false
			case *ast.CallExpr:
				// An explicit generic instantiation wraps the callee in
				// an index expression - still a direct call.
				fun := n.Fun
				for {
					switch f := fun.(type) {
					case *ast.ParenExpr:
						fun = f.X
						continue
					case *ast.IndexExpr:
						fun = f.X
						continue
					case *ast.IndexListExpr:
						fun = f.X
						continue
					}
					break
				}
				if ident, ok := fun.(*ast.Ident); ok {
					if key, ok := funcKeyOf(p.TypesInfo.Uses[ident]); ok {
						calls[ident] = true
						add(key, region)
					}
				}
				if sel, ok := fun.(*ast.SelectorExpr); ok {
					if key, ok := funcKeyOf(p.TypesInfo.Uses[sel.Sel]); ok {
						calls[sel.Sel] = true
						add(key, region)
					}
				}
			case *ast.Ident:
				if calls[n] {
					return true
				}
				if key, ok := funcKeyOf(p.TypesInfo.Uses[n]); ok {
					// A non-call reference hands the function out as a
					// value - poisoned everywhere.
					add(key, "prog")
				}
			}
			return true
		})
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				switch {
				case decl.Recv != nil:
					if decl.Body != nil {
						scan("prog", decl.Body)
					}
				case decl.Name != nil && decl.Name.Name == "init":
					if decl.Body != nil {
						scan("init", decl.Body)
					}
				case decl.Name != nil && initOnly[decl.Name.Name]:
					if decl.Body != nil {
						scan("init", decl.Body)
					}
				case decl.Name != nil:
					if decl.Body != nil && p.Types != nil {
						scan(p.Types.Path()+"\x00"+decl.Name.Name, decl.Body)
					}
				}
			default:
				// Initializer expressions are init flow; the scan's
				// literal arm classifies nested function bodies as
				// program code itself.
				scan("init", decl)
			}
		}
	}
}

// recordOpaqueDynamicVars judges which interface-typed package-level
// variables — own or foreign — are object-closed: the initializer and
// every init-flow store are provably-immutable audited constructions
// (errors.New; the nil zero value), so no holder of the value can
// mutate the shared object and escapes of it are not mutation. Every
// plain named function's direct body is audited, not just init bodies
// and package-locally-proven helpers: whether a function is init flow
// is settled only at composition (the graph-wide fixed point), and a
// store the composition discharges as init flow must have passed this
// audit — for a function that stays program code the store marks
// mutation anyway, so the extra break is unobservable. The
// audited-construction set grows only by source audit
// (REQ-closure-shared-dynamic-state).
func recordOpaqueDynamicVars(p *packages.Package, opaque, breaks map[string]bool) {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return
	}
	auditedImmutable := func(expr ast.Expr) bool {
		switch expr := expr.(type) {
		case *ast.Ident:
			return expr.Name == "nil" && p.TypesInfo.Uses[expr] == types.Universe.Lookup("nil")
		case *ast.CallExpr:
			sel, ok := expr.Fun.(*ast.SelectorExpr)
			if !ok {
				return false
			}
			fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
			return ok && fn.Pkg() != nil && fn.Pkg().Path() == "errors" && fn.Name() == "New"
		default:
			return false
		}
	}
	interfacePackageVar := func(obj types.Object) (*types.Var, bool) {
		variable, ok := obj.(*types.Var)
		if !ok || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
			return nil, false
		}
		_, isInterface := types.Unalias(variable.Type()).Underlying().(*types.Interface)
		return variable, isInterface
	}
	failed := map[string]bool{}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		if variable, ok := interfacePackageVar(scope.Lookup(name)); ok {
			opaque[dynamicVarKey(variable)] = true
		}
	}
	audit := func(target ast.Expr, value ast.Expr) {
		ident, ok := target.(*ast.Ident)
		if !ok {
			return
		}
		obj, ok := p.TypesInfo.Defs[ident]
		if !ok || obj == nil {
			if obj, ok = p.TypesInfo.Uses[ident]; !ok {
				return
			}
		}
		if variable, ok := interfacePackageVar(obj); ok {
			if value == nil || !auditedImmutable(value) {
				failed[dynamicVarKey(variable)] = true
			}
		}
	}
	failTargets := func(expr ast.Expr) {
		ast.Inspect(expr, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if obj, ok := p.TypesInfo.Uses[ident]; ok {
				if variable, ok := interfacePackageVar(obj); ok {
					failed[dynamicVarKey(variable)] = true
				}
			}
			return true
		})
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, ident := range vs.Names {
						var value ast.Expr
						if i < len(vs.Values) {
							value = vs.Values[i]
						}
						if len(vs.Values) == 0 {
							// No initializer: the zero value nil, audited.
							continue
						}
						audit(ident, value)
					}
				}
			case *ast.FuncDecl:
				if decl.Recv != nil || decl.Name == nil || decl.Body == nil {
					continue
				}
				ast.Inspect(decl.Body, func(n ast.Node) bool {
					switch n := n.(type) {
					case *ast.FuncLit:
						// A nested literal is program code wherever it
						// appears, not init flow - its stores are the
						// mutation walk's to judge, never audited here.
						return false
					case *ast.AssignStmt:
						for i, lhs := range n.Lhs {
							if _, ok := lhs.(*ast.Ident); !ok {
								// An indirect or selector store the audit
								// cannot attribute fails every interface
								// variable the target subtree reaches.
								failTargets(lhs)
								continue
							}
							var value ast.Expr
							if i < len(n.Rhs) {
								value = n.Rhs[i]
							}
							audit(lhs, value)
						}
					case *ast.UnaryExpr:
						if n.Op == token.AND {
							// An init-flow address capture licenses later
							// unattributable stores - fail-close.
							failTargets(n.X)
						}
					case *ast.RangeStmt:
						// A range binding is an init store of a value that
						// is never an audited construction - fail-close.
						if n.Key != nil {
							failTargets(n.Key)
						}
						if n.Value != nil {
							failTargets(n.Value)
						}
					}
					return true
				})
			}
		}
	}
	for key := range failed {
		delete(opaque, key)
		// A break can name a foreign package's variable - a cross-package
		// init store the declaring package cannot see. The composition
		// unions breaks from every fact, so the foreign opacity falls.
		breaks[key] = true
	}
}

// typeHandsOutMutableReach reports whether holding a value of the type
// hands out write access to the memory it aliases: pointers, maps,
// slices, channels, unsafe pointers, and interfaces (concrete type
// unknown) do; function values do not - calling one executes program
// code whose own writes are judged where they are written, but the
// value itself cannot be written through. The receiver-effect and
// carrier read discharges gate on this, not on dynamic reach: a write
// through any aliased part of a tracked carrier is mutation
// (REQ-closure-shared-dynamic-state).
func typeHandsOutMutableReach(t types.Type, seen map[types.Type]bool) bool {
	if t == nil || seen[t] {
		return false
	}
	seen[t] = true
	switch t := types.Unalias(t).(type) {
	case *types.Basic:
		return t.Kind() == types.UnsafePointer
	case *types.Interface, *types.Pointer, *types.Map, *types.Slice, *types.Chan:
		return true
	case *types.Signature:
		return false
	case *types.Named:
		return typeHandsOutMutableReach(t.Underlying(), seen)
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if typeHandsOutMutableReach(t.Field(i).Type(), seen) {
				return true
			}
		}
		return false
	case *types.Array:
		return typeHandsOutMutableReach(t.Elem(), seen)
	case *types.TypeParam:
		return true
	default:
		return true
	}
}

// rangeBindsAlias reports whether ranging the type binds an
// alias-handing value into the iteration variables.
func rangeBindsAlias(t types.Type) bool {
	switch t := types.Unalias(t).Underlying().(type) {
	case *types.Map:
		return typeHandsOutMutableReach(t.Key(), make(map[types.Type]bool)) || typeHandsOutMutableReach(t.Elem(), make(map[types.Type]bool))
	case *types.Slice:
		return typeHandsOutMutableReach(t.Elem(), make(map[types.Type]bool))
	case *types.Array:
		return typeHandsOutMutableReach(t.Elem(), make(map[types.Type]bool))
	case *types.Pointer:
		if arr, ok := types.Unalias(t.Elem()).Underlying().(*types.Array); ok {
			return typeHandsOutMutableReach(arr.Elem(), make(map[types.Type]bool))
		}
		return true
	default:
		return false
	}
}

// typeHandsOutDynamicAlias reports whether reading the type hands out
// shared mutable access to dynamic state: an interface value (its
// concrete object is shared), a channel, a pointer, map, or slice
// reaching a dynamic carrier, or an unsafe pointer. Function values
// and by-value composites of them are copies — reading them cannot
// reach the shared cell (REQ-closure-shared-dynamic-state).
func typeHandsOutDynamicAlias(t types.Type, seen map[types.Type]bool) bool {
	if t == nil || seen[t] {
		return false
	}
	seen[t] = true
	switch t := types.Unalias(t).(type) {
	case *types.Basic:
		return t.Kind() == types.UnsafePointer
	case *types.Interface:
		return true
	case *types.Chan:
		return typeMayCarryUnknownDynamic(t.Elem(), make(map[types.Type]bool))
	case *types.Pointer:
		return typeMayCarryUnknownDynamic(t.Elem(), make(map[types.Type]bool))
	case *types.Map:
		return typeMayCarryUnknownDynamic(t.Key(), make(map[types.Type]bool)) || typeMayCarryUnknownDynamic(t.Elem(), make(map[types.Type]bool))
	case *types.Slice:
		return typeMayCarryUnknownDynamic(t.Elem(), make(map[types.Type]bool))
	case *types.Named:
		return typeHandsOutDynamicAlias(t.Underlying(), seen)
	case *types.TypeParam:
		return typeHandsOutDynamicAlias(t.Constraint(), seen)
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if typeHandsOutDynamicAlias(t.Field(i).Type(), seen) {
				return true
			}
		}
	case *types.Array:
		return typeHandsOutDynamicAlias(t.Elem(), seen)
	case *types.Tuple:
		for i := 0; i < t.Len(); i++ {
			if typeHandsOutDynamicAlias(t.At(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}
