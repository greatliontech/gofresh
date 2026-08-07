package gofresh

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"

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
	recordDynamicGlobalUses(p, mutated, map[string]bool{}, initOnlyReachableHelpers(p))
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
func recordDynamicGlobalUses(p *packages.Package, mutated, escaped, initOnly map[string]bool) {
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
				}
			}
			return true
		})
	}
	walkBody := func(body ast.Node) {
		// readContext collects ident occurrences whose enclosing shape is
		// a provably-writeless read: indexing, iteration source,
		// length/capacity, comparison. Inspect visits parents before
		// children, so the shape records its operand idents ahead of the
		// ident visit that would otherwise classify them as escapes.
		readContext := map[*ast.Ident]bool{}
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
				// the iteration discharge holds only when the produced
				// bindings are not themselves alias-handing
				// (REQ-closure-shared-dynamic-state).
				if t := p.TypesInfo.TypeOf(n.X); t != nil {
					if _, isChan := types.Unalias(t).Underlying().(*types.Chan); isChan {
						markTargets(n.X)
					} else if !rangeBindsAlias(t) {
						markRead(n.X)
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
				if t := p.TypesInfo.TypeOf(n); t == nil || !typeHandsOutDynamicAlias(t, make(map[types.Type]bool)) {
					markRead(n.X)
				}
			case *ast.BinaryExpr:
				if n.Op == token.EQL || n.Op == token.NEQ {
					markRead(n.X)
					markRead(n.Y)
				}
			case *ast.CallExpr:
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
			case *ast.SelectorExpr:
				// A pointer-receiver method USE — bind or call alike —
				// is an implicit address capture of its receiver chain.
				if selection, ok := p.TypesInfo.Selections[n]; ok && selection.Kind() == types.MethodVal {
					if fn, ok := selection.Obj().(*types.Func); ok {
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
				if decl.Recv == nil && decl.Name != nil && initOnly[decl.Name.Name] {
					// An init-only-reachable helper's body is init flow:
					// its mutations are startup-deterministic. Literals
					// nested in it stay program code, exactly as in an
					// init body (REQ-closure-shared-dynamic-state).
					if decl.Body != nil {
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
					}
					continue
				}
				if decl.Recv == nil && decl.Name != nil && decl.Name.Name == "init" {
					// init flow is exempt, but a function literal nested
					// in an init body is callable program code exactly
					// like one nested in a package-level declaration.
					if decl.Body != nil {
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
					}
					continue
				}
				if decl.Body != nil {
					walkBody(decl.Body)
				}
			default:
				// The declaration itself is initialization, but a
				// function literal nested in it is callable program
				// code — a package-level `var rebind = func() {...}`
				// mutator must be walked.
				ast.Inspect(decl, func(n ast.Node) bool {
					if lit, ok := n.(*ast.FuncLit); ok && lit.Body != nil {
						walkBody(lit.Body)
						return false
					}
					return true
				})
			}
		}
	}
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

// recordOpaqueDynamicVars judges, in the declaring package alone, which
// interface-typed package-level variables are object-closed: the
// initializer and every init-flow store are provably-immutable audited
// constructions (errors.New; the nil zero value), so no holder of the
// value can mutate the shared object and escapes of it are not
// mutation. Rebinding stays mutation everywhere — a non-init store is a
// demonstrated write in whatever package performs it, so opacity never
// needs to audit those. The audited-construction set grows only by
// source audit (REQ-closure-shared-dynamic-state).
func recordOpaqueDynamicVars(p *packages.Package, opaque, breaks, initOnly map[string]bool) {
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
				// Init-only-reachable helpers are init flow: their
				// stores are audited under the same rules as init
				// bodies (REQ-closure-shared-dynamic-state).
				if decl.Name.Name != "init" && !initOnly[decl.Name.Name] {
					continue
				}
				ast.Inspect(decl.Body, func(n ast.Node) bool {
					switch n := n.(type) {
					case *ast.FuncLit:
						// A literal nested in an init body is program
						// code, not init flow - its stores are the
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

// rangeBindsAlias reports whether ranging the type binds an
// alias-handing value into the iteration variables.
func rangeBindsAlias(t types.Type) bool {
	switch t := types.Unalias(t).Underlying().(type) {
	case *types.Map:
		return typeHandsOutDynamicAlias(t.Key(), make(map[types.Type]bool)) || typeHandsOutDynamicAlias(t.Elem(), make(map[types.Type]bool))
	case *types.Slice:
		return typeHandsOutDynamicAlias(t.Elem(), make(map[types.Type]bool))
	case *types.Array:
		return typeHandsOutDynamicAlias(t.Elem(), make(map[types.Type]bool))
	case *types.Pointer:
		if arr, ok := types.Unalias(t.Elem()).Underlying().(*types.Array); ok {
			return typeHandsOutDynamicAlias(arr.Elem(), make(map[types.Type]bool))
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
