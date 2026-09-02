package gofresh

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
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

// sharedDynamicStatePrefix opens every shared-dynamic-state downgrade
// reason. It is the one discriminator between the downgrade family and
// ordinary unverifiable dependence on the verdict path: observation
// evidence may substitute for the latter, never the former, and the
// prefix is set here alone so the two sites cannot drift.
const sharedDynamicStatePrefix = "package graph shares mutated dynamic state: "

func scanSubjectsInWithBuildFlagsEnv(ctx context.Context, dir string, env, buildFlags []string, pkgPaths ...string) (*subjectScan, error) {
	hasher, err := closure.NewAtContextEnv(ctx, dir, env, buildFlags...)
	if err != nil {
		return nil, err
	}
	scan, _, err := scanViewSubjects(ctx, hasher, "", dir, env, buildFlags, nil, nil, false, false, pkgPaths...)
	return scan, err
}

// scanViewSubjects performs one observation pass's whole subject scan: the
// metadata graph names every node and its mutability class, one typed load
// covers the view packages' variants and every mutable-local graph package,
// the dynamic-state derivation serves version-pinned facts from the memo, and
// the subject walk reads that one load (REQ-fresh-coherent-view). The typed
// load is installed on the hasher for the pass's sibling consumers. An empty
// factScope disables fact persistence, never the derivation.
func scanViewSubjects(ctx context.Context, hasher *closure.Hasher, factScope, dir string, env, buildFlags []string, snapshot *gotool.EnvSnapshot, vouches map[string]bool, singleSubject, packageProcess bool, pkgPaths ...string) (*subjectScan, *closure.ViewLoad, error) {
	meta, err := hasher.GraphMetadata(pkgPaths...)
	if err != nil {
		return nil, nil, err
	}
	requested := make(map[string]bool, len(pkgPaths))
	for _, pkgPath := range pkgPaths {
		requested[pkgPath] = true
	}
	// A test variant of a module-cache-resident view package: the view
	// packages are the only test-expanded ones, and a subject package
	// inside the read-only cache has no runnable tests to vouch for it —
	// refused from the listing, before the typed load below is paid, and
	// named rather than surfaced as a coverage gap. A pinned view package
	// with no test files carries no variant and derives through the
	// pinned-fact path as before.
	for _, node := range meta {
		if node.Class == closure.PinnedPackage && node.ForTest != "" && requested[node.ForTest] && (node.PkgPath == node.ForTest || node.PkgPath == node.ForTest+"_test") {
			return nil, nil, fmt.Errorf("gofresh: view package %s resolves into the module cache; module-cache-resident subjects are unsupported", node.ForTest)
		}
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
	if viewTestHooks.typedLoad != nil {
		viewTestHooks.typedLoad()
	}
	load, err := closure.LoadViewPackagesEnvSnapshot(ctx, dir, env, buildFlags, snapshot, patterns...)
	if err != nil {
		return nil, nil, err
	}
	hasher.UseViewLoad(load)
	state, err := deriveViewDynamicState(ctx, hasher, factScope, dir, env, buildFlags, load, pkgPaths, vouches, singleSubject)
	if err != nil {
		return nil, nil, err
	}
	scan, err := scanSubjectsFromLoaded(hasher.SelectionAudited(), load.Packages(), state, pkgPaths...)
	if err != nil {
		return nil, nil, err
	}
	if singleSubject {
		// The attestation-gated reachability scoping: per downgraded
		// subject, a culprit whose every marking site is provably
		// outside the subject's rooted flow discharges — no proof, no
		// discharge (REQ-closure-shared-dynamic-state).
		if err := dischargeUnreachableCulprits(hasher, state, scan); err != nil {
			return nil, nil, err
		}
	} else if packageProcess {
		// The package-process attestation's binary-scoped reachability
		// judgment: every measured process is the subject package's own
		// test binary, so sibling subjects are themselves harness roots
		// of the analyzed binary, and a culprit no harness root's
		// post-init flow can reach is init-determined for every subject
		// of the binary — no proof, no discharge
		// (REQ-closure-shared-dynamic-state).
		if err := dischargeBinaryUnreachableCulprits(hasher, state, scan); err != nil {
			return nil, nil, err
		}
	}
	return scan, load, nil
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
	// and variable (REQ-closure-shared-dynamic-state-reason).
	downgradeReason map[Subject]string
	// vouchDischarges maps each subject to the canonical sorted
	// comma-joined caller-vouch identities that discharged would-be
	// culprits reachable from its package (REQ-vouch-recorded).
	vouchDischarges map[Subject]string
	// attestationDischarges maps each subject to the canonical sorted
	// comma-joined variable keys whose discharge the caller's
	// single-subject-process attestation carried — a pool variable's
	// admitted Get/Put, a single-subject-directed variable —
	// reachable from its package; the vouch-recording discipline's
	// parallel (REQ-vouch-recorded).
	attestationDischarges map[Subject]string
	// packageProcessDischarges mirrors attestationDischarges for the
	// package-process attestation's binary-scoped reachability judgment
	// (REQ-vouch-recorded).
	packageProcessDischarges map[Subject]string
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
func scanSubjectsFromLoaded(audited bool, pkgs []*packages.Package, state *viewDynamicState, pkgPaths ...string) (*subjectScan, error) {
	scan := &subjectScan{
		pure:                     map[Subject]bool{},
		known:                    map[Subject]bool{},
		openWorld:                map[Subject]bool{},
		external:                 map[Subject]bool{},
		downgradeReason:          map[Subject]string{},
		vouchDischarges:          map[Subject]string{},
		attestationDischarges:    map[Subject]string{},
		packageProcessDischarges: map[Subject]string{},
		ambiguous:                map[Subject]string{},
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
				initOrdinal := 0
				for _, decl := range f.Decls {
					fd, ok := decl.(*ast.FuncDecl)
					if !ok {
						continue
					}
					sym := fd.Name.Name
					if recv := recvTypeName(fd); recv != "" {
						sym = recv + "." + sym
					} else if fd.Recv != nil {
						// A receiver the grammar cannot name (a type
						// error the parser tolerates): never mint the
						// method as a plain-function subject — the
						// bare name would collide with a real
						// function's, marking the wrong subject. The
						// sibling tools skip identically. The skip
						// covers the whole body, directives included:
						// a declaration yielding no subject is outside
						// the conflict refusal's scope below.
						continue
					} else if sym == "init" {
						// Unaddressable by name: init subjects carry the
						// declaration ledger's positional identity,
						// init#<file>#<ordinal> (file base name, 0-based
						// ordinal within the file in declaration order),
						// so multiple inits stay distinct subjects instead
						// of collapsing onto one ambiguous name. Receiver
						// absence is established by the branches above:
						// a nameable receiver minted a method subject, an
						// unnameable one skipped the declaration — so a
						// method named init never reaches here to skew a
						// sibling's ordinal.
						if p.Fset == nil {
							// Cannot mint the positional identity; skip the
							// declaration rather than resurrect the bare
							// colliding name. Unreachable under the loader
							// modes in use (Syntax implies Fset).
							continue
						}
						sym = fmt.Sprintf("init#%s#%d", filepath.Base(p.Fset.PositionFor(f.Pos(), false).Filename), initOrdinal)
						initOrdinal++
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
					if fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func); ok && signatureMayReceiveUnknownDynamic(audited, fn.Type().(*types.Signature)) {
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
					if sig, ok := method.Type().(*types.Signature); ok && signatureMayReceiveUnknownDynamic(audited, sig) {
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
			scan.downgradeReason[subject] = sharedDynamicStatePrefix + reason
		}
		if discharges := state.vouchDischarges[subject.Package]; discharges != "" {
			scan.vouchDischarges[subject] = discharges
		}
		if attested := state.attestationDischarges[subject.Package]; attested != "" {
			scan.attestationDischarges[subject] = attested
		}
	}
	return scan, nil
}

func signatureMayReceiveUnknownDynamic(audited bool, sig *types.Signature) bool {
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
			if !closure.TypeParamBoundsAwayFromDynamic(audited, list.At(i)) {
				return true
			}
		}
	}
	// One fresh map per parameter, mirroring the closure tier: no
	// cross-parameter mark leakage, cycle-safe within each evaluation.
	if recv := sig.Recv(); recv != nil && typeMayCarryUnknownDynamic(audited, recv.Type(), make(map[types.Type]bool)) {
		return true
	}
	params := sig.Params()
	for i := 0; params != nil && i < params.Len(); i++ {
		if typeMayCarryUnknownDynamic(audited, params.At(i).Type(), make(map[types.Type]bool)) {
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

func typeMayCarryUnknownDynamic(audited bool, t types.Type, seen map[types.Type]bool) bool {
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
		return !closure.TypeParamBoundsAwayFromDynamic(audited, t)
	case *types.Named:
		// The audited atomic transparency (closure.AuditedAtomicPointerElem
		// carries the audit): sync/atomic.Pointer[T] is walked as *T.
		// The uninstantiated generic inside sync/atomic itself falls
		// through to the fail-closed type-parameter judgment.
		if elem, ok := closure.AuditedAtomicPointerElem(audited, t); ok {
			return typeMayCarryUnknownDynamic(audited, elem, seen)
		}
		return typeMayCarryUnknownDynamic(audited, t.Underlying(), seen)
	case *types.Pointer:
		return typeMayCarryUnknownDynamic(audited, t.Elem(), seen)
	case *types.Slice:
		return typeMayCarryUnknownDynamic(audited, t.Elem(), seen)
	case *types.Array:
		return typeMayCarryUnknownDynamic(audited, t.Elem(), seen)
	case *types.Map:
		return typeMayCarryUnknownDynamic(audited, t.Key(), seen) || typeMayCarryUnknownDynamic(audited, t.Elem(), seen)
	case *types.Chan:
		return typeMayCarryUnknownDynamic(audited, t.Elem(), seen)
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if typeMayCarryUnknownDynamic(audited, t.Field(i).Type(), seen) {
				return true
			}
		}
	case *types.Tuple:
		for i := 0; i < t.Len(); i++ {
			if typeMayCarryUnknownDynamic(audited, t.At(i).Type(), seen) {
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
	for {
		switch e := t.(type) {
		case *ast.ParenExpr: // ((*T)) — the legal parenthesized form
			t = e.X
		case *ast.StarExpr:
			t = e.X
		case *ast.IndexExpr: // Recv[T]
			t = e.X
		case *ast.IndexListExpr: // Recv[T, U]
			t = e.X
		case *ast.Ident:
			return e.Name
		default:
			return ""
		}
	}
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
func recordDynamicGlobalMutations(audited bool, p *packages.Package, mutated map[string]bool) {
	recordDynamicGlobalUses(audited, p, mutated, map[string]bool{}, initOnlyReachableHelpers(p), nil, nil, nil, nil, nil, nil, nil, nil, false, nil)
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
	// literal marks a use recorded inside a function literal or go
	// statement nested in fn's body: the site attributes to fn for the
	// reachability scopings ONLY — the literal value outlives fn's
	// frame, so composition never init-discharges it, and an fn the
	// init flow can reach (transitively, "prog" failing closed)
	// forecloses instead of attributing: an init-created literal can be
	// stored and executed past initialization by flows no site names
	// (REQ-closure-shared-dynamic-state).
	literal bool
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

// explainMark observes a mutation or escape decision for the explain
// surface; nil outside an explain re-derivation
// (REQ-explain-passive).
func explainMark(p *packages.Package, kind, key string, at token.Pos) {
	if h := explainHooks.Load(); h != nil && h.site != nil {
		h.site(p, kind, key, at)
	}
}

// explainDeferralMark observes a deferred-use recording for the explain
// surface; nil outside an explain re-derivation (REQ-explain-passive).
func explainDeferralMark(p *packages.Package, kind byte, key, resolvent string, at token.Pos) {
	if h := explainHooks.Load(); h != nil && h.deferral != nil {
		h.deferral(p, kind, key, resolvent, at)
	}
}

// singleSubject is the engine's caller-attested single-subject-process
// execution model: it arms the audited pooling set's discharge — off,
// every pool use keeps the fail-closed judgment
// (REQ-closure-shared-dynamic-state). poolDischarged, when non-nil,
// collects the pool variable keys whose admitted Get/Put calls the
// attestation discharged, for the subject-evidence audit record
// (REQ-vouch-recorded).
func recordDynamicGlobalUses(audited bool, p *packages.Package, mutated, escaped, initOnly map[string]bool, methodUses, paramUses, initParamUses, initMethodUses, fieldUses, elemUses, carrierLinks map[string]map[string]bool, attributed *[]attributedUse, singleSubject bool, poolDischarged map[string]bool) {
	if p == nil || p.TypesInfo == nil {
		return
	}
	dynamicPackageVar := func(obj types.Object) (*types.Var, bool) {
		variable, ok := obj.(*types.Var)
		if !ok || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
			return nil, false
		}
		if !typeMayCarryUnknownDynamic(audited, variable.Type(), make(map[types.Type]bool)) {
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
					explainMark(p, "mutation", dynamicVarKey(variable), ident.Pos())
					mutated[dynamicVarKey(variable)] = true
				} else {
					for key := range aliasedLocals[obj] {
						explainMark(p, "mutation", key, ident.Pos())
						mutated[key] = true
					}
				}
			}
			return true
		})
	}
	// initOnlyParams maps each init-only-qualified helper to its
	// positional parameter objects (nil placeholders for unnamed
	// parameters), so an init call site can bind a carrier argument to
	// the parameter the helper's own scan sees - closing the recorded
	// helper-parameter residue. paramSeeds carries those bindings
	// across bodies; seedingPass suppresses the scan's advisory side
	// channels (escapes, links, explain marks) while the package-level
	// seed fixpoint converges, so nothing double-records.
	initOnlyParams := map[*types.Func][]types.Object{}
	paramSeeds := map[types.Object]map[string]bool{}
	paramSeedGrowth := false
	seedingPass := false
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name == nil || !initOnly[fd.Name.Name] || fd.Type == nil || fd.Type.Params == nil {
				continue
			}
			fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func)
			if !ok {
				continue
			}
			var params []types.Object
			for _, field := range fd.Type.Params.List {
				if len(field.Names) == 0 {
					params = append(params, nil)
					continue
				}
				for _, name := range field.Names {
					params = append(params, p.TypesInfo.Defs[name])
				}
			}
			initOnlyParams[fn] = params
		}
	}
	// initAliasedLocals maps an init-flow body's locals bound from
	// carriers to the carrier keys they alias, to a fixpoint over
	// assignment and range chains, with nested literals and go
	// statements excluded (they are program code, walked separately).
	// An interior that touches such a local touches the carrier.
	initAliasedLocals := func(body ast.Node) map[types.Object]map[string]bool {
		aliased := map[types.Object]map[string]bool{}
		for obj, keys := range paramSeeds {
			set := map[string]bool{}
			for key := range keys {
				set[key] = true
			}
			aliased[obj] = set
		}
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
		// linkKeys is rhsKeys minus call results: a call's value is the
		// callee's, not the argument carrier's backing, so it aliases
		// conservatively but never links keys.
		linkKeys := func(expr ast.Expr) map[string]bool {
			keys := map[string]bool{}
			ast.Inspect(expr, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.FuncLit, *ast.CallExpr:
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
		// storeLink links a composite store target's base carrier to the
		// stored value's carriers - an element or field store aliases the
		// backings exactly as a whole-name bind does
		// (REQ-closure-shared-dynamic-state).
		storeLink := func(target ast.Expr, lkeys map[string]bool) {
			if len(lkeys) == 0 || carrierLinks == nil || seedingPass {
				return
			}
			base := target
			for {
				switch t := base.(type) {
				case *ast.IndexExpr:
					base = t.X
				case *ast.SelectorExpr:
					base = t.X
				case *ast.StarExpr:
					base = t.X
				case *ast.ParenExpr:
					base = t.X
				default:
					ident, identOK := base.(*ast.Ident)
					if !identOK {
						return
					}
					obj, objOK := resolve(ident)
					if !objOK {
						return
					}
					variable, varOK := dynamicPackageVar(obj)
					if !varOK {
						return
					}
					own := dynamicVarKey(variable)
					for key := range lkeys {
						if key == own {
							continue
						}
						if carrierLinks[own] == nil {
							carrierLinks[own] = map[string]bool{}
						}
						carrierLinks[own][key] = true
					}
					return
				}
			}
		}
		// markRHSMethodValues escapes the receiver of every bound method
		// value in the expression: the bound value retains its receiver
		// past initialization, fail-closed exactly as the call
		// spelling's unproven receiver
		// (REQ-closure-shared-dynamic-state).
		markRHSMethodValues := func(rhs ast.Expr) {
			if seedingPass {
				return
			}
			calledFuns := map[ast.Node]bool{}
			ast.Inspect(rhs, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					calledFuns[unparenExpr(call.Fun)] = true
				}
				return true
			})
			ast.Inspect(rhs, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || calledFuns[sel] {
					// A called method's receiver is priced by the call's
					// own arm - only the BOUND value retains.
					return true
				}
				if selection, selOK := p.TypesInfo.Selections[sel]; selOK && selection.Kind() == types.MethodVal {
					ast.Inspect(sel.X, func(inner ast.Node) bool {
						if ident, ok := inner.(*ast.Ident); ok {
							if obj, ok := resolve(ident); ok {
								if variable, ok := dynamicPackageVar(obj); ok {
									explainMark(p, "escape", dynamicVarKey(variable), ident.Pos())
									escaped[dynamicVarKey(variable)] = true
								} else {
									for key := range aliased[obj] {
										explainMark(p, "escape", key, ident.Pos())
										escaped[key] = true
									}
								}
							}
						}
						return true
					})
				}
				return true
			})
		}
		bind := func(target ast.Expr, keys, lkeys map[string]bool) bool {
			if len(keys) == 0 {
				return false
			}
			// A composite-target binding (s.m = Hooks, a[i] = Hooks, *p =
			// Hooks) makes the whole base a carrier: a later literal
			// writing through the composite writes carrier state, so the
			// base binds coarsely - fail-closed, closing the recorded
			// composite-target residue.
			composite := false
		unwrap:
			for {
				switch t := target.(type) {
				case *ast.ParenExpr:
					target = t.X
				case *ast.SelectorExpr:
					target = t.X
					composite = true
				case *ast.IndexExpr:
					target = t.X
					composite = true
				case *ast.StarExpr:
					target = t.X
					composite = true
				default:
					break unwrap
				}
			}
			ident, ok := target.(*ast.Ident)
			if !ok {
				return false
			}
			obj, ok := resolve(ident)
			if !ok {
				return false
			}
			if _, isPkg := obj.(*types.PkgName); isPkg {
				// A package-qualified composite target (reg.Var = ...) is
				// the qualified-store class, not a local binding: aliasing
				// the package name would make every later reg.X mention a
				// spurious carrier touch.
				return false
			}
			if variable, pkg := dynamicPackageVar(obj); pkg {
				// A carrier bound from another carrier shares its
				// backing: the two keys link as one storage, mutation,
				// escape, and environment marks crossing the pair at
				// composition; reach-free sources and call results
				// record no link key and stay unlinked
				// (REQ-closure-shared-dynamic-state).
				if carrierLinks != nil && !seedingPass {
					own := dynamicVarKey(variable)
					for key := range lkeys {
						if key == own {
							continue
						}
						if carrierLinks[own] == nil {
							carrierLinks[own] = map[string]bool{}
						}
						carrierLinks[own][key] = true
					}
				}
				return false
			}
			if !composite && !typeHandsOutDynamicAlias(audited, obj.Type(), make(map[types.Type]bool)) {
				// A composite binding skips the type gate: the stored
				// carrier keys are themselves the proof the base now
				// reaches carrier state, whatever the base's own type
				// would hand out.
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
							markRHSMethodValues(rhs)
							lkeys := linkKeys(rhs)
							if bind(n.Lhs[i], rhsKeys(rhs), lkeys) {
								changed = true
							}
							storeLink(n.Lhs[i], lkeys)
						}
					} else if len(n.Rhs) == 1 {
						markRHSMethodValues(n.Rhs[0])
						keys := rhsKeys(n.Rhs[0])
						lkeys := linkKeys(n.Rhs[0])
						for _, lhs := range n.Lhs {
							if bind(lhs, keys, lkeys) {
								changed = true
							}
							storeLink(lhs, lkeys)
						}
					}
				case *ast.ValueSpec:
					// A declaration binding aliases exactly as an
					// assignment binding does.
					if len(n.Names) == len(n.Values) {
						for i, name := range n.Names {
							markRHSMethodValues(n.Values[i])
							if bind(name, rhsKeys(n.Values[i]), linkKeys(n.Values[i])) {
								changed = true
							}
						}
					} else if len(n.Values) == 1 {
						markRHSMethodValues(n.Values[0])
						keys := rhsKeys(n.Values[0])
						lkeys := linkKeys(n.Values[0])
						for _, name := range n.Names {
							if bind(name, keys, lkeys) {
								changed = true
							}
						}
					}
				case *ast.RangeStmt:
					keys := rhsKeys(n.X)
					lkeys := linkKeys(n.X)
					for _, target := range []ast.Expr{n.Key, n.Value} {
						if target != nil && bind(target, keys, lkeys) {
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
							lkeys := linkKeys(n.Args[1])
							if bind(n.Args[0], rhsKeys(n.Args[1]), lkeys) {
								changed = true
							}
							storeLink(n.Args[0], lkeys)
						}
					}
					// A qualified helper's parameter binds at the init
					// call site: the argument's carrier keys seed the
					// parameter for the helper's own scan, and the
					// package-level fixpoint carries the seeds across
					// bodies - closing the recorded helper-parameter
					// residue. The binding takes the same alias-handing
					// type gate as a whole-identifier bind - a by-value
					// carrier cannot be rebound through the argument -
					// and every call spelling of the helper binds
					// (parenthesized, generic-instantiated). Excess
					// variadic arguments seed the final parameter.
					callee := n.Fun
				unwrapFun:
					for {
						switch f := callee.(type) {
						case *ast.ParenExpr:
							callee = f.X
						case *ast.IndexExpr:
							callee = f.X
						case *ast.IndexListExpr:
							callee = f.X
						default:
							break unwrapFun
						}
					}
					if ident, ok := callee.(*ast.Ident); ok {
						if fn, ok := p.TypesInfo.Uses[ident].(*types.Func); ok {
							if params := initOnlyParams[fn]; len(params) != 0 {
								variadic := false
								if sig, ok := fn.Type().(*types.Signature); ok {
									variadic = sig.Variadic()
								}
								for i, arg := range n.Args {
									slot := min(i, len(params)-1)
									param := params[slot]
									if param == nil {
										continue
									}
									// A non-spread variadic argument is
									// copied into a fresh slice: the gate
									// judges the ELEMENT type the value
									// lands as, not the slice the helper
									// sees.
									gateType := param.Type()
									if variadic && slot == len(params)-1 && n.Ellipsis == token.NoPos {
										if slice, ok := types.Unalias(gateType).(*types.Slice); ok {
											gateType = slice.Elem()
										}
									}
									if !typeHandsOutDynamicAlias(audited, gateType, make(map[types.Type]bool)) {
										continue
									}
									for key := range rhsKeys(arg) {
										if paramSeeds[param] == nil {
											paramSeeds[param] = map[string]bool{}
										}
										if !paramSeeds[param][key] {
											paramSeeds[param][key] = true
											paramSeedGrowth = true
										}
									}
								}
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
		if !typeHandsOutDynamicAlias(audited, variable.Type(), make(map[types.Type]bool)) {
			// A non-alias-handing carrier (a func-typed hook, a by-value
			// struct) cannot be rebound through the argument - the ident
			// arm already classifies it without an escape, and no
			// leak-free fact exists to resolve a deferral against.
			return nil, nil
		}
		return target, variable
	}
	deferCarrierArgs := func(n *ast.CallExpr, sink map[string]map[string]bool, kind byte, onDeferred func(*ast.Ident)) {
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
			if sink[key] == nil {
				sink[key] = map[string]bool{}
			}
			paramKey := pkgPath + "\x00" + fn.Name() + "\x00" + strconv.Itoa(idx)
			sink[key][paramKey] = true
			explainDeferralMark(p, kind, key, paramKey, target.Pos())
			if onDeferred != nil {
				onDeferred(target)
			}
		}
	}
	// poolCarrierIdent resolves an audited pooling call's receiver
	// expression to the package-level sync.Pool carrier it names — the
	// pool variable itself, or an element of a package-level array or
	// slice of sync.Pool indexed directly on the variable — returning
	// the receiver ident and the carrier variable. Any other receiver
	// shape — a local, an alias, a qualified or computed base — names no
	// admitted carrier and keeps the fail-closed judgment
	// (REQ-closure-shared-dynamic-state).
	poolCarrierIdent := func(recv ast.Expr) (*ast.Ident, *types.Var) {
		ident, isIdent := recv.(*ast.Ident)
		element := false
		if !isIdent {
			index, isIndex := recv.(*ast.IndexExpr)
			if !isIndex {
				return nil, nil
			}
			ident, isIdent = index.X.(*ast.Ident)
			if !isIdent {
				return nil, nil
			}
			element = true
		}
		obj, ok := resolve(ident)
		if !ok {
			return nil, nil
		}
		variable, ok := obj.(*types.Var)
		if !ok || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
			return nil, nil
		}
		t := types.Unalias(variable.Type())
		if element {
			switch sequence := t.(type) {
			case *types.Array:
				t = types.Unalias(sequence.Elem())
			case *types.Slice:
				t = types.Unalias(sequence.Elem())
			default:
				return nil, nil
			}
		}
		named, ok := t.(*types.Named)
		if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
			return nil, nil
		}
		if named.Obj().Pkg().Path() != "sync" || named.Obj().Name() != "Pool" {
			return nil, nil
		}
		return ident, variable
	}
	// dischargePool records one fired pooling admission for the audit
	// record: a load-bearing attestation must be visible on the evidence
	// of every subject reaching the pool, never silent — the
	// vouch-recording discipline (REQ-vouch-recorded). The content-proven
	// discharge fires through the same gates but records nothing here:
	// it is the engine's own verdict, not a caller assertion
	// (REQ-closure-shared-dynamic-state), and poolDischarged is nil
	// without the attestation.
	dischargePool := func(variable *types.Var) {
		if poolDischarged != nil {
			poolDischarged[dynamicVarKey(variable)] = true
		}
	}
	// provenCalls marks each Get/Put call selector that the
	// content-proven discharge admits without the attestation: a
	// conforming call on a surviving proven pool, derived in one place
	// (provenSharedPools) so both admission gates — program code and
	// the init-exempt regions — and the eviction judge one shape
	// (REQ-closure-shared-dynamic-state). Skipped under the
	// attestation, whose admission is broader.
	provenCalls := map[*ast.SelectorExpr]bool{}
	if !singleSubject {
		_, provenCalls = provenSharedPools(audited, p)
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
						if typeHandsOutDynamicAlias(audited, variable.Type(), make(map[types.Type]bool)) {
							explainMark(p, "escape", dynamicVarKey(variable), ident.Pos())
							escaped[dynamicVarKey(variable)] = true
						}
					} else {
						for key := range aliasedLocals[obj] {
							explainMark(p, "escape", key, ident.Pos())
							escaped[key] = true
						}
					}
				}
			}
			return true
		})
	}
	scanExemptCalls := func(body ast.Node) {
		if initParamUses == nil || body == nil {
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
					deferCarrierArgs(n, initParamUses, 'q', nil)
				} else if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
					// A method call's receiver is handed to the callee
					// exactly as an argument is: a statically dispatched
					// non-interface method on a carrier receiver defers to
					// the method's receiver retention proof - writes are
					// the region's own exempt shape, only escape or
					// outliving refuses - and every other shape escapes
					// fail-closed; a dispatched func value's base is a
					// callee-position read, tolerated like every call
					// (REQ-closure-shared-dynamic-state).
					if selection, selOK := p.TypesInfo.Selections[sel]; selOK && selection.Kind() == types.MethodVal {
						deferred := false
						var poolVar *types.Var
						if fn, fnOK := selection.Obj().(*types.Func); fnOK && (singleSubject || provenCalls[sel]) && auditedPooling(audited, fn) {
							_, poolVar = poolCarrierIdent(sel.X)
						}
						if poolVar != nil {
							// The audited pooling set: under the
							// caller-attested single-subject-process
							// execution model — or, without it, under
							// the content-proven discharge for a
							// conforming call on a proven pool — a Get
							// or Put CALL on a
							// package-level sync.Pool carrier marks
							// nothing for the pool in init flow exactly
							// as in program code; the call's arguments
							// keep the region's own pricing below, and an
							// indexed receiver's index expression keeps
							// the escape sweep
							// (REQ-closure-shared-dynamic-state).
							dischargePool(poolVar)
							if index, isIndex := sel.X.(*ast.IndexExpr); isIndex {
								markExemptEscapes(index.Index)
							}
							deferred = true
						} else if fn, fnOK := selection.Obj().(*types.Func); fnOK && !interfaceReceiver(fn) && instantiatedResultsHandOutNothing(audited, selection.Type()) {
							if ident, idOK := sel.X.(*ast.Ident); idOK {
								if obj, rOK := resolve(ident); rOK {
									if variable, vOK := dynamicPackageVar(obj); vOK {
										key := dynamicVarKey(variable)
										if initMethodUses[key] == nil {
											initMethodUses[key] = map[string]bool{}
										}
										initMethodUses[key][methodFactKey(fn)] = true
										explainDeferralMark(p, 'n', key, methodFactKey(fn), sel.Pos())
										deferred = true
									}
								}
							}
						}
						if !deferred {
							markExemptEscapes(sel.X)
						}
					}
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
				// A comma-ok existence read whose element lands in a
				// blank produces no value to hand out - writeless on any
				// carrier, whatever the element type
				// (REQ-closure-shared-dynamic-state).
				if len(n.Lhs) == 2 && len(n.Rhs) == 1 {
					if blank, ok := n.Lhs[0].(*ast.Ident); ok && blank.Name == "_" {
						if index, ok := unparenExpr(n.Rhs[0]).(*ast.IndexExpr); ok {
							markRead(unparenExpr(index.X))
						}
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
						var wants, methodWants, fieldWants, elemWants map[string]bool
						var returned bool
						var retPtr *bool
						if paramUses != nil {
							wants = map[string]bool{}
							if methodUses != nil {
								methodWants = map[string]bool{}
							}
							if fieldUses != nil {
								fieldWants = map[string]bool{}
							}
							if elemUses != nil {
								elemWants = map[string]bool{}
							}
							if currentFn != nil && currentFn.Recv == nil && currentFn.Name != nil && !currentFn.Name.IsExported() && currentFn.Name.Name != "init" {
								retPtr = &returned
							}
						}
						if sound && (len(roots) == 0 || boundValueLeakFreeJudged(audited, p, roots, n.Body, wants, retPtr, methodWants, fieldWants, elemWants)) {
							if len(wants) == 0 && len(methodWants) == 0 && len(fieldWants) == 0 && len(elemWants) == 0 && !returned {
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
											explainDeferralMark(p, 'p', key, want, n.X.Pos())
										}
										if len(methodWants) > 0 && methodUses[key] == nil {
											methodUses[key] = map[string]bool{}
										}
										for want := range methodWants {
											methodUses[key][want] = true
											explainDeferralMark(p, 'm', key, want, n.X.Pos())
										}
										if len(fieldWants) > 0 && fieldUses[key] == nil {
											fieldUses[key] = map[string]bool{}
										}
										for want := range fieldWants {
											fieldUses[key][want] = true
											explainDeferralMark(p, 'f', key, want, n.X.Pos())
										}
										if len(elemWants) > 0 && elemUses[key] == nil {
											elemUses[key] = map[string]bool{}
										}
										for want := range elemWants {
											elemUses[key][want] = true
											explainDeferralMark(p, 'e', key, want, n.X.Pos())
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
					// Taking the address of a composite literal captures
					// the fresh object alone — no existing variable's cell
					// is reachable through the pointer. The literal's
					// element references stay escapes (the fresh object's
					// holder may write what it was handed), judged by the
					// ident arm exactly as an un-addressed composite's;
					// a nested address capture inside the literal marks
					// through its own visit
					// (REQ-closure-shared-dynamic-state).
					if _, composite := unparenExpr(n.X).(*ast.CompositeLit); !composite || n.Op == token.ARROW {
						markTargets(n.X)
					}
				}
			case *ast.IndexExpr:
				// The discharge holds only when the produced element is
				// not itself alias-handing - an indexed-out map or slice
				// still writes through; a comma-ok context's recorded
				// tuple type keeps the fail-closed default, and its
				// blank-target admission is the assignment arm's
				// (REQ-closure-shared-dynamic-state).
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
					deferCarrierArgs(n, paramUses, 'p', func(target *ast.Ident) {
						readContext[target] = true
					})
				}
				// A carrier argument to a callee-position index read of
				// another carrier (the dispatch-table shape
				// legs[token](arg)) defers to the dispatch carrier's
				// element population - never from a go statement, and
				// init flow keeps the escape like every deferral
				// (REQ-closure-shared-dynamic-state).
				if elemUses != nil && !goCalls[n] {
					if index, ok := unparenExpr(n.Fun).(*ast.IndexExpr); ok {
						if base, ok := unparenExpr(index.X).(*ast.Ident); ok {
							if obj, ok := resolve(base); ok {
								if owner, ok := dynamicPackageVar(obj); ok {
									if sig, ok := types.Unalias(p.TypesInfo.TypeOf(n.Fun)).Underlying().(*types.Signature); ok {
										ownerKey := dynamicVarKey(owner)
										for i, arg := range n.Args {
											ident, ok := unparenExpr(arg).(*ast.Ident)
											if !ok {
												continue
											}
											aobj, ok := resolve(ident)
											if !ok {
												continue
											}
											variable, ok := dynamicPackageVar(aobj)
											if !ok || !typeHandsOutDynamicAlias(audited, variable.Type(), make(map[types.Type]bool)) {
												continue
											}
											idx := i
											if sig.Variadic() && idx >= sig.Params().Len()-1 {
												idx = sig.Params().Len() - 1
											}
											argKey := dynamicVarKey(variable)
											want := ownerKey + "\x01" + strconv.Itoa(idx)
											if elemUses[argKey] == nil {
												elemUses[argKey] = map[string]bool{}
											}
											elemUses[argKey][want] = true
											explainDeferralMark(p, 'e', argKey, want, arg.Pos())
											readContext[ident] = true
										}
									}
								}
							}
						}
					}
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
						// The audited pooling set: under the
						// caller-attested single-subject-process
						// execution model, a Get or Put CALL on a
						// package-level sync.Pool carrier — the pool
						// variable itself or an element of a
						// package-level array or slice of sync.Pool —
						// marks nothing for the pool: every in-process
						// Put site lies in the subject's own rooted
						// flow, so pool contents are a function of the
						// analyzed source and the subject alone, and
						// their contractual removability is why the
						// values need no per-item pricing at the call.
						// The values passed and produced keep their own
						// full pricing; without the attestation a call
						// is admitted only through the content-proven
						// discharge (a conforming call on a proven
						// pool), and for
						// every other use — a write, a rebinding, an
						// address capture, an escape, a method-value
						// bind, a New-field access outside init flow —
						// the fail-closed judgment stands
						// (REQ-closure-shared-dynamic-state).
						if (singleSubject || provenCalls[n]) && calledSelectors[n] && auditedPooling(audited, fn) {
							if ident, variable := poolCarrierIdent(n.X); variable != nil {
								dischargePool(variable)
								readContext[ident] = true
								return true
							}
						}
						if methodUses != nil && calledSelectors[n] && !interfaceReceiver(fn) && instantiatedResultsHandOutNothing(audited, selection.Type()) {
							if ident, ok := n.X.(*ast.Ident); ok {
								if obj, ok := resolve(ident); ok {
									if variable, ok := dynamicPackageVar(obj); ok {
										key := dynamicVarKey(variable)
										if methodUses[key] == nil {
											methodUses[key] = map[string]bool{}
										}
										factKey := methodFactKey(fn)
										methodUses[key][factKey] = true
										explainDeferralMark(p, 'm', key, factKey, n.Pos())
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
					if variable, ok := dynamicPackageVar(obj); ok && typeHandsOutDynamicAlias(audited, variable.Type(), make(map[types.Type]bool)) {
						explainMark(p, "escape", dynamicVarKey(variable), n.Pos())
						escaped[dynamicVarKey(variable)] = true
					} else {
						// An init-flow local aliasing a carrier is the
						// carrier inside program code.
						for key := range aliasedLocals[obj] {
							explainMark(p, "escape", key, n.Pos())
							escaped[key] = true
						}
					}
				}
			}
			return true
		})
	}
	// The helper-parameter seed fixpoint runs the alias scan over every
	// init-flow body until no call site grows a parameter's seed set,
	// advisory side channels suppressed; the main walk below then scans
	// each body once with the converged seeds in force.
	if len(initOnlyParams) != 0 {
		seedingPass = true
		for {
			paramSeedGrowth = false
			for _, file := range p.Syntax {
				for _, decl := range file.Decls {
					switch decl := decl.(type) {
					case *ast.FuncDecl:
						if decl.Recv == nil && decl.Name != nil && decl.Body != nil && (decl.Name.Name == "init" || initOnly[decl.Name.Name]) {
							initAliasedLocals(decl.Body)
						}
					case *ast.GenDecl:
						initAliasedLocals(decl)
					}
				}
			}
			if !paramSeedGrowth {
				break
			}
		}
		seedingPass = false
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				methodKey := ""
				if decl.Recv != nil && decl.Name != nil && attributed != nil && decl.Body != nil && p.Types != nil {
					// The key derives from the SEMANTIC receiver — the
					// method-fact spelling over the unaliased defined
					// type — never the written (possibly alias) receiver
					// name: the rooted-flow inventory keys the same way,
					// and a spelling mismatch would let a rooted marking
					// site discharge (REQ-closure-shared-dynamic-state).
					if fn, ok := p.TypesInfo.Defs[decl.Name].(*types.Func); ok && fn != nil {
						if key := methodFactKey(fn); !strings.Contains(key, "\x00.") {
							methodKey = key
						}
					}
				}
				if methodKey != "" {
					// A method's carrier uses attribute to it under the
					// type-qualified key ("pkg\x00Type.Method", the
					// method-fact spelling): a method is never init flow,
					// so composition promotes the marks unconditionally —
					// the same final marks the immediate maps produced —
					// while the reachability scopings gain the site.
					// Literals and go statements inside attribute to the
					// method as literal-borne sites: their execution
					// requires the method to have run, so an
					// init-unreachable method no root reaches bounds them
					// — composition still never init-discharges them and
					// forecloses under init reach
					// (REQ-closure-shared-dynamic-state).
					fnKey := methodKey
					litMutated, litEscaped := map[string]bool{}, map[string]bool{}
					litMethods := map[string]map[string]bool{}
					interiors := map[ast.Node]bool{}
					saveLM, saveLE, saveLMU := mutated, escaped, methodUses
					mutated, escaped, methodUses = litMutated, litEscaped, litMethods
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
					mutated, escaped, methodUses = saveLM, saveLE, saveLMU
					for key := range litMutated {
						*attributed = append(*attributed, attributedUse{fn: fnKey, key: key, literal: true})
					}
					for key := range litEscaped {
						*attributed = append(*attributed, attributedUse{fn: fnKey, key: key, escape: true, literal: true})
					}
					for key, methods := range litMethods {
						for method := range methods {
							*attributed = append(*attributed, attributedUse{fn: fnKey, key: key, method: method, literal: true})
						}
					}
					localMutated, localEscaped := map[string]bool{}, map[string]bool{}
					localMethods := map[string]map[string]bool{}
					saveM, saveE, saveMU := mutated, escaped, methodUses
					mutated, escaped, methodUses = localMutated, localEscaped, localMethods
					skipInteriors = interiors
					walkBody(decl.Body)
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
				if decl.Recv == nil && decl.Name != nil && attributed != nil && !initOnly[decl.Name.Name] && decl.Name.Name != "init" && decl.Body != nil {
					// A plain named function's carrier uses attribute to
					// it: the cross-package fixed point decides at
					// composition whether they are init flow. Literals
					// and go statements nested in the body attribute to
					// it as literal-borne sites (never init-discharged,
					// foreclosing under init reach).
					fnKey := ""
					if p.Types != nil {
						fnKey = p.Types.Path() + "\x00" + decl.Name.Name
					}
					litMutated, litEscaped := map[string]bool{}, map[string]bool{}
					litMethods := map[string]map[string]bool{}
					interiors := map[ast.Node]bool{}
					saveLM, saveLE, saveLMU := mutated, escaped, methodUses
					mutated, escaped, methodUses = litMutated, litEscaped, litMethods
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
					mutated, escaped, methodUses = saveLM, saveLE, saveLMU
					if fnKey != "" {
						for key := range litMutated {
							*attributed = append(*attributed, attributedUse{fn: fnKey, key: key, literal: true})
						}
						for key := range litEscaped {
							*attributed = append(*attributed, attributedUse{fn: fnKey, key: key, escape: true, literal: true})
						}
						for key, methods := range litMethods {
							for method := range methods {
								*attributed = append(*attributed, attributedUse{fn: fnKey, key: key, method: method, literal: true})
							}
						}
					} else {
						// No attributable key: the marks stay immediate,
						// unattributed, foreclosing exactly as before.
						for key := range litMutated {
							mutated[key] = true
						}
						for key := range litEscaped {
							escaped[key] = true
						}
						for key, methods := range litMethods {
							for method := range methods {
								if methodUses[key] == nil {
									methodUses[key] = map[string]bool{}
								}
								methodUses[key][method] = true
							}
						}
					}
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
				// earn the same deferral as an init body's. The alias
				// scan runs here too: a package-level carrier bound from
				// another carrier records the storage link.
				aliasedLocals = initAliasedLocals(decl)
				ast.Inspect(decl, func(n ast.Node) bool {
					if lit, ok := n.(*ast.FuncLit); ok && lit.Body != nil {
						walkBody(lit.Body)
						return false
					}
					return true
				})
				scanExemptCalls(decl)
				aliasedLocals = nil
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
					var siteMethodWants, siteFieldWants, siteElemWants map[string]bool
					if methodUses != nil {
						siteMethodWants = map[string]bool{}
					}
					if fieldUses != nil {
						siteFieldWants = map[string]bool{}
					}
					if elemUses != nil {
						siteElemWants = map[string]bool{}
					}
					var siteReturned bool
					var siteRet *bool
					if siteEligible {
						siteRet = &siteReturned
					}
					if !boundValueLeakFreeJudged(audited, p, roots, body, siteWants, siteRet, siteMethodWants, siteFieldWants, siteElemWants) {
						bad[fnName] = true
						return true
					}
					for want := range siteWants {
						for key := range returnerKeys[fnName] {
							if paramUses[key] == nil {
								paramUses[key] = map[string]bool{}
							}
							paramUses[key][want] = true
							explainDeferralMark(p, 'p', key, want, call.Pos())
						}
					}
					for want := range siteMethodWants {
						for key := range returnerKeys[fnName] {
							if methodUses[key] == nil {
								methodUses[key] = map[string]bool{}
							}
							methodUses[key][want] = true
							explainDeferralMark(p, 'm', key, want, call.Pos())
						}
					}
					for want := range siteFieldWants {
						for key := range returnerKeys[fnName] {
							if fieldUses[key] == nil {
								fieldUses[key] = map[string]bool{}
							}
							fieldUses[key][want] = true
							explainDeferralMark(p, 'f', key, want, call.Pos())
						}
					}
					for want := range siteElemWants {
						for key := range returnerKeys[fnName] {
							if elemUses[key] == nil {
								elemUses[key] = map[string]bool{}
							}
							elemUses[key][want] = true
							explainDeferralMark(p, 'e', key, want, call.Pos())
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
					explainMark(p, "escape", key, token.NoPos)
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

// callResultHandsOut reports whether a call's result set can hand its
// consumer carrier-derived state: any result - the single result type, or
// any element of a multi-result tuple - that hands out mutable reach or
// carries a signature refuses. A void call hands out nothing. Missing
// type information refuses, fail-closed like every judged value position.
func callResultHandsOut(t types.Type) bool {
	if t == nil {
		return true
	}
	if tuple, ok := t.(*types.Tuple); ok {
		for i := 0; i < tuple.Len(); i++ {
			rt := tuple.At(i).Type()
			if typeHandsOutMutableReach(rt, make(map[types.Type]bool)) || typeCarriesSignature(rt, make(map[types.Type]bool)) {
				return true
			}
		}
		return false
	}
	return typeHandsOutMutableReach(t, make(map[types.Type]bool)) || typeCarriesSignature(t, make(map[types.Type]bool))
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
func environmentFreeFuncLit(audited bool, p *packages.Package, lit *ast.FuncLit, enclosing ast.Node) bool {
	return environmentFreeFuncLitJudged(audited, p, lit, enclosing, nil, nil)
}

// environmentFreeFuncLitJudged additionally collects parameter and
// method wants when the caller supplies sinks, instead of refusing the
// deferrable shapes outright - the constructor-result proof resolves the
// collected wants against its own package's facts
// (REQ-closure-shared-dynamic-state).
func environmentFreeFuncLitJudged(audited bool, p *packages.Package, lit *ast.FuncLit, enclosing ast.Node, wants, methodWants map[string]bool) bool {
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
	if !boundValueLeakFreeJudged(audited, p, roots, lit.Body, wants, nil, methodWants, nil, nil) {
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
			if shared && !boundValueLeakFreeJudged(audited, p, roots, n.Body, wants, nil, methodWants, nil, nil) {
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
// fieldRegMark is one registered-population disposition for a
// func-signature struct field a carrier can hand out: class 'd' defers the
// field position to a parameter's leak-free fact, class 'p' poisons it. A
// poison with field "" covers the whole population, idx -1 every index.
type fieldRegMark struct {
	class byte
	field string
	idx   int
	param string
}

// classifyFieldRegistrants derives the registered-population marks of one
// admitted registration store: a store targeting a func-signature field
// directly registers its value at that field; every other store's flowing
// value is classified structurally. Any shape the classifier cannot
// attribute poisons the whole population - the discharge over an
// enumerated population is sound only when the enumeration is complete
// (REQ-closure-shared-dynamic-state).
func classifyFieldRegistrants(audited bool, p *packages.Package, lhs, rhs ast.Expr, emit func(fieldRegMark)) {
	if sel, ok := unparenExpr(lhs).(*ast.SelectorExpr); ok {
		if selection, ok := p.TypesInfo.Selections[sel]; ok && selection.Kind() == types.FieldVal {
			if _, isSig := types.Unalias(selection.Type()).Underlying().(*types.Signature); isSig {
				classifyFieldRegistrantValue(audited, p, sel.Sel.Name, rhs, emit)
				return
			}
		}
	}
	classifyRegistrantFlow(audited, p, rhs, emit)
}

func unparenExpr(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

// elemPositionField is the reserved position name for a carrier's own
// element population - the values a callee-position index read can
// invoke (legs[token](args)). No Go identifier can collide with it, so
// it shares the field-mark encoding and resolution unchanged
// (REQ-closure-shared-dynamic-state).
const elemPositionField = "\x02"

// classifyRegistrantFlow classifies a whole value flowing into carrier
// storage. A bare function value is an element-population registrant -
// a callee-position index read can invoke it, so it dispositions at
// the reserved element position; call results join the population
// through the callee's return-environment-free field marks
// (EnvCallUses names the callee). Everything else that can carry a
// function is unattributable here: whole-population poison.
func classifyRegistrantFlow(audited bool, p *packages.Package, expr ast.Expr, emit func(fieldRegMark)) {
	switch e := unparenExpr(expr).(type) {
	case *ast.CompositeLit:
		classifyRegistrantComposite(audited, p, e, emit)
		return
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			classifyRegistrantFlow(audited, p, e.X, emit)
			return
		}
	case *ast.FuncLit:
		classifyLiteralRegistrant(audited, p, elemPositionField, e, emit)
		return
	case *ast.BasicLit:
		return
	case *ast.CallExpr:
		// An admitted call is the constructor channel: the result's
		// body-built values are the callee's recorded field marks, but a
		// value handed in as an argument reaches the result only through
		// the constructor's parameters - it is in hand here, so it is
		// classified at the store site exactly as a directly stored
		// value (the constructor's side poisons any parameter it places
		// into a func-signature field). Builtin make and new construct
		// empty values and their type argument is not a value - nothing
		// to classify.
		if ident, ok := unparenExpr(e.Fun).(*ast.Ident); ok {
			if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && (ident.Name == "make" || ident.Name == "new") {
				return
			}
		}
		for _, arg := range e.Args {
			classifyRegistrantFlow(audited, p, arg, emit)
		}
		return
	case *ast.Ident:
		if obj, ok := identUseOrDef(p, e); ok {
			switch obj.(type) {
			case *types.Func:
				classifyFieldRegistrantValue(audited, p, elemPositionField, e, emit)
				return
			case *types.Nil:
				return
			}
		}
	case *ast.SelectorExpr:
		if obj, ok := p.TypesInfo.Uses[e.Sel]; ok {
			if _, isFunc := obj.(*types.Func); isFunc {
				classifyFieldRegistrantValue(audited, p, elemPositionField, e, emit)
				return
			}
		}
	}
	if typeCarriesSignature(p.TypesInfo.TypeOf(unparenExpr(expr)), make(map[types.Type]bool)) {
		emit(fieldRegMark{class: 'p', idx: -1})
	}
}

func identUseOrDef(p *packages.Package, ident *ast.Ident) (types.Object, bool) {
	if obj, ok := p.TypesInfo.Uses[ident]; ok {
		return obj, true
	}
	if obj, ok := p.TypesInfo.Defs[ident]; ok && obj != nil {
		return obj, true
	}
	return nil, false
}

// classifyRegistrantComposite pools registrants by struct field name across
// every composite level - the use side keys wants by the immediate field
// name of whatever binding it judged, and a nested value can become such a
// binding through the taint chain, so all levels share one namespace;
// pooling only ever adds constraints.
func classifyRegistrantComposite(audited bool, p *packages.Package, lit *ast.CompositeLit, emit func(fieldRegMark)) {
	t := p.TypesInfo.TypeOf(lit)
	if t == nil {
		emit(fieldRegMark{class: 'p', idx: -1})
		return
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Struct:
		for i, elt := range lit.Elts {
			var field *types.Var
			value := elt
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				value = kv.Value
				if key, ok := kv.Key.(*ast.Ident); ok {
					for j := 0; j < u.NumFields(); j++ {
						if u.Field(j).Name() == key.Name {
							field = u.Field(j)
							break
						}
					}
				}
			} else if i < u.NumFields() {
				field = u.Field(i)
			}
			if field == nil {
				emit(fieldRegMark{class: 'p', idx: -1})
				continue
			}
			if _, isSig := types.Unalias(field.Type()).Underlying().(*types.Signature); isSig {
				classifyFieldRegistrantValue(audited, p, field.Name(), value, emit)
				continue
			}
			classifyRegistrantFlow(audited, p, value, emit)
		}
	case *types.Map, *types.Slice, *types.Array:
		for _, elt := range lit.Elts {
			value := elt
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				value = kv.Value
			}
			classifyRegistrantFlow(audited, p, value, emit)
		}
	default:
		emit(fieldRegMark{class: 'p', idx: -1})
	}
}

// classifyFieldRegistrantValue dispositions one value registered at a
// func-signature field. A plain named function defers every parameter
// index to its leak-free fact; a function literal is judged here, each
// parameter proving leak-free with its own collected deferrals; nil
// registers nothing. Method values and expressions carry a receiver frame
// no leak-free fact covers, and every unrecognized shape is
// unattributable - poison, fail-closed.
func classifyFieldRegistrantValue(audited bool, p *packages.Package, field string, value ast.Expr, emit func(fieldRegMark)) {
	deferNamed := func(fn *types.Func) bool {
		if fn == nil || fn.Pkg() == nil {
			return false
		}
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() != nil {
			return false
		}
		for idx := 0; idx < sig.Params().Len(); idx++ {
			emit(fieldRegMark{class: 'd', field: field, idx: idx, param: fn.Pkg().Path() + "\x00" + fn.Name() + "\x00" + strconv.Itoa(idx)})
		}
		return true
	}
	switch v := unparenExpr(value).(type) {
	case *ast.FuncLit:
		classifyLiteralRegistrant(audited, p, field, v, emit)
		return
	case *ast.Ident:
		if obj, ok := identUseOrDef(p, v); ok {
			if _, isNil := obj.(*types.Nil); isNil {
				return
			}
			if fn, ok := obj.(*types.Func); ok && deferNamed(fn) {
				return
			}
		}
	case *ast.SelectorExpr:
		if _, isSelection := p.TypesInfo.Selections[v]; !isSelection {
			if x, ok := v.X.(*ast.Ident); ok {
				if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
					if fn, ok := p.TypesInfo.Uses[v.Sel].(*types.Func); ok && deferNamed(fn) {
						return
					}
				}
			}
		}
	}
	emit(fieldRegMark{class: 'p', field: field, idx: -1})
}

func classifyLiteralRegistrant(audited bool, p *packages.Package, field string, lit *ast.FuncLit, emit func(fieldRegMark)) {
	if lit.Type == nil || lit.Body == nil {
		emit(fieldRegMark{class: 'p', field: field, idx: -1})
		return
	}
	idx := 0
	if lit.Type.Params != nil {
		for _, group := range lit.Type.Params.List {
			names := group.Names
			if len(names) == 0 {
				// An unnamed parameter cannot be referenced - leak-free
				// trivially, it still occupies its index.
				idx++
				continue
			}
			for _, name := range names {
				if name.Name == "_" {
					idx++
					continue
				}
				obj := p.TypesInfo.Defs[name]
				if obj == nil {
					emit(fieldRegMark{class: 'p', field: field, idx: idx})
					idx++
					continue
				}
				wants := map[string]bool{}
				if boundValueLeakFreeJudged(audited, p, map[types.Object]bool{obj: true}, lit.Body, wants, nil, nil, nil, nil) {
					for want := range wants {
						emit(fieldRegMark{class: 'd', field: field, idx: idx, param: want})
					}
				} else {
					emit(fieldRegMark{class: 'p', field: field, idx: idx})
				}
				idx++
			}
		}
	}
}

func recordEnvCarryingRegistrations(audited bool, p *packages.Package, envCarrying map[string]bool, envCalls, fieldDefer, fieldPoison map[string]map[string]bool) {
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
		if !typeMayCarryUnknownDynamic(audited, variable.Type(), make(map[types.Type]bool)) {
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
			if !typeHandsOutDynamicAlias(audited, obj.Type(), make(map[types.Type]bool)) {
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
			return !environmentFreeFuncLit(audited, p, e, enclosingBody)
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
		var poisonAt token.Pos
		for _, flow := range flows {
			if carrying(flow) {
				poison = true
				poisonAt = flow.Pos()
				break
			}
		}
		if poison {
			for _, variable := range targets {
				if h := explainHooks.Load(); h != nil && h.store != nil {
					h.store(p, dynamicVarKey(variable), poisonAt)
				}
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
			if fieldDefer != nil {
				var marks []fieldRegMark
				for _, flow := range flows {
					classifyFieldRegistrants(audited, p, lhs, flow, func(m fieldRegMark) {
						marks = append(marks, m)
					})
				}
				for _, variable := range targets {
					key := dynamicVarKey(variable)
					for _, m := range marks {
						switch m.class {
						case 'd':
							if fieldDefer[key] == nil {
								fieldDefer[key] = map[string]bool{}
							}
							fieldDefer[key][m.field+"\x00"+strconv.Itoa(m.idx)+"\x01"+m.param] = true
						case 'p':
							if fieldPoison[key] == nil {
								fieldPoison[key] = map[string]bool{}
							}
							if m.field == "" {
								fieldPoison[key][""] = true
							} else {
								fieldPoison[key][m.field+"\x00"+strconv.Itoa(m.idx)] = true
							}
						}
					}
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

// auditedValuePlane names the standard value-plane helpers whose
// results carry exactly their arguments' values - clone and
// concatenation shapes with no environment of their own. A closed
// set: absence keeps the refusal.
var auditedValuePlane = map[string]bool{
	"slices\x00Clone":  true,
	"slices\x00Concat": true,
	"maps\x00Clone":    true,
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
func returnEnvFreeFunctions(audited bool, p *packages.Package, paramLeakFree, readOnly map[string]bool) (map[string]bool, map[string]map[string]bool, map[string]map[string]bool, map[string]map[string]bool, map[string]bool, map[string]map[string]bool, map[string]map[string]bool) {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return nil, nil, nil, nil, nil, nil, nil
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
	retDefer := map[string]map[string]bool{}
	retPoison := map[string]map[string]bool{}
	// insFree marks fnName\x00idx parameters whose argument-storage
	// insertions all judge environment-free (possibly conditionally,
	// via insDeps edges); absence is poison, fail-closed
	// (REQ-closure-shared-dynamic-state's callees-join-their-populations
	// clause).
	insFree := map[string]bool{}
	insDeps := map[string]map[string]bool{}
	callerInsDeps := map[string]map[string]bool{}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name == nil || fd.Body == nil || fd.Name.Name == "init" {
				continue
			}
			fnKey := fd.Name.Name
			params := map[types.Object]bool{}
			// paramIndex keys each named parameter to its zero-based
			// declared index — the persisted insertion-fact key's third
			// segment; unnamed and blank parameters are unreferencable,
			// so their storage receives nothing and the index is
			// insertion-free by construction.
			paramIndex := map[types.Object]int{}
			paramCount := 0
			if fd.Type.Params != nil {
				for _, field := range fd.Type.Params.List {
					if len(field.Names) == 0 {
						insFree[fnKey+"\x00"+strconv.Itoa(paramCount)] = true
						paramCount++
						continue
					}
					for _, name := range field.Names {
						// A blank parameter is unreferencable whatever
						// go/types records for it - insertion-free by
						// construction like an unnamed one.
						if obj := p.TypesInfo.Defs[name]; obj != nil && name.Name != "_" {
							params[obj] = true
							paramIndex[obj] = paramCount
						} else {
							insFree[fnKey+"\x00"+strconv.Itoa(paramCount)] = true
						}
						paramCount++
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
			// insertionWrites holds values stored by DEEP writes into a
			// root's reachable storage: unattributable to a slot for the
			// return plane (the root breaks there, fail-closed), but for
			// a parameter component these are exactly the
			// argument-storage insertions the per-parameter fact judges
			// (REQ-closure-shared-dynamic-state).
			insertionWrites := map[types.Object][]ast.Expr{}
			localBroken := map[types.Object]bool{}
			// captureBroken records the fail-closed break causes alone —
			// captures, escapes, unattributable callees — separately from
			// the parameter-store rule: a parameter component broken only
			// by judged stores still gets a per-parameter insertion fact,
			// while a capture-broken component's insertions are
			// unknowable, poison.
			captureBroken := map[types.Object]bool{}
			// aliasPairs links bindings whose bound value shares its
			// backing header: the two names are one storage, so breaks,
			// the store union, and the parameter refusal all cross the
			// pair. heldPairs links a holder to the origin of a struct
			// or array value copied out of it: the copy's interior may
			// reach the origin's backing, so breaks cross the pair
			// fail-closed, but the holder's own storage stays its own -
			// slot writes never count as writes into the origin's.
			var aliasPairs [][2]types.Object
			var heldPairs [][2]types.Object
			// stmtCallDeps carries the plain named callees handed a
			// tracked binding anywhere in the body - their recorded
			// populations join this proof's over dependency edges
			// exactly like return-position callees'.
			stmtCallDeps := map[string]bool{}
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
								captureBroken[obj] = true
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
			// sharesHeader reports whether a value of the type shares
			// its backing when bound - a header or reference copy -
			// rather than copying its content. Struct and array values
			// copy; everything else (pointers, slices, maps, channels,
			// interfaces, type parameters, unknowns) is fail-closed
			// header-sharing.
			sharesHeader := func(t types.Type) bool {
				if t == nil {
					return true
				}
				switch types.Unalias(t).Underlying().(type) {
				case *types.Struct, *types.Array, *types.Basic:
					return false
				}
				return true
			}
			// linkBacking links a bound or written name to each
			// reach-bearing tracked name its source expression reaches.
			// The link kind follows the value that flows: a
			// header-sharing value makes the two names one storage - a
			// symmetric alias carrying breaks, the store union, and the
			// parameter refusal - while a struct or array value is a
			// copy whose interior may still reach the origin's backing:
			// a directional held link carrying breaks only, so slot
			// writes into the holder's own storage never count as
			// writes into the origin's. Both kinds are fail-closed
			// relative to their claim; reach-free values stay unlinked
			// as independent storage.
			pairLink := func(obj, sobj types.Object, shares bool) {
				if v, ok := sobj.(*types.Var); ok && v.IsField() {
					return
				}
				// Carrying parameters are themselves tracked, so
				// tracked alone covers every reach-relevant name.
				_, tracked := trackedVar(sobj)
				if !tracked || !typeHandsOutMutableReach(sobj.Type(), make(map[types.Type]bool)) {
					return
				}
				if shares {
					aliasPairs = append(aliasPairs, [2]types.Object{obj, sobj})
				} else {
					heldPairs = append(heldPairs, [2]types.Object{obj, sobj})
				}
			}
			var linkBacking func(obj types.Object, source ast.Expr)
			linkValue := func(obj types.Object, e ast.Expr, shares bool) {
				if ident, ok := chainRoot(e).(*ast.Ident); ok {
					sobj := p.TypesInfo.Uses[ident]
					if sobj == nil {
						sobj = p.TypesInfo.Defs[ident]
					}
					if sobj != nil {
						pairLink(obj, sobj, shares)
						return
					}
				}
				// No plain chain root - fall back to the blind walk,
				// every reached name linked as sharing: the value
				// relationship is unknown, and sharing is the
				// fail-closed kind.
				ast.Inspect(e, func(m ast.Node) bool {
					if id, ok := m.(*ast.Ident); ok {
						if sobj := p.TypesInfo.Uses[id]; sobj != nil {
							pairLink(obj, sobj, true)
						}
					}
					return true
				})
			}
			// linkBacking classifies a bound or stored source expression
			// by the value that flows out of each shape and links the
			// reached names accordingly.
			linkBacking = func(obj types.Object, source ast.Expr) {
				e := unparen(source)
				switch v := e.(type) {
				case *ast.Ident, *ast.SelectorExpr, *ast.IndexExpr, *ast.StarExpr, *ast.SliceExpr:
					linkValue(obj, e, sharesHeader(p.TypesInfo.TypeOf(e)))
				case *ast.CompositeLit:
					for _, elt := range v.Elts {
						value := elt
						if kv, ok := elt.(*ast.KeyValueExpr); ok {
							value = kv.Value
						}
						linkBacking(obj, value)
					}
				case *ast.UnaryExpr:
					if v.Op == token.AND {
						linkBacking(obj, v.X)
						return
					}
					linkValue(obj, e, true)
				case *ast.CallExpr:
					if fnIdent, ok := unparen(v.Fun).(*ast.Ident); ok {
						if _, builtin := p.TypesInfo.Uses[fnIdent].(*types.Builtin); builtin {
							switch fnIdent.Name {
							case "make", "new":
								return
							case "append":
								if len(v.Args) > 0 {
									linkValue(obj, v.Args[0], true)
									for _, arg := range v.Args[1:] {
										linkBacking(obj, arg)
									}
								}
								return
							}
						}
					}
					if tv, ok := p.TypesInfo.Types[v.Fun]; ok && tv.IsType() && len(v.Args) == 1 {
						linkBacking(obj, v.Args[0])
						return
					}
					// The callee expression itself may carry backing
					// into the result - a func literal's captures, a
					// value receiver's fields - blind-walked as
					// sharing, fail-closed.
					ast.Inspect(v.Fun, func(m ast.Node) bool {
						if id, ok := m.(*ast.Ident); ok {
							if sobj := p.TypesInfo.Uses[id]; sobj != nil {
								pairLink(obj, sobj, true)
							}
						}
						return true
					})
					for _, arg := range v.Args {
						linkBacking(obj, arg)
					}
				case *ast.BasicLit, *ast.FuncLit:
					// A literal carries no prior backing; a func literal's
					// captures are the escape walk's business, not
					// storage aliasing.
				default:
					linkValue(obj, e, true)
				}
			}
			// pendingStores defers element, field, and dereference
			// writes of present values until the walk completes: the
			// slot-versus-deep judgment needs every binding source
			// collected first.
			type pendingStore struct {
				robj   types.Object
				root   *ast.Ident
				target ast.Expr
				source ast.Expr
			}
			var pendingStores []pendingStore
			// pendingInsertionUses records a plain named callee handed a
			// tracked chain-rooted argument: the callee holds a write
			// path into the argument's storage, and the storage's later
			// judgment defers to the callee's per-parameter insertion
			// fact over a conditional edge (calleeKey\x00index), resolved
			// at composition to a least fixed point
			// (REQ-closure-shared-dynamic-state).
			type insertionUse struct {
				root        types.Object
				calleeParam string
				args        []ast.Expr
			}
			var pendingInsertionUses []insertionUse
			bindLocal := func(target ast.Expr, source ast.Expr, broken bool) {
				ident, ok := unparen(target).(*ast.Ident)
				if !ok {
					// An element, field, or dereference write of a
					// present value stores into the root's storage; the
					// post-walk pass decides slot versus deep. A
					// valueless or already-broken write keeps the
					// break; parameter storage - reached directly or
					// through any alias - breaks in the component pass,
					// the one enforcement point for the parameter-write
					// clause.
					if source != nil && !broken {
						if rootIdent, ok := chainRoot(target).(*ast.Ident); ok {
							robj := p.TypesInfo.Uses[rootIdent]
							if robj == nil {
								robj = p.TypesInfo.Defs[rootIdent]
							}
							if robj != nil {
								if _, tracked := trackedVar(robj); tracked {
									pendingStores = append(pendingStores, pendingStore{robj, rootIdent, target, source})
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
					// walk cannot see. An ident root's base binding
					// breaks; a chain rooted at a call result still
					// addresses storage that call may hand back, so
					// every tracked name the operand reaches breaks -
					// fail-closed, in every position. A composite-
					// literal operand addresses fresh storage and
					// breaks nothing here: its embedded reach is the
					// bind link's and the returned-literal audit's in
					// bind and return position, and the call arm's in
					// argument position, per the capture clause in
					// docs/specs/closure.md.
					if n.Op == token.AND {
						switch root := chainRoot(n.X).(type) {
						case *ast.Ident:
							breakTargets(root)
						case *ast.CallExpr:
							breakTargets(n.X)
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
								_, ptr := types.Unalias(sig.Recv().Type()).(*types.Pointer)
								// A value receiver whose backing or copied
								// interior reaches mutable state writes
								// through exactly like a pointer receiver -
								// same exemption, same break; only a
								// reach-free receiver copy is inert.
								if ptr || sharesHeader(sig.Recv().Type()) || typeHandsOutMutableReach(sig.Recv().Type(), make(map[types.Type]bool)) {
									pkgPath, rest, ok := strings.Cut(methodFactKey(fn), "\x00")
									if !ok || pkgPath != ownPath || !readOnly[rest] {
										breakBase(n.X)
									}
								}
							}
						}
					}
				case *ast.CallExpr:
					if ident, ok := unparen(n.Fun).(*ast.Ident); ok {
						if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
							if ident.Name == "copy" && len(n.Args) == 2 {
								bindLocal(n.Args[0], nil, true)
							}
							// Builtin reads and construction cannot
							// insert elements; append and copy have
							// their own admitted arms.
							return true
						}
					}
					// Any callee handed a tracked binding can mutate its
					// backing - insert an element the recorded
					// population never sees. A plain named callee's own
					// body is swept when it proves, so its insertions
					// join the population over a dependency edge instead
					// of breaking the binding - an unproven callee then
					// fails the proof's resolution, fail-closed; the
					// audited value-plane helpers are proven
					// non-mutating and pass free. Every other callee
					// shape is unattributable: the tracked bindings its
					// arguments reach break.
					if tv, ok := p.TypesInfo.Types[n.Fun]; ok && tv.IsType() {
						// A conversion is not a callee - the converted
						// value's disposition rides the admitted
						// conversion arms.
						return true
					}
					if fn := plainNamedCalleeFn(p, n); fn != nil {
						if !auditedValuePlane[fn.Pkg().Path()+"\x00"+fn.Name()] {
							// A signature-carrying result can land in the
							// returned elements wherever it flows - the
							// callee's own recorded population must join.
							reaches := typeCarriesSignature(p.TypesInfo.TypeOf(n), make(map[types.Type]bool))
							for _, arg := range n.Args {
								ast.Inspect(arg, func(inner ast.Node) bool {
									if ident, ok := inner.(*ast.Ident); ok {
										obj := p.TypesInfo.Uses[ident]
										if obj == nil {
											obj = p.TypesInfo.Defs[ident]
										}
										if obj != nil {
											if _, ok := trackedVar(obj); ok || params[obj] {
												reaches = true
											}
										}
									}
									return !reaches
								})
								if reaches {
									break
								}
							}
							if reaches {
								stmtCallDeps[fn.Pkg().Path()+"\x00"+fn.Name()] = true
							}
							// Every argument is classified by the write
							// path its value hands the callee
							// (REQ-closure-shared-dynamic-state's
							// callees-join-their-populations clause). A
							// tracked chain-rooted argument whose value
							// hands out mutable reach defers to the
							// callee's per-parameter insertion fact — the
							// precise edge. A composite literal — plain,
							// addressed, or Go's elided address-of in
							// pointer-element literals (no UnaryExpr
							// exists to see) — breaks its embedded
							// reach-bearing tracked names fail-closed: the
							// literal's fresh storage maps caller names
							// onto callee storage in a shape the
							// per-parameter fact cannot attribute. A
							// call-rooted or otherwise unattributable
							// argument value breaks every reach-bearing
							// tracked name it reaches, the discipline the
							// capture arm already applies. Audited
							// value-plane callees are proven non-mutating
							// and classify nothing.
							sig, _ := fn.Type().(*types.Signature)
							var breakReachIn func(e ast.Expr)
							breakReachIn = func(e ast.Expr) {
								ast.Inspect(e, func(inner ast.Node) bool {
									if ident, ok := inner.(*ast.Ident); ok {
										obj := p.TypesInfo.Uses[ident]
										if obj == nil {
											obj = p.TypesInfo.Defs[ident]
										}
										if obj != nil {
											if _, ok := trackedVar(obj); ok || params[obj] {
												if typeHandsOutMutableReach(obj.Type(), make(map[types.Type]bool)) {
													localBroken[obj] = true
													captureBroken[obj] = true
												}
											}
										}
									}
									return true
								})
							}
							var classifyLit func(lit *ast.CompositeLit)
							classifyLit = func(lit *ast.CompositeLit) {
								for _, elt := range lit.Elts {
									value := elt
									if kv, ok := elt.(*ast.KeyValueExpr); ok {
										value = kv.Value
									}
									value = unparen(value)
									// An element whose value hands no mutable
									// reach copies into the literal's fresh
									// storage - no write path back.
									if t := p.TypesInfo.TypeOf(value); t != nil && !typeHandsOutMutableReach(t, make(map[types.Type]bool)) {
										continue
									}
									switch v := value.(type) {
									case *ast.CompositeLit:
										classifyLit(v)
									case *ast.UnaryExpr:
										if v.Op == token.AND {
											if inner, ok := unparen(v.X).(*ast.CompositeLit); ok {
												classifyLit(inner)
												continue
											}
										}
										breakReachIn(value)
									case *ast.BasicLit, *ast.FuncLit:
									default:
										breakReachIn(value)
									}
								}
							}
							elemReach := func(t types.Type) bool {
								if t == nil {
									return true
								}
								switch u := types.Unalias(t).Underlying().(type) {
								case *types.Slice:
									return typeHandsOutMutableReach(u.Elem(), make(map[types.Type]bool))
								case *types.Array:
									return typeHandsOutMutableReach(u.Elem(), make(map[types.Type]bool))
								case *types.Map:
									return typeHandsOutMutableReach(u.Key(), make(map[types.Type]bool)) || typeHandsOutMutableReach(u.Elem(), make(map[types.Type]bool))
								}
								return true
							}
							var classifyArg func(e ast.Expr, calleeParam string, callArgs []ast.Expr)
							classifyArg = func(e ast.Expr, calleeParam string, callArgs []ast.Expr) {
								e = unparen(e)
								// The classification gates on the VALUE's own
								// type, never the chain root's alone: a value
								// handing no mutable reach copies, and no
								// write path into tracked backing rides it
								// whatever storage its expression read from.
								if t := p.TypesInfo.TypeOf(e); t != nil && !typeHandsOutMutableReach(t, make(map[types.Type]bool)) {
									return
								}
								switch v := e.(type) {
								case *ast.Ident, *ast.SelectorExpr, *ast.IndexExpr, *ast.StarExpr, *ast.SliceExpr:
									if ident, ok := chainRoot(e).(*ast.Ident); ok {
										obj := p.TypesInfo.Uses[ident]
										if obj == nil {
											obj = p.TypesInfo.Defs[ident]
										}
										if obj != nil {
											_, tracked := trackedVar(obj)
											if (tracked || params[obj]) && typeHandsOutMutableReach(obj.Type(), make(map[types.Type]bool)) {
												pendingInsertionUses = append(pendingInsertionUses, insertionUse{root: obj, calleeParam: calleeParam, args: callArgs})
											}
										}
										return
									}
									breakReachIn(e)
								case *ast.CompositeLit:
									classifyLit(v)
								case *ast.UnaryExpr:
									if v.Op == token.AND {
										if lit, ok := unparen(v.X).(*ast.CompositeLit); ok {
											classifyLit(lit)
											return
										}
										// A &chain capture is the capture
										// arm's own case, already broken
										// there.
										return
									}
									breakReachIn(e)
								case *ast.BasicLit, *ast.FuncLit:
								case *ast.CallExpr:
									// Fresh-and-copying derivations hand the
									// callee backing the caller's tracked
									// names never share: builtin make/new,
									// append whose operands classify clean,
									// conversions of clean operands, and an
									// audited value-plane result whose
									// container elements copy. Everything
									// else is unattributable provenance -
									// the demonstrated sink(id(s)) fault -
									// and breaks fail-closed.
									if fnIdent, ok := unparen(v.Fun).(*ast.Ident); ok {
										if _, builtin := p.TypesInfo.Uses[fnIdent].(*types.Builtin); builtin {
											switch fnIdent.Name {
											case "make", "new":
												return
											case "append":
												for ai, a := range v.Args {
													// The spread hands only the
													// operand's ELEMENTS - copied
													// into the append target - so
													// a no-reach element type
													// classifies nothing.
													if ai == len(v.Args)-1 && v.Ellipsis.IsValid() {
														if t := p.TypesInfo.TypeOf(a); t != nil {
															if sl, ok := types.Unalias(t).Underlying().(*types.Slice); ok && !typeHandsOutMutableReach(sl.Elem(), make(map[types.Type]bool)) {
																continue
															}
														}
													}
													classifyArg(a, calleeParam, callArgs)
												}
												return
											}
											breakReachIn(e)
											return
										}
									}
									if tv, ok := p.TypesInfo.Types[v.Fun]; ok && tv.IsType() && len(v.Args) == 1 {
										classifyArg(v.Args[0], calleeParam, callArgs)
										return
									}
									if inner := plainNamedCalleeFn(p, v); inner != nil && auditedValuePlane[inner.Pkg().Path()+"\x00"+inner.Name()] {
										if !elemReach(p.TypesInfo.TypeOf(e)) {
											// The fresh container's elements
											// copy - no path back into the
											// operands' backing.
											return
										}
									}
									breakReachIn(e)
								default:
									breakReachIn(e)
								}
							}
							for j, arg := range n.Args {
								idx := j
								if sig != nil && sig.Variadic() && sig.Params().Len() > 0 && idx >= sig.Params().Len()-1 {
									idx = sig.Params().Len() - 1
								}
								classifyArg(arg, fn.Pkg().Path()+"\x00"+fn.Name()+"\x00"+strconv.Itoa(idx), n.Args)
							}
						}
						return true
					}
					for _, arg := range n.Args {
						breakTargets(arg)
					}
					// A func-valued callee expression's own tracked reach
					// shares backing with the call; method receivers have
					// their own arm with the read-only exemption.
					if sel, ok := unparen(n.Fun).(*ast.SelectorExpr); !ok || func() bool {
						selection, ok := p.TypesInfo.Selections[sel]
						return !ok || selection.Kind() != types.MethodVal
					}() {
						breakTargets(n.Fun)
					}
				}
				return true
			})
			// freshObj marks bindings whose every source is body-owned
			// storage: a fresh allocation, an append or conversion over
			// one, or a value read back out of a fresh container. A
			// pessimistic ascending fixpoint - ungrounded cycles stay
			// non-fresh, fail-closed.
			freshObj := map[types.Object]bool{}
			var srcFresh func(e ast.Expr) bool
			srcFresh = func(e ast.Expr) bool {
				e = unparen(e)
				switch v := e.(type) {
				case *ast.CompositeLit:
					return true
				case *ast.UnaryExpr:
					return v.Op == token.AND && srcFresh(v.X)
				case *ast.CallExpr:
					if fnIdent, ok := unparen(v.Fun).(*ast.Ident); ok {
						if _, builtin := p.TypesInfo.Uses[fnIdent].(*types.Builtin); builtin {
							switch fnIdent.Name {
							case "make", "new":
								return true
							case "append":
								return len(v.Args) > 0 && srcFresh(v.Args[0])
							}
							return false
						}
					}
					if tv, ok := p.TypesInfo.Types[v.Fun]; ok && tv.IsType() && len(v.Args) == 1 {
						return srcFresh(v.Args[0])
					}
					return false
				case *ast.Ident, *ast.IndexExpr, *ast.SliceExpr, *ast.StarExpr, *ast.SelectorExpr:
					if ident, ok := chainRoot(e).(*ast.Ident); ok {
						obj := p.TypesInfo.Uses[ident]
						if obj == nil {
							obj = p.TypesInfo.Defs[ident]
						}
						return obj != nil && freshObj[obj]
					}
				}
				return false
			}
			for changed := true; changed; {
				changed = false
				for obj, srcs := range localSources {
					if freshObj[obj] || len(srcs) == 0 {
						continue
					}
					all := true
					for _, s := range srcs {
						if !srcFresh(s) {
							all = false
							break
						}
					}
					if all {
						freshObj[obj] = true
						changed = true
					}
				}
			}
			// A deferred store is a slot write - landing in the root's
			// own storage - when the chain stays on the root's owned
			// spine: for a fresh root, an initial dereference of the
			// root's own pointer, selector steps over struct values,
			// and at most one index as the final step; for any root,
			// selector steps over struct values alone. Every other
			// step - a dereference or pointer-crossing selector below
			// the root, an index on a non-fresh root or in non-final
			// position - may write storage the root does not own:
			// fail-closed deep, breaking the root and, through the
			// links, every origin its held values may reach.
			deepWrite := func(target ast.Expr, fresh bool) bool {
				var steps []ast.Expr
				e := unparen(target)
			flatten:
				for {
					switch s := e.(type) {
					case *ast.SelectorExpr:
						steps = append(steps, s)
						e = unparen(s.X)
					case *ast.IndexExpr:
						steps = append(steps, s)
						e = unparen(s.X)
					case *ast.SliceExpr:
						steps = append(steps, s)
						e = unparen(s.X)
					case *ast.StarExpr:
						steps = append(steps, s)
						e = unparen(s.X)
					default:
						break flatten
					}
				}
				selectorSeen := false
				for i := len(steps) - 1; i >= 0; i-- {
					atRoot := i == len(steps)-1
					final := i == 0
					switch st := steps[i].(type) {
					case *ast.StarExpr:
						if !atRoot || !fresh {
							return true
						}
					case *ast.SelectorExpr:
						if t := p.TypesInfo.TypeOf(st.X); t != nil {
							if _, ptr := types.Unalias(t).Underlying().(*types.Pointer); ptr {
								if !atRoot || !fresh {
									return true
								}
							}
						}
						selectorSeen = true
					case *ast.IndexExpr:
						// An index is a slot only directly on the root
						// (past its own dereference at most): a header
						// reached through a selector may have arrived
						// inside a held copy, and freshness is
						// value-blind to embedded foreign backing.
						if !final || !fresh || selectorSeen {
							return true
						}
					case *ast.SliceExpr:
						if !fresh || selectorSeen {
							return true
						}
					}
				}
				return false
			}
			for _, ps := range pendingStores {
				if deepWrite(ps.target, freshObj[ps.robj]) {
					// The return plane breaks fail-closed (the slot
					// discipline cannot attribute the write), but the
					// stored value still lands in the root's reachable
					// storage: recorded for the insertion plane, where a
					// parameter component judges it instead of
					// inheriting the break. Only breakTargets-class
					// causes poison insertions, so localBroken is set
					// directly here, never captureBroken.
					ast.Inspect(ps.root, func(n ast.Node) bool {
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
					insertionWrites[ps.robj] = append(insertionWrites[ps.robj], ps.source)
					linkBacking(ps.robj, ps.source)
					continue
				}
				writeSources[ps.robj] = append(writeSources[ps.robj], ps.source)
				// The store also makes the base's storage reach the
				// stored value's backing - a later write through the
				// base's elements lands there.
				linkBacking(ps.robj, ps.source)
			}
			// Breaks propagate across shared backing and held reach
			// alike before any judgment reads the map - a break on
			// either side of either link kind is fail-closed shared.
			for changed := true; changed; {
				changed = false
				for _, pairs := range [][][2]types.Object{aliasPairs, heldPairs} {
					for _, pair := range pairs {
						if localBroken[pair[0]] != localBroken[pair[1]] {
							localBroken[pair[0]], localBroken[pair[1]] = true, true
							changed = true
						}
						if captureBroken[pair[0]] != captureBroken[pair[1]] {
							captureBroken[pair[0]], captureBroken[pair[1]] = true, true
							changed = true
						}
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
			sharedInsertionWrites := map[types.Object][]ast.Expr{}
			for obj, stores := range insertionWrites {
				root := aliasFind(obj)
				sharedInsertionWrites[root] = append(sharedInsertionWrites[root], stores...)
			}
			// resolvedUses and usePoison are filled by the use-resolution
			// pass once the value judgment exists: a deferring call's
			// every argument judges at the call site (the caller's
			// obligation), an unjudgeable argument poisoning the handed
			// storage instead of deferring.
			resolvedUses := map[types.Object]map[string]bool{}
			usePoison := map[types.Object]bool{}
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
			// Load-bearing superset: stmtCallDeps records every plain
			// named callee whose call carries signature results or
			// touches tracked storage, gated on the same carries()
			// predicate as free's CallExpr recording - so a dep free()
			// would record while running under a redirected channel
			// (the insertion-facts loop) is already seeded here, and a
			// memoized local skipping free(src) on the return walk
			// loses nothing. Narrowing the reaches gate without
			// widening this seed would silently break that cover.
			for callee := range stmtCallDeps {
				fnDeps[callee] = true
			}
			// insCallDeps carries this proof's insertion conditions — a
			// callee parameter handed tracked storage — on their own
			// channel: the population-join walk follows fnDeps as
			// function keys, and an insertion condition is a parameter
			// key resolved against the insertion fixed point instead.
			insCallDeps := map[string]bool{}
			// useFold is where a consumed insertion edge lands: the
			// return plane's insCallDeps normally, the parameter fact's
			// own collected set while the insertion loop judges - so a
			// persisted ParamInsertionDeps carries conditions reached
			// through locals too, never only direct ones.
			useFold := &insCallDeps
			var free func(expr ast.Expr) bool
			localFree := map[types.Object]int{} // 0 unknown, 1 proving, 2 free, 3 refused
			var judgeLocal func(obj types.Object) bool
			judgeLocal = func(obj types.Object) bool {
				// Poison and edge folding run BEFORE the memo: a local
				// judged while the use-resolution was still recording
				// caches its freedom with no edges attached, and a
				// memo-shortcut past the fold would drop every
				// local-rooted deferral condition. The fold runs even
				// when the binding then refuses - an extra condition on
				// a refusing path is over-conservative, never unsound.
				if usePoison[aliasFind(obj)] {
					localFree[obj] = 3
					return false
				}
				for use := range resolvedUses[aliasFind(obj)] {
					(*useFold)[use] = true
				}
				switch localFree[obj] {
				case 2:
					return true
				case 3:
					return false
				case 1:
					// A cyclic binding chain recirculates existing
					// values - no new value enters through the cycle
					// edge itself - so the edge holds and the judgment
					// rests on the chain's external sources alone. A
					// poisoned external source or store still refuses
					// every member.
					return true
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
					if !environmentFreeFuncLitJudged(audited, p, e, fd.Body, wants, methodWants) {
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
							// no longer holds it. A callee handed the
							// parameter's storage joins over its
							// insertion edges.
							if localBroken[obj] {
								return false
							}
							if usePoison[aliasFind(obj)] {
								return false
							}
							for use := range resolvedUses[aliasFind(obj)] {
								(*useFold)[use] = true
							}
							return true
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
					// function used as a value) carries no environment.
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
					// An element read of a judged container is judged:
					// the store-set invariant guarantees every element
					// stored judges. Gated on the same containers the
					// range clause admits; anything else - type
					// parameters included - keeps the refusal.
					if t := p.TypesInfo.TypeOf(e.X); t != nil {
						switch u := types.Unalias(t).Underlying().(type) {
						case *types.Map, *types.Slice, *types.Array, *types.Basic:
							return free(e.X)
						case *types.Pointer:
							if _, isArr := types.Unalias(u.Elem()).Underlying().(*types.Array); isArr {
								return free(e.X)
							}
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
						// An audited value-plane standard helper carries
						// exactly its arguments' values into its result -
						// judged when every argument judges, every
						// spelling the callee resolution admits. A
						// closed set; every other standard callee falls
						// to the dependency channel, whose fail-closed
						// composition refuses absent proofs.
						if auditedValuePlane[fn.Pkg().Path()+"\x00"+fn.Name()] {
							return true
						}
						fnDeps[fn.Pkg().Path()+"\x00"+fn.Name()] = true
						return true
					}
					return false
				}
				return false
			}
			// Use resolution: each recorded call deferral resolves once
			// - every argument of the deferring call judges under the
			// audit's value judgment (the caller's obligation,
			// discharged here); a call with an unjudgeable argument
			// poisons the storage it was handed instead of deferring
			// (an environment-carrying value could land there through
			// the callee's insertions).
			// The pass iterates to a fixpoint on the poison set: a use
			// judged before a sibling's poison landed may have read a
			// clean cache, so each new poison clears the local caches
			// and re-runs; the final recording pass then re-judges every
			// surviving use under the converged poison state, so no edge
			// rests on a stale freedom claim.
			resolveUses := func(record bool) bool {
				changed := false
				for _, use := range pendingInsertionUses {
					root := aliasFind(use.root)
					if usePoison[root] {
						continue
					}
					allFree := true
					for _, a := range use.args {
						if !free(a) {
							allFree = false
							break
						}
					}
					if !allFree {
						usePoison[root] = true
						changed = true
						continue
					}
					if record {
						if resolvedUses[root] == nil {
							resolvedUses[root] = map[string]bool{}
						}
						resolvedUses[root][use.calleeParam] = true
					}
				}
				return changed
			}
			// Poison and recorded edges cross shared backing AND held
			// copies exactly as the breaks do: a struct copy's interior
			// reaches its origin's backing, so a callee handed the copy
			// holds a write path into the origin (the chunk-83 round-2
			// review's H2) - fail-closed, both directions.
			propagateUses := func() bool {
				changed := false
				for _, pairs := range [][][2]types.Object{aliasPairs, heldPairs} {
					for _, pair := range pairs {
						a, b := aliasFind(pair[0]), aliasFind(pair[1])
						if a == b {
							continue
						}
						if usePoison[a] != usePoison[b] {
							usePoison[a], usePoison[b] = true, true
							changed = true
						}
						for use := range resolvedUses[a] {
							if !resolvedUses[b][use] {
								if resolvedUses[b] == nil {
									resolvedUses[b] = map[string]bool{}
								}
								resolvedUses[b][use] = true
								changed = true
							}
						}
						for use := range resolvedUses[b] {
							if !resolvedUses[a][use] {
								if resolvedUses[a] == nil {
									resolvedUses[a] = map[string]bool{}
								}
								resolvedUses[a][use] = true
								changed = true
							}
						}
					}
				}
				return changed
			}
			// Discovery rounds judge against scratch dep targets: an edge
			// collected for a use later poisoned must not linger on the
			// return proof (over-conservative but noisy); only the final
			// recording pass writes the real channels.
			scratchDeps := map[string]bool{}
			savedDeps, savedFold := fnDeps, useFold
			fnDeps, useFold = scratchDeps, &scratchDeps
			for {
				changed := resolveUses(false)
				if propagateUses() {
					changed = true
				}
				if !changed {
					break
				}
				for k := range localFree {
					delete(localFree, k)
				}
			}
			fnDeps, useFold = savedDeps, savedFold
			for k := range localFree {
				delete(localFree, k)
			}
			resolveUses(true)
			for propagateUses() {
			}
			for k := range localFree {
				delete(localFree, k)
			}
			// Per-parameter argument-storage insertion facts
			// (REQ-closure-shared-dynamic-state's
			// callees-join-their-populations clause): a parameter's
			// component judges by what the body stores into it. A
			// capture-broken component's insertions are unknowable —
			// poison, absent. A stored bare unrebroken parameter is the
			// caller's obligation, discharged by the recursive argument
			// judgment at each call site, so it contributes nothing here.
			// Every other stored value judges by the audit's own value
			// judgment, its dependency edges collected onto this
			// parameter's fact rather than the enclosing return proof;
			// a parameter handed onward chains through the callee's own
			// insertion fact. Runs before the explain wrap: insertion
			// refusals surface through composition, not as return-shape
			// refusal links.
			for obj, idx := range paramIndex {
				key := fnKey + "\x00" + strconv.Itoa(idx)
				root := aliasFind(obj)
				// captureBroken propagates across both link kinds before
				// any judgment reads it, so the component's poison shows
				// on the parameter itself; a poisoned deferral (an
				// unjudgeable call argument) poisons identically.
				if captureBroken[obj] || usePoison[root] {
					continue
				}
				collected := map[string]bool{}
				saved, savedFold := fnDeps, useFold
				fnDeps, useFold = collected, &collected
				okIns := true
				for _, stored := range append(append([]ast.Expr{}, sharedWrites[root]...), sharedInsertionWrites[root]...) {
					if ident, isIdent := unparen(stored).(*ast.Ident); isIdent {
						if sobj := p.TypesInfo.Uses[ident]; sobj != nil && params[sobj] &&
							!localBroken[sobj] && !captureBroken[sobj] {
							// A stored bare parameter neither rebound nor
							// broken is the caller's obligation - judged
							// at each deferring call site by the
							// use-resolution pass.
							continue
						}
					}
					if !free(stored) {
						okIns = false
						break
					}
				}
				fnDeps, useFold = saved, savedFold
				if !okIns {
					continue
				}
				for use := range resolvedUses[root] {
					collected[use] = true
				}
				insFree[key] = true
				if len(collected) > 0 {
					insDeps[key] = collected
				}
			}
			if h := explainHooks.Load(); h != nil && h.refusal != nil {
				inner := free
				free = func(e ast.Expr) bool {
					r := inner(e)
					if !r {
						clause := "an unrecognized return shape"
						switch e := unparen(e).(type) {
						case *ast.Ident:
							obj := p.TypesInfo.Uses[e]
							if obj == nil {
								obj = p.TypesInfo.Defs[e]
							}
							switch {
							case obj != nil && localBroken[obj]:
								clause = "write or capture broke the binding"
							case obj != nil && usePoison[aliasFind(obj)]:
								clause = "an unjudgeable argument to a deferring call poisoned the storage"
							case obj != nil && len(sharedWrites[aliasFind(obj)]) > 0:
								clause = "a stored value refused"
							default:
								clause = "a binding source refused"
							}
						case *ast.CallExpr:
							clause = "callee outside the audited set and dependency channel"
						case *ast.CompositeLit:
							clause = "a literal element refused"
						case *ast.SelectorExpr, *ast.IndexExpr, *ast.SliceExpr:
							clause = "an unadmitted derivation shape"
						}
						h.refusal(p, fd.Name.Name, e, clause)
					}
					return r
				}
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
			if len(insCallDeps) > 0 {
				callerInsDeps[fnKey] = insCallDeps
			}
			recordReturnFieldRegistrants(audited, p, fnKey, fd.Body, retDefer, retPoison)
		}
	}
	return proven, deps, retDefer, retPoison, insFree, insDeps, callerInsDeps
}

// recordReturnFieldRegistrants derives a proven constructor's contribution
// to the registered field populations of the carriers its results reach:
// every composite literal in the body is classified (pooling by field name
// across levels - a superset of the returned values only ever adds
// constraints), a direct func-signature field write registers its value,
// and a read of any signature-carrying package variable poisons the whole
// population - the proof's derivation channel could hand that variable's
// unclassified interior into the result, fail-closed
// (REQ-closure-shared-dynamic-state). Values arriving through dependency
// callees are the callees' own records, joined transitively at
// composition over the proof's dependency edges.
func recordReturnFieldRegistrants(audited bool, p *packages.Package, fnKey string, body ast.Node, retDefer, retPoison map[string]map[string]bool) {
	emit := func(m fieldRegMark) {
		switch m.class {
		case 'd':
			if retDefer[fnKey] == nil {
				retDefer[fnKey] = map[string]bool{}
			}
			retDefer[fnKey][m.field+"\x00"+strconv.Itoa(m.idx)+"\x01"+m.param] = true
		case 'p':
			if retPoison[fnKey] == nil {
				retPoison[fnKey] = map[string]bool{}
			}
			if m.field == "" {
				retPoison[fnKey][""] = true
			} else {
				retPoison[fnKey][m.field+"\x00"+strconv.Itoa(m.idx)] = true
			}
		}
	}
	fieldWrite := func(lhs, rhs ast.Expr) {
		if sel, ok := unparenExpr(lhs).(*ast.SelectorExpr); ok {
			if selection, ok := p.TypesInfo.Selections[sel]; ok && selection.Kind() == types.FieldVal {
				if _, isSig := types.Unalias(selection.Type()).Underlying().(*types.Signature); isSig {
					classifyFieldRegistrantValue(audited, p, sel.Sel.Name, rhs, emit)
				}
			}
		}
	}
	// Every bare-function reference in VALUE position is an
	// element-population registrant: the proof's derivation channels
	// admit locals, index writes, conversions, and appends that carry
	// the value into the returned elements, so any such reference pools
	// its disposition - only call-position references are excluded
	// (calling a helper registers nothing), and only parameters skip,
	// priced by the store site's argument classification. Pooling a
	// value the result never reaches only adds constraints - the
	// fail-closed direction (REQ-closure-shared-dynamic-state).
	funPositions := map[ast.Node]bool{}
	writePositions := map[ast.Node]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			fun := unparenExpr(n.Fun)
			funPositions[fun] = true
			if sel, ok := fun.(*ast.SelectorExpr); ok {
				funPositions[sel.Sel] = true
			}
		case *ast.AssignStmt:
			// A write target is not a produced value - the stored
			// value's own visit prices it.
			for _, lhs := range n.Lhs {
				writePositions[unparenExpr(lhs)] = true
			}
		case *ast.IncDecStmt:
			writePositions[unparenExpr(n.X)] = true
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			classifyRegistrantComposite(audited, p, n, emit)
			return false

		case *ast.AssignStmt:
			if len(n.Lhs) == len(n.Rhs) {
				for i, lhs := range n.Lhs {
					fieldWrite(lhs, n.Rhs[i])
				}
			} else if len(n.Rhs) == 1 {
				for _, lhs := range n.Lhs {
					fieldWrite(lhs, n.Rhs[0])
				}
			}
		case *ast.FuncLit:
			if !funPositions[n] {
				classifyLiteralRegistrant(audited, p, elemPositionField, n, emit)
			}
		case *ast.CallExpr:
			// A conversion produces its operand - the operand is swept
			// on descent. A plain named callee's result joins over the
			// dependency edge the binding walk records; a builtin
			// constructs or reads. Any other call producing a
			// signature-carrying value is unattributable - poison the
			// element position, fail-closed.
			if tv, ok := p.TypesInfo.Types[n.Fun]; ok && tv.IsType() {
				break
			}
			if ident, ok := unparenExpr(n.Fun).(*ast.Ident); ok {
				if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
					break
				}
			}
			if plainNamedCalleeFn(p, n) != nil {
				break
			}
			if typeCarriesSignature(p.TypesInfo.TypeOf(n), make(map[types.Type]bool)) {
				emit(fieldRegMark{class: 'p', field: elemPositionField, idx: -1})
			}
		case *ast.SelectorExpr:
			if funPositions[n] || writePositions[n] {
				break
			}
			if _, isFunc := p.TypesInfo.Uses[n.Sel].(*types.Func); isFunc {
				classifyFieldRegistrantValue(audited, p, elemPositionField, n, emit)
				break
			}
			// A field or foreign read producing a signature-carrying
			// value is an element registrant the sweep cannot attribute
			// - poison, fail-closed. (A package variable read is the
			// Ident arm's whole-population poison via its Sel visit.)
			if typeCarriesSignature(p.TypesInfo.TypeOf(n), make(map[types.Type]bool)) {
				emit(fieldRegMark{class: 'p', field: elemPositionField, idx: -1})
			}
		case *ast.IndexExpr:
			// An element read handed onward re-registers a value this
			// carrier's records never priced - poison, fail-closed.
			if !funPositions[n] && !writePositions[n] && typeCarriesSignature(p.TypesInfo.TypeOf(n), make(map[types.Type]bool)) {
				emit(fieldRegMark{class: 'p', field: elemPositionField, idx: -1})
			}
		case *ast.Ident:
			if funPositions[n] {
				break
			}
			if _, isFunc := p.TypesInfo.Uses[n].(*types.Func); isFunc {
				classifyFieldRegistrantValue(audited, p, elemPositionField, n, emit)
				break
			}
			if v, ok := p.TypesInfo.Uses[n].(*types.Var); ok && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() && typeCarriesSignature(v.Type(), make(map[types.Type]bool)) {
				// Locals' contents are priced where their values are
				// stored - every stored value is itself swept - and a
				// parameter's direct value at the store site; only the
				// package-variable read is unattributable here.
				emit(fieldRegMark{class: 'p', idx: -1})
			}
		}
		return true
	})
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
func boundValueLeakFree(audited bool, p *packages.Package, roots map[types.Object]bool, body ast.Node) bool {
	return boundValueLeakFreeJudged(audited, p, roots, body, nil, nil, nil, nil, nil)
}

func boundValueLeakFreeDeferred(audited bool, p *packages.Package, roots map[types.Object]bool, body ast.Node, wants map[string]bool) bool {
	return boundValueLeakFreeJudged(audited, p, roots, body, wants, nil, nil, nil, nil)
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
//
// A fieldWants collector additionally defers a rooted alias-handing
// argument passed through a func-valued field of the judged binding
// itself: the callee is statically unknowable, so the want names the
// field position (field name and zero-based parameter index NUL-joined)
// and resolves at composition against that field's registered population
// - every value the environment audit admits into the carrier must prove
// the parameter leak-free at that field, any unproven registrant keeping
// the escape (REQ-closure-shared-dynamic-state). Never from a go
// statement's call, the goroutine runs concurrently.
// An elemWants collector defers a rooted alias-handing argument passed
// through a callee-position index read of a package carrier (the
// dispatch-table shape legs[token](arg)): the want carries the dispatch
// carrier's key and the parameter index \x01-joined, resolved at
// composition against that carrier's element population - never from a
// go statement's call (REQ-closure-shared-dynamic-state).
func boundValueLeakFreeJudged(audited bool, p *packages.Package, roots map[types.Object]bool, body ast.Node, wants map[string]bool, returns *bool, methodWants map[string]bool, fieldWants map[string]bool, elemWants map[string]bool) bool {
	return boundValueJudged(audited, p, roots, body, wants, returns, methodWants, fieldWants, elemWants, false)
}

// boundValueRetentionFreeJudged proves the retention-only grade: the
// bound value never escapes or outlives the call, while writes through
// the binding - stores and increments - are tolerated. This is the
// init-flow deferral's grade, where direct stores are already exempt;
// every other use keeps the leak-free rules
// (REQ-closure-shared-dynamic-state).
func boundValueRetentionFreeJudged(audited bool, p *packages.Package, roots map[types.Object]bool, body ast.Node, wants map[string]bool, methodWants map[string]bool) bool {
	return boundValueJudged(audited, p, roots, body, wants, nil, methodWants, nil, nil, true)
}

func boundValueJudged(audited bool, p *packages.Package, roots map[types.Object]bool, body ast.Node, wants map[string]bool, returns *bool, methodWants map[string]bool, fieldWants map[string]bool, elemWants map[string]bool, tolerateRootedStores bool) bool {
	if p == nil || p.TypesInfo == nil || body == nil || len(roots) == 0 {
		return false
	}
	// Every call within a go statement's subtree runs concurrently with
	// the walked body - a call wrapped in a goroutine literal exactly as
	// the direct spelling - so none of them defers.
	goCalls := map[*ast.CallExpr]bool{}
	goIdents := map[ast.Node]bool{}
	litReturns := map[*ast.ReturnStmt]bool{}
	// calleeReads marks call-Fun selector and index nodes: invoking a
	// signature-carrying read is not a handout - the call arms price the
	// arguments and the callee enumeration prices the effects - so the
	// value-plane refusal skips exactly these nodes.
	calleeReads := map[ast.Node]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			switch fun := call.Fun.(type) {
			case *ast.SelectorExpr, *ast.IndexExpr, *ast.Ident:
				calleeReads[fun] = true
			case *ast.ParenExpr:
				calleeReads[unparenExpr(fun)] = true
			}
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.GoStmt:
			ast.Inspect(n, func(inner ast.Node) bool {
				if call, ok := inner.(*ast.CallExpr); ok {
					goCalls[call] = true
				}
				if lit, ok := inner.(*ast.FuncLit); ok {
					// A literal under the go statement is the goroutine's
					// own code: a rooted read it captures is a retained
					// alias whatever shape consumes it - fail-closed for
					// every grade. The statement's direct arguments are
					// evaluated at the go statement and retain nothing;
					// the goCalls gate already prices them.
					ast.Inspect(lit, func(deep ast.Node) bool {
						if call, ok := deep.(*ast.CallExpr); ok {
							goCalls[call] = true
						}
						if ident, ok := deep.(*ast.Ident); ok {
							goIdents[ident] = true
						}
						return true
					})
					return false
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
	// carrierReaching marks body locals bound from expressions whose
	// subtree reads a dynamic-capable package variable - directly or
	// through such a local, to a fixpoint - so a tolerated store cannot
	// launder a foreign backing through a local hop
	// (REQ-closure-shared-dynamic-state).
	carrierReaching := map[types.Object]bool{}
	carrierReach := func(expr ast.Expr) bool {
		if expr == nil {
			return false
		}
		found := false
		ast.Inspect(expr, func(m ast.Node) bool {
			if found {
				return false
			}
			if ident, ok := m.(*ast.Ident); ok {
				if obj := p.TypesInfo.Uses[ident]; obj != nil {
					if carrierReaching[obj] {
						found = true
						return false
					}
					if variable, ok := obj.(*types.Var); ok && variable.Pkg() != nil &&
						variable.Parent() == variable.Pkg().Scope() &&
						typeMayCarryUnknownDynamic(audited, variable.Type(), make(map[types.Type]bool)) {
						found = true
					}
				}
			}
			return true
		})
		return found
	}
	if tolerateRootedStores {
		mark := func(ident *ast.Ident) bool {
			obj := p.TypesInfo.Defs[ident]
			if obj == nil {
				obj = p.TypesInfo.Uses[ident]
			}
			if obj == nil || carrierReaching[obj] {
				return false
			}
			carrierReaching[obj] = true
			return true
		}
		for changed := true; changed; {
			changed = false
			ast.Inspect(body, func(m ast.Node) bool {
				switch m := m.(type) {
				case *ast.AssignStmt:
					if len(m.Lhs) == len(m.Rhs) {
						for i, rhs := range m.Rhs {
							if carrierReach(rhs) {
								if ident, ok := m.Lhs[i].(*ast.Ident); ok && mark(ident) {
									changed = true
								}
							}
						}
					} else if len(m.Rhs) == 1 && carrierReach(m.Rhs[0]) {
						for _, lhs := range m.Lhs {
							if ident, ok := lhs.(*ast.Ident); ok && mark(ident) {
								changed = true
							}
						}
					}
				case *ast.ValueSpec:
					for i, name := range m.Names {
						var rhs ast.Expr
						if len(m.Names) == len(m.Values) {
							rhs = m.Values[i]
						} else if len(m.Values) == 1 {
							rhs = m.Values[0]
						}
						if rhs != nil && carrierReach(rhs) && mark(name) {
							changed = true
						}
					}
				}
				return true
			})
		}
	}
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
			// A signature-carrying binding is tracked on the value
			// plane - the bound value carries its environment even
			// where its type hands out no writable reach
			// (REQ-closure-shared-dynamic-state).
			if !typeHandsOutMutableReach(obj.Type(), make(map[types.Type]bool)) && !typeCarriesSignature(obj.Type(), make(map[types.Type]bool)) {
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
			for i, lhs := range n.Lhs {
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
						// A signature-carrying tracked binding rebound
						// from a non-rooted source no longer holds a
						// carrier-derived value while the taint set
						// still treats it as one - its func-field calls
						// would resolve against the wrong registered
						// population; fail-closed, but only where that
						// channel exists: a judge without a fieldWants
						// collector never defers a field call, and a
						// binding whose type carries no signature can
						// never be a func-field base, so those rebinds
						// keep the pre-existing tolerance. The one
						// exemption is an original root's own defining
						// statement: the disposition that supplied the
						// roots designated that binding as the carrier
						// value (a returner call's targets bind from
						// the call), so the define is the origin, not a
						// detachment.
						if fieldWants != nil && typeCarriesSignature(obj.Type(), make(map[types.Type]bool)) {
							var rhs ast.Expr
							if len(n.Lhs) == len(n.Rhs) {
								rhs = n.Rhs[i]
							} else if len(n.Rhs) == 1 {
								rhs = n.Rhs[0]
							}
							originDefine := roots[obj] && p.TypesInfo.Defs[ident] != nil
							if (rhs == nil || !rooted(rhs)) && !originDefine {
								leaky = true
							}
						}
					}
					consume(ident)
					continue
				}
				if rooted(lhs) {
					// A store through the binding is a write, not a
					// handout - the retention grade tolerates it and
					// consumes the target's root read. A stored value
					// reaching another package carrier keeps the
					// refusal: the store would alias two backings
					// through the binding, a link the call-scoped
					// judgment cannot record.
					var rhs ast.Expr
					if len(n.Lhs) == len(n.Rhs) {
						rhs = n.Rhs[i]
					} else if len(n.Rhs) == 1 {
						rhs = n.Rhs[0]
					}
					smuggles := false
					if rhs != nil {
						if t := p.TypesInfo.TypeOf(rhs); t == nil ||
							typeHandsOutMutableReach(t, make(map[types.Type]bool)) ||
							typeCarriesSignature(t, make(map[types.Type]bool)) {
							smuggles = carrierReach(rhs) || t == nil
						}
					}
					if tolerateRootedStores && !smuggles {
						consume(lhs)
					} else {
						leaky = true
					}
				}
			}
		case *ast.ValueSpec:
			// A declaration binding inside the body tracks exactly like
			// an assignment binding - the names are fresh in-body
			// objects, so no retention check applies. A tracked name
			// declared with a non-rooted initial value needs no arm of
			// its own: only rooted values allow their names, so the
			// declaration ident stays unconsumed and the tracked-ident
			// catch-all refuses it - the binding would sometimes hold a
			// value the registered population never saw.
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
				// A pure write through the binding - the retention grade
				// tolerates it exactly as a store.
				if tolerateRootedStores {
					consume(n.X)
				} else {
					leaky = true
				}
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
					} else if methodValueBind(result) || typeCarriesSignature(p.TypesInfo.TypeOf(result), make(map[types.Type]bool)) {
						// A signature-carrying value IS its environment -
						// handing it out is a value-plane leak whatever
						// the reach walk says about its type
						// (REQ-closure-shared-dynamic-state).
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
			if tv, ok := p.TypesInfo.Types[n.Fun]; ok && tv.IsType() {
				// A conversion of a tracked value is a value read judged
				// by its result type: a reach-free, signature-free result
				// is a fresh copy that cannot write back or hand out the
				// binding; any other result may alias the operand and
				// keeps the refusal. A method-value operand carries its
				// receiver whatever the result type says - never consumed
				// (REQ-closure-shared-dynamic-state).
				if len(n.Args) == 1 && rooted(n.Args[0]) && !methodValueBind(n.Args[0]) {
					if t := p.TypesInfo.TypeOf(n); t != nil && !typeHandsOutMutableReach(t, make(map[types.Type]bool)) && !typeCarriesSignature(t, make(map[types.Type]bool)) {
						consume(n.Args[0])
					}
				}
				break
			}
			if sel, ok := n.Fun.(*ast.SelectorExpr); ok && rooted(sel.X) {
				selection, selOK := p.TypesInfo.Selections[sel]
				if selOK && selection.Kind() == types.MethodVal {
					fn, isFunc := selection.Obj().(*types.Func)
					if isFunc && auditedSynchronization(audited, fn) {
						consume(sel.X)
						break
					}
					// A method call on a bound value defers to the
					// method's receiver-read-only fact: statically
					// dispatched, results handing out no mutable reach,
					// never concurrently - mirroring the carrier-receiver
					// deferral, resolved through the same marks.
					if isFunc && methodWants != nil && !goCalls[n] && fn.Pkg() != nil && !interfaceReceiver(fn) && instantiatedResultsHandOutNothing(audited, selection.Type()) {
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
					// by this binding proof. The call's RESULT is judged by
					// the rooted-callee result gate below.
				} else {
					leaky = true
				}
			}
			// A rooted callee - a func-typed field, a bound local, an
			// indexed element - tolerates its READ at the call, but the
			// call's RESULT is the carrier handing its consumer a value
			// no channel prices: any result handing out mutable reach or
			// carrying a signature refuses in every consumption position,
			// fail-closed; a void or all-scalar result set hands out
			// nothing (REQ-closure-shared-dynamic-state).
			if fun := unparenExpr(n.Fun); rooted(fun) {
				if callResultHandsOut(p.TypesInfo.TypeOf(n)) {
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
					if t := p.TypesInfo.TypeOf(arg); t == nil || typeHandsOutMutableReach(t, make(map[types.Type]bool)) || typeCarriesSignature(t, make(map[types.Type]bool)) {
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
						if !deferred && fieldWants != nil && !goCalls[n] {
							if sel, ok := n.Fun.(*ast.SelectorExpr); ok && isRoot(sel.X) {
								if selection, selOK := p.TypesInfo.Selections[sel]; selOK && selection.Kind() == types.FieldVal {
									if sig, sigOK := types.Unalias(selection.Type()).Underlying().(*types.Signature); sigOK && sig.Params().Len() > 0 {
										idx := i
										if sig.Variadic() && idx >= sig.Params().Len()-1 {
											idx = sig.Params().Len() - 1
										}
										fieldWants[sel.Sel.Name+"\x00"+strconv.Itoa(idx)] = true
										consume(arg)
										deferred = true
									}
								}
							}
						}
						if !deferred && elemWants != nil && !goCalls[n] {
							if index, ok := unparenExpr(n.Fun).(*ast.IndexExpr); ok {
								if base, ok := unparenExpr(index.X).(*ast.Ident); ok {
									obj := p.TypesInfo.Uses[base]
									if v, isVar := obj.(*types.Var); isVar && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() && typeMayCarryUnknownDynamic(audited, v.Type(), make(map[types.Type]bool)) {
										if sig, sigOK := types.Unalias(p.TypesInfo.TypeOf(n.Fun)).Underlying().(*types.Signature); sigOK && sig.Params().Len() > 0 {
											idx := i
											if sig.Variadic() && idx >= sig.Params().Len()-1 {
												idx = sig.Params().Len() - 1
											}
											elemWants[dynamicVarKey(v)+"\x01"+strconv.Itoa(idx)] = true
											consume(arg)
											deferred = true
										}
									}
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
				if t := p.TypesInfo.TypeOf(n); t == nil || typeHandsOutMutableReach(t, make(map[types.Type]bool)) || (!calleeReads[n] && typeCarriesSignature(t, make(map[types.Type]bool))) {
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
				// A signature-carrying read refuses on the value plane -
				// the produced value carries its environment; only its
				// call is tolerated, by the call arms.
				if t := p.TypesInfo.TypeOf(n); t == nil || typeHandsOutMutableReach(t, make(map[types.Type]bool)) || (!calleeReads[n] && typeCarriesSignature(t, make(map[types.Type]bool))) {
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
			// consumed is an unrecognized use - fail-closed. A call
			// position is an invocation, not a handout - the call's own
			// arms price it.
			if isRoot(n) && (goIdents[n] || (!allowed[n] && !calleeReads[n])) {
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
// omitted - no carrier can flow into them. The second proven set is the
// retention-only grade - writes through the binding tolerated, every
// other rule kept - recorded only where the leak-free grade failed
// (leak-free implies retention-free; consumers union the two)
// (REQ-closure-shared-dynamic-state).
func paramLeakFreeFunctions(audited bool, p *packages.Package, readOnlyLocal, retentionMethods map[string]bool) (map[string]bool, map[string]map[string]bool, map[string]bool, map[string]map[string]bool) {
	if p == nil || p.TypesInfo == nil {
		return nil, nil, nil, nil
	}
	proven := map[string]bool{}
	deps := map[string]map[string]bool{}
	retention := map[string]bool{}
	retentionDeps := map[string]map[string]bool{}
	retentionConditional := map[string]map[string]bool{}
	// A parameter's proof may rely on other parameters: a rooted
	// argument handed to another plain named function chains when that
	// parameter proves leak-free. Same-package chains resolve here to
	// an intra-package fixed point, mutual recursion refusing; a chain
	// touching a foreign parameter records conditional edges instead,
	// resolved at composition to a least fixed point exactly as the
	// constructor proofs resolve - cycles and absence refusing
	// (REQ-closure-shared-dynamic-state).
	conditional := map[string]map[string]bool{}
	ownPath := ""
	if p.Types != nil {
		ownPath = p.Types.Path()
	}
	// Method wants at fact time resolve against the package's own
	// receiver-read-only fixed point, computed once by the fact assembly;
	// a cross-package method want leaves the parameter unproven - only
	// parameter wants earn the conditional-edge channel, method wants
	// stay fact-time-local, deliberate conservatism.
	//
	// retainOnly attempts the retention grade where the leak-free grade
	// failed: same collection, same method-want resolution, the needs
	// satisfiable by either grade of the chained parameter (a write in
	// the chain is a write through the same bound value).
	retainOnly := func(obj types.Object, body ast.Node, key string) {
		wants := map[string]bool{}
		methodWants := map[string]bool{}
		if !boundValueRetentionFreeJudged(audited, p, map[types.Object]bool{obj: true}, body, wants, methodWants) {
			return
		}
		for want := range methodWants {
			// The retention grade tolerates writes, so a method call on
			// the binding needs the retention proof alone - read-only
			// never substitutes, a reading method can still retain.
			pkgPath, rest, ok := strings.Cut(want, "\x00")
			if !ok || pkgPath != ownPath || !retentionMethods[rest] {
				return
			}
		}
		if len(wants) == 0 {
			retention[key] = true
			return
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
			retentionConditional[key] = local
			return
		}
		edges := map[string]bool{}
		for want := range wants {
			edges[want] = true
		}
		retentionDeps[key] = edges
	}
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
					key := fd.Name.Name + "\x00" + strconv.Itoa(idx)
					wants := map[string]bool{}
					methodWants := map[string]bool{}
					if !boundValueLeakFreeJudged(audited, p, map[types.Object]bool{obj: true}, fd.Body, wants, nil, methodWants, nil, nil) {
						retainOnly(obj, fd.Body, key)
						continue
					}
					methodsProven := true
					for want := range methodWants {
						// The leak-free contract includes never-outliving:
						// a read-only method can still retain the binding
						// (a goroutine capture reads after the call ends),
						// so both grades must hold.
						pkgPath, rest, ok := strings.Cut(want, "\x00")
						if !ok || pkgPath != ownPath || !readOnlyLocal[rest] || !retentionMethods[rest] {
							methodsProven = false
							break
						}
					}
					if !methodsProven {
						continue
					}
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
						continue
					}
					// The chain leaves the package: every want becomes a
					// composition-resolved edge, full-keyed - the local
					// fixed point cannot see foreign facts.
					edges := map[string]bool{}
					for want := range wants {
						edges[want] = true
					}
					deps[key] = edges
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
	// A same-package chain the local fixed point could not close may
	// still resolve through a foreign hop downstream - the amended
	// clause conditions on the chain, not the first hop. Promote each
	// unresolved entry's remaining needs to composition-resolved edges,
	// full-keyed; a purely mutual recursion becomes a composition cycle
	// and refuses there exactly as it refused here.
	for key, needs := range conditional {
		if proven[key] {
			continue
		}
		edges := deps[key]
		if edges == nil {
			edges = map[string]bool{}
		}
		for need := range needs {
			if !proven[need] {
				edges[ownPath+"\x00"+need] = true
			}
		}
		deps[key] = edges
	}
	// The retention grade's chains resolve identically, satisfiable by
	// either grade - a leak-free hop retains nothing a fortiori.
	for changed := true; changed; {
		changed = false
		for key, needs := range retentionConditional {
			if retention[key] || proven[key] {
				continue
			}
			ok := true
			for need := range needs {
				if !retention[need] && !proven[need] {
					ok = false
					break
				}
			}
			if ok {
				retention[key] = true
				changed = true
			}
		}
	}
	for key, needs := range retentionConditional {
		if retention[key] || proven[key] {
			continue
		}
		edges := retentionDeps[key]
		if edges == nil {
			edges = map[string]bool{}
		}
		for need := range needs {
			if !retention[need] && !proven[need] {
				edges[ownPath+"\x00"+need] = true
			}
		}
		retentionDeps[key] = edges
	}
	return proven, deps, retention, retentionDeps
}

// receiverRetentionFreeMethods proves, in the declaring package alone,
// which methods never escape or outlive their receiver: writes through
// the receiver are tolerated - the grade an init-flow receiver deferral
// resolves against, where direct stores are the region's own exempt
// shape - while every escape shape keeps the leak-free rules. The
// read-only grade never substitutes: a method can read its receiver
// only and still retain it (a goroutine capture reads after
// initialization ends), so retention is proven for every method on its
// own. A receiver handed to a parameter leaves the proof, and a method
// chains only into same-package siblings proven retention-free - an
// intra-package fixed point, fail-closed on every other shape
// (REQ-closure-shared-dynamic-state). Keys are "Recv.Method"; the fact
// layer prefixes the package path.
func receiverRetentionFreeMethods(audited bool, p *packages.Package, readOnlyLocal map[string]bool) map[string]bool {
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
			recvName := recvTypeName(fd)
			if recvName == "" {
				continue
			}
			key := recvName + "." + fd.Name.Name
			var recvIdent *ast.Ident
			if names := fd.Recv.List[0].Names; len(names) == 1 && names[0].Name != "_" {
				recvIdent = names[0]
			}
			if recvIdent == nil {
				// A blank or anonymous receiver cannot be referenced -
				// nothing can retain it.
				proven[key] = true
				continue
			}
			recvObj := p.TypesInfo.Defs[recvIdent]
			if recvObj == nil {
				continue
			}
			wants := map[string]bool{}
			methodWants := map[string]bool{}
			if !boundValueRetentionFreeJudged(audited, p, map[types.Object]bool{recvObj: true}, fd.Body, wants, methodWants) {
				continue
			}
			if len(wants) != 0 {
				// A receiver handed to a parameter leaves the method's
				// own proof - deliberate conservatism of the receiver
				// grade.
				continue
			}
			needs := map[string]bool{}
			sound := true
			for want := range methodWants {
				pkgPath, rest, ok := strings.Cut(want, "\x00")
				if !ok || pkgPath != ownPath {
					sound = false
					break
				}
				needs[rest] = true
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
	for changed := true; changed; {
		changed = false
		for key, needs := range pending {
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
func receiverReadOnlyMethods(audited bool, p *packages.Package) map[string]bool {
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
			return true, !instantiatedResultsHandOutNothing(audited, selection.Type())
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
						if t := p.TypesInfo.TypeOf(n); t != nil && !typeHandsOutMutableReach(t, make(map[types.Type]bool)) && !typeCarriesSignature(t, make(map[types.Type]bool)) {
							consume(n.Args[0])
						}
					}
					break
				}
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok && recvRooted(sel.X) {
					if selection, ok := p.TypesInfo.Selections[sel]; ok && selection.Kind() == types.MethodVal {
						if fn, ok := selection.Obj().(*types.Func); ok && auditedSynchronization(audited, fn) {
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
					// reach exactly as before the taint paths existed -
					// and a signature-carrying value IS its environment,
					// so it refuses whatever the reach walk says
					// (the receiver-stored closure launder).
					if t := p.TypesInfo.TypeOf(n); t == nil || typeHandsOutMutableReach(t, make(map[types.Type]bool)) || typeCarriesSignature(t, make(map[types.Type]bool)) {
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
					// A signature-carrying produced value refuses whatever
					// the reach walk says of its type: a constructor-
					// installed closure captures the receiver invisibly to
					// the carrier rules, so a func-valued field read - or
					// a composite holding one - is mutable reach unless
					// the declaring package could prove every install
					// environment-free, which this engine does not audit
					// (the receiver-stored closure launder).
					if t := p.TypesInfo.TypeOf(n); t == nil || typeHandsOutMutableReach(t, make(map[types.Type]bool)) || typeCarriesSignature(t, make(map[types.Type]bool)) {
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
func instantiatedResultsHandOutNothing(audited bool, t types.Type) bool {
	sig, ok := types.Unalias(t).(*types.Signature)
	if !ok {
		return false
	}
	results := sig.Results()
	for i := 0; results != nil && i < results.Len(); i++ {
		rt := results.At(i).Type()
		if auditedImmutableType(audited, rt) {
			continue
		}
		// A signature-carrying result IS its environment - the method
		// can hand back receiver-reaching state on the value plane
		// whatever the reach walk says (REQ-closure-shared-dynamic-state).
		if typeHandsOutMutableReach(rt, make(map[types.Type]bool)) || typeCarriesSignature(rt, make(map[types.Type]bool)) {
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
func auditedImmutableType(audited bool, t types.Type) bool {
	if !audited {
		return false
	}
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
func auditedSynchronization(audited bool, fn *types.Func) bool {
	if !audited || fn.Pkg() == nil || fn.Pkg().Path() != "sync" {
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

// auditedPooling reports whether the method is in the audited pooling
// set: sync.Pool's Get and Put. Under the caller-attested
// single-subject-process execution model (WithSingleSubjectExecution)
// every in-process Put site lies in the subject's own rooted flow, so
// pool contents are a function of the analyzed source and the subject
// alone, and their contractual removability is why the values need no
// per-item pricing at the call — a Get or Put CALL on a package-level
// pool carrier is then not mutation of the carrier, while the values
// passed and produced keep their own full pricing. Without the
// attestation, a pool use is admitted only through the content-proven
// discharge (provenSharedPools); every pool the proof does not cover
// keeps the fail-closed judgment at every use.
// Grows only by source audit (REQ-closure-shared-dynamic-state).
func auditedPooling(audited bool, fn *types.Func) bool {
	if !audited || fn.Pkg() == nil || fn.Pkg().Path() != "sync" {
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
	if !ok || named.Obj() == nil || named.Obj().Name() != "Pool" {
		return false
	}
	switch fn.Name() {
	case "Get", "Put":
		return true
	default:
		return false
	}
}

// provenSharedPools derives the package's content-proven pools and
// their admitted call selectors: the audited pooling set's
// engine-proven discharge, admitting Get/Put in any execution model
// when the declaration alone could ever type the pool's contents
// (REQ-closure-shared-dynamic-state). A pool is content-proven
// exactly when it is an unexported package-level sync.Pool variable —
// unexported so every reference site lies in the owning package's
// compilation variants; the shared-dynamic-state marks are keyed
// variant-blind and union at composition, so a dirty site in any
// variant downgrades every subject linking the package (stricter
// than per-variant, never weaker) — declared with a composite
// literal whose single field is a New function literal with no named
// results and no defer in its own body (the post-return channels
// that could retype or nil the produced value —
// provenPoolContentType), every
// return of that literal one identical concrete
// dynamic-carrier-free type T (never untyped), and the variable's
// every other appearance in this package's syntax is exactly the
// receiver of a Get or Put call — any other appearance, a New-field
// access or an initializer-flow write included, evicts the proof
// wholesale. Put-argument conformance stays a per-site judgment
// (provenPoolCallConforms): a non-conforming site keeps its own
// fail-closed mark without evicting the proof. Contents are then
// always of type T under every schedule — New is total and every
// plant is T, so the interface value Get yields is never nil — and
// no type assertion, type switch, or method dispatch can distinguish
// subject orders; the data plane stays order-sensitive exactly as
// any data-only package variable the invariant never triggers on.
// The engine's own verdict, not a caller assertion: no attestation,
// no evidence record. calls marks each Get/Put call selector the
// discharge admits — a conforming call on a surviving proven pool —
// derived here, in one place, so the admission gates and the
// eviction judge one shape.
func provenSharedPools(audited bool, p *packages.Package) (proven map[*types.Var]types.Type, calls map[*ast.SelectorExpr]bool) {
	proven = map[*types.Var]types.Type{}
	calls = map[*ast.SelectorExpr]bool{}
	if p.TypesInfo == nil {
		return proven, calls
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
					continue
				}
				name := vs.Names[0]
				if name.IsExported() {
					continue
				}
				// file.Decls yields only package-scope declarations, so
				// the Defs object needs no scope check.
				variable, ok := p.TypesInfo.Defs[name].(*types.Var)
				if !ok || variable.Pkg() == nil {
					continue
				}
				named, ok := types.Unalias(variable.Type()).(*types.Named)
				if !ok || named.Obj() == nil || named.Obj().Pkg() == nil ||
					named.Obj().Pkg().Path() != "sync" || named.Obj().Name() != "Pool" {
					continue
				}
				lit, ok := unparenExpr(vs.Values[0]).(*ast.CompositeLit)
				if !ok || len(lit.Elts) != 1 {
					continue
				}
				kv, ok := lit.Elts[0].(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "New" {
					continue
				}
				fnLit, ok := unparenExpr(kv.Value).(*ast.FuncLit)
				if !ok {
					continue
				}
				content := provenPoolContentType(audited, p, fnLit)
				if content == nil {
					continue
				}
				proven[variable] = content
			}
		}
	}
	if len(proven) == 0 {
		return proven, calls
	}
	// One walk resolves every audited Get/Put call on a candidate: the
	// receiver idents (the only appearances that do not evict) and the
	// per-site conformance verdict. The receiver shape is exactly what
	// the admission gates consult — an unparenthesized selector on an
	// unparenthesized ident — judged here once, so a shape a gate
	// would not admit evicts, fail-closed.
	receiver := map[*ast.Ident]bool{}
	type poolCall struct {
		variable *types.Var
		conforms bool
	}
	sites := map[*ast.SelectorExpr]poolCall{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			selection, ok := p.TypesInfo.Selections[sel]
			if !ok || selection.Kind() != types.MethodVal {
				return true
			}
			fn, ok := selection.Obj().(*types.Func)
			if !ok || !auditedPooling(audited, fn) {
				return true
			}
			receiver[ident] = true
			variable, ok := p.TypesInfo.Uses[ident].(*types.Var)
			if !ok {
				return true
			}
			if content, candidate := proven[variable]; candidate {
				sites[sel] = poolCall{variable: variable, conforms: provenPoolCallConforms(p, fn, call, content)}
			}
			return true
		})
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			variable, ok := p.TypesInfo.Uses[ident].(*types.Var)
			if !ok {
				return true
			}
			if _, candidate := proven[variable]; candidate && !receiver[ident] {
				delete(proven, variable)
			}
			return true
		})
	}
	// Admitted calls are derived after eviction so an evicted pool's
	// sites never admit.
	for sel, site := range sites {
		if _, stands := proven[site.variable]; stands && site.conforms {
			calls[sel] = true
		}
	}
	return proven, calls
}

// provenPoolContentType derives the single concrete content type a
// conforming New function literal could ever produce, or nil when the
// literal does not conform: no named results (a deferred write to a
// named result retypes the produced value after the return
// expression this derivation reads — refusing the signature shape is
// the fail-closed answer, and it holds without a defer in sight: a
// racing goroutine can write a named result too), no defer statement
// in the literal's own body (a deferred call is the only channel
// that can rewrite a named result or recover a panic into a
// zero-valued — nil-interface — return; either retypes or nils the
// produced value after the return expressions the derivation reads,
// and a New literal has no legitimate use for defer), and every
// return statement at the
// literal's own depth (nested literals are their own functions) must
// return one expression of one identical concrete type — never
// untyped (an untyped nil would let Get yield nil, and nil-vs-T is a
// type-plane outcome subject order could steer) — and that type must
// be free of dynamic carriers under the invariant's own trigger
// predicate (REQ-closure-shared-dynamic-state). A panic that
// propagates out of New is outside the proof's claims exactly as
// under the attestation: contents are contractually removable at any
// time, so whether New runs at all is undetermined either way, and a
// verdict conditioned on it is out of contract in every execution
// model.
func provenPoolContentType(audited bool, p *packages.Package, lit *ast.FuncLit) types.Type {
	if lit.Type == nil || lit.Type.Results == nil {
		return nil
	}
	for _, field := range lit.Type.Results.List {
		if len(field.Names) > 0 {
			return nil
		}
	}
	var content types.Type
	conforming := true
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		if !conforming {
			return false
		}
		if _, nested := n.(*ast.FuncLit); nested {
			return false
		}
		if _, deferred := n.(*ast.DeferStmt); deferred {
			conforming = false
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		if len(ret.Results) != 1 {
			conforming = false
			return false
		}
		tv, ok := p.TypesInfo.Types[ret.Results[0]]
		if !ok || tv.Type == nil {
			conforming = false
			return false
		}
		t := tv.Type
		// The untyped rejection is the single source of the "never
		// untyped" bound: with T never untyped, an untyped Put argument
		// can never be Identical to T, so the per-site judgment needs no
		// untyped check of its own. Interfaces need no check at all —
		// an interface is itself a dynamic carrier, so the carrier
		// predicate below rejects it.
		if basic, isBasic := types.Unalias(t).(*types.Basic); isBasic && basic.Info()&types.IsUntyped != 0 {
			conforming = false
			return false
		}
		if content == nil {
			content = t
		} else if !types.Identical(content, t) {
			conforming = false
			return false
		}
		return true
	})
	if !conforming || content == nil {
		return nil
	}
	if typeMayCarryUnknownDynamic(audited, content, make(map[types.Type]bool)) {
		return nil
	}
	return content
}

// provenPoolCallConforms judges one Get or Put call against a proven
// pool's content type. Get takes no argument; a Put conforms exactly
// when its single argument's static type is identical to T — an
// untyped or differently-typed argument is not admitted and keeps the
// fail-closed judgment (REQ-closure-shared-dynamic-state).
func provenPoolCallConforms(p *packages.Package, fn *types.Func, call *ast.CallExpr, content types.Type) bool {
	switch fn.Name() {
	case "Get":
		return len(call.Args) == 0
	case "Put":
		if len(call.Args) != 1 {
			return false
		}
		tv, ok := p.TypesInfo.Types[call.Args[0]]
		if !ok || tv.Type == nil {
			return false
		}
		// T is never untyped (provenPoolContentType's bound), so an
		// untyped argument can never be Identical to it — no separate
		// untyped check.
		return types.Identical(tv.Type, content)
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
// included - the strongest region class of those references: the
// reference edges from init flow ("init") and from other plain named
// functions (the caller's own function key) compose to the graph-wide
// init-only fixed point; a reference from a literal or go-statement
// context nested in NAMED flow, and a value reference in named flow,
// record as "lit:" plus the enclosing region's base key — never
// init-only-provable (the value or deferred body outlives the frame),
// init-REACHABLE exactly when the encloser is (the reference cannot
// execute, and a value cannot be handed out, unless the encloser ran);
// a literal or value reference in init flow or method bodies stays
// "prog", poisoned everywhere — its creation site the regions cannot
// bound (REQ-closure-shared-dynamic-state's cross-package init-only
// class and init-reach dual). Keys are pkgPath NUL name; edges are
// joined caller NUL callee at composition via the fact schema.
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
	// literalRegion bounds a nested literal's (or handed-out value's)
	// execution by its enclosing named flow: inside a caller-keyed or
	// already-lit region the bound is the base caller key; init flow
	// and method bodies give no bound ("prog" - the value outlives
	// initialization, and method regions are not part of the fixed
	// point).
	literalRegion := func(region string) string {
		if strings.HasPrefix(region, "lit:") {
			return region
		}
		if region == "init" || region == "prog" {
			return "prog"
		}
		return "lit:" + region
	}
	var scan func(region string, root ast.Node)
	scan = func(region string, root ast.Node) {
		calls := map[*ast.Ident]bool{}
		ast.Inspect(root, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit:
				if n != root && n.Body != nil {
					scan(literalRegion(region), n.Body)
					return false
				}
			case *ast.GoStmt:
				scan(literalRegion(region), n.Call)
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
					// value: never init-only-provable, init-reachable
					// exactly when the handing flow is.
					add(key, literalRegion(region))
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
// (errors.New; a direct reflect.TypeOf call; a fmt.Errorf call chained
// through audited arguments; the nil zero value), so no
// holder of the value can mutate the shared object and escapes of it
// are not mutation. Every
// plain named function's direct body is audited, not just init bodies
// and package-locally-proven helpers: whether a function is init flow
// is settled only at composition (the graph-wide fixed point), and a
// store the composition discharges as init flow must have passed this
// audit — for a function that stays program code the store marks
// mutation anyway, so the extra break is unobservable. deps collects
// conditional dependency edges: a store admitted through a sibling
// object-closed variable reference (the wrapped-sentinel idiom) is
// closed exactly when the sibling stays closed, resolved at
// composition against the unioned break set — declaration and store
// order never decide (REQ-closure-shared-dynamic-state). The
// audited-construction set grows only by source audit
// (REQ-closure-shared-dynamic-state).
func recordOpaqueDynamicVars(p *packages.Package, opaque, breaks map[string]bool, deps map[string]map[string]bool) {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return
	}
	interfacePackageVar := func(obj types.Object) (*types.Var, bool) {
		variable, ok := obj.(*types.Var)
		if !ok || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
			return nil, false
		}
		_, isInterface := types.Unalias(variable.Type()).Underlying().(*types.Interface)
		return variable, isInterface
	}
	// auditedImmutable judges a stored value; storeDeps, when non-nil,
	// collects the object-closed variables the admission is conditional
	// on. auditedArgument judges a value in a retained argument or
	// store position, where a reference to another package-level
	// interface variable additionally admits as a dependency edge.
	var auditedImmutable func(expr ast.Expr, storeDeps map[string]bool) bool
	auditedArgument := func(expr ast.Expr, storeDeps map[string]bool) bool {
		if auditedImmutable(expr, storeDeps) {
			return true
		}
		// A reference to a package-level interface-typed variable —
		// sibling or imported, a bare identifier or a pkg-qualified
		// selector, resolved semantically by the type checker (a
		// dot-imported name resolves to its one object; no textual
		// ambiguity survives type checking) — chains the judgment: the
		// construction is closed exactly when the referent stays
		// object-closed, recorded as a dependency edge and resolved at
		// composition against every fact's break set, an undeclared
		// referent (a module-less package's variable, which no fact
		// audits) refusing fail-closed there
		// (REQ-closure-shared-dynamic-state).
		if storeDeps != nil {
			var target *ast.Ident
			switch e := unparenExpr(expr).(type) {
			case *ast.Ident:
				target = e
			case *ast.SelectorExpr:
				if x, ok := e.X.(*ast.Ident); ok {
					if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
						target = e.Sel
					}
				}
			}
			if target != nil {
				if obj, ok := p.TypesInfo.Uses[target]; ok {
					if variable, ok := interfacePackageVar(obj); ok {
						storeDeps[dynamicVarKey(variable)] = true
						return true
					}
				}
			}
		}
		return false
	}
	auditedImmutable = func(expr ast.Expr, storeDeps map[string]bool) bool {
		// A constant-valued expression (a literal, a typed or untyped
		// named constant, a folded expression — the syscall.Errno
		// sentinel shape included) boxes a basic-kind value: the boxed
		// object carries no mutable reach at all, so no holder of the
		// stored interface value can write through it — audited exactly
		// as the nil zero value is, while rebinding the variable remains
		// mutation everywhere (REQ-closure-shared-dynamic-state).
		if tv, ok := p.TypesInfo.Types[expr]; ok && tv.Value != nil {
			return true
		}
		// A value of static type reflect.Type is runtime-canonical
		// whatever expression produced it: the interface is sealed by
		// unexported methods, so its every referent is the runtime's
		// immutable type descriptor (or nil) — reflect.TypeOf results,
		// chained view methods (Elem, Key, ...), and rebinds from other
		// descriptors alike. The object-closed mirror of the effect
		// tiers' audited-immutable ruling; the producing expression's
		// own operands keep their own pricing at the use walks
		// (REQ-closure-shared-dynamic-state).
		if t := p.TypesInfo.TypeOf(expr); t != nil {
			if named, ok := types.Unalias(t).(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() != nil {
				if named.Obj().Pkg().Path() == "reflect" && named.Obj().Name() == "Type" {
					return true
				}
			}
		}
		switch expr := expr.(type) {
		case *ast.Ident:
			return expr.Name == "nil" && p.TypesInfo.Uses[expr] == types.Universe.Lookup("nil")
		case *ast.CallExpr:
			sel, ok := expr.Fun.(*ast.SelectorExpr)
			if !ok {
				return false
			}
			fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
			if !ok || fn.Pkg() == nil {
				return false
			}
			if fn.Pkg().Path() == "errors" && fn.Name() == "New" {
				return true
			}
			// A direct fmt.Errorf call retains at most its argument
			// objects (the %w-wrapped errors; every other argument is
			// rendered into the immutable message), so the construction
			// is object-closed exactly when every argument is audited —
			// judged structurally over ALL arguments, never by parsing
			// the format string: a constant, a nested audited
			// construction, or a sibling object-closed variable
			// reference admits; any other argument shape refuses
			// fail-closed (REQ-closure-shared-dynamic-state).
			if fn.Pkg().Path() == "fmt" && fn.Name() == "Errorf" {
				if sig, ok := fn.Type().(*types.Signature); !ok || sig.Recv() != nil {
					return false
				}
				for _, arg := range expr.Args {
					if !auditedArgument(arg, storeDeps) {
						return false
					}
				}
				return true
			}
			return false
		default:
			return false
		}
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
			key := dynamicVarKey(variable)
			storeDeps := map[string]bool{}
			// The store value judges under the argument shapes: audited
			// constructions plus references to other package-level
			// interface variables (the re-export idiom), the latter as
			// dependency edges falling with the referent's closure
			// (REQ-closure-shared-dynamic-state).
			if value == nil || !auditedArgument(value, storeDeps) {
				failed[key] = true
				return
			}
			for dep := range storeDeps {
				if deps == nil {
					break
				}
				if deps[key] == nil {
					deps[key] = map[string]bool{}
				}
				deps[key][dep] = true
			}
		}
	}
	failSubtree := func(expr ast.Expr) {
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
	// failTargets fails the interface package variables a target
	// expression can actually write or capture: the base chain through
	// selections, indexing, indirection, and parentheses. An index
	// expression is a read of its key - a registry indexed by a
	// sentinel never writes the sentinel - discharged exactly as the
	// carrier read rules discharge writeless reads; an unrecognized
	// target shape keeps the whole-subtree fail-close.
	failTargets := func(expr ast.Expr) {
		for {
			switch t := expr.(type) {
			case *ast.Ident:
				if obj, ok := p.TypesInfo.Uses[t]; ok {
					if variable, ok := interfacePackageVar(obj); ok {
						failed[dynamicVarKey(variable)] = true
					}
				}
				return
			case *ast.SelectorExpr:
				// A qualified reference (pkg.Var) resolves as the
				// variable itself; a field selector chains to its base.
				if obj, ok := p.TypesInfo.Uses[t.Sel]; ok {
					if variable, ok := interfacePackageVar(obj); ok {
						failed[dynamicVarKey(variable)] = true
						return
					}
				}
				expr = t.X
			case *ast.IndexExpr:
				expr = t.X
			case *ast.StarExpr:
				expr = t.X
			case *ast.ParenExpr:
				expr = t.X
			default:
				failSubtree(expr)
				return
			}
		}
	}
	// failCaptures runs the init-flow fail arms over an expression: an
	// address capture licenses later unattributable stores wherever it
	// sits - a package-level initializer expression included - while a
	// nested literal stays program code for the mutation walk to judge.
	failCaptures := func(expr ast.Expr) {
		ast.Inspect(expr, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.UnaryExpr:
				// The address of a composite literal is the fresh
				// object's — it licenses stores into that object only,
				// never an unattributable store into a variable its
				// elements reference; a nested capture inside the
				// literal breaks through its own visit
				// (REQ-closure-shared-dynamic-state).
				if n.Op == token.AND {
					if _, composite := unparenExpr(n.X).(*ast.CompositeLit); !composite {
						failTargets(n.X)
					}
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
						if value != nil {
							// An initializer expression is init flow: a
							// capture inside it breaks the closure exactly
							// as one in an init body does.
							failCaptures(value)
						}
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
							var value ast.Expr
							if i < len(n.Rhs) {
								value = n.Rhs[i]
							}
							switch target := lhs.(type) {
							case *ast.Ident:
								audit(target, value)
							case *ast.SelectorExpr:
								// A qualified store (pkg.Var = ...) is a
								// direct store the auditing package
								// resolves to the variable - the spec's
								// clause admits it from any package - so
								// it takes the same value audit as an
								// identifier store; a field selector is
								// the unattributable fail arm's.
								if base, ok := target.X.(*ast.Ident); ok {
									if _, isPkg := p.TypesInfo.Uses[base].(*types.PkgName); isPkg {
										audit(target.Sel, value)
										continue
									}
								}
								failTargets(lhs)
							default:
								// An indirect store the audit cannot
								// attribute fails every interface variable
								// the target chain reaches.
								failTargets(lhs)
							}
						}
					case *ast.UnaryExpr:
						if n.Op == token.AND {
							// An init-flow address capture licenses later
							// unattributable stores - fail-close. A
							// composite literal's address is the fresh
							// object's alone; nested captures break
							// through their own visit
							// (REQ-closure-shared-dynamic-state).
							if _, composite := unparenExpr(n.X).(*ast.CompositeLit); !composite {
								failTargets(n.X)
							}
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
func typeHandsOutDynamicAlias(audited bool, t types.Type, seen map[types.Type]bool) bool {
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
		return typeMayCarryUnknownDynamic(audited, t.Elem(), make(map[types.Type]bool))
	case *types.Pointer:
		return typeMayCarryUnknownDynamic(audited, t.Elem(), make(map[types.Type]bool))
	case *types.Map:
		return typeMayCarryUnknownDynamic(audited, t.Key(), make(map[types.Type]bool)) || typeMayCarryUnknownDynamic(audited, t.Elem(), make(map[types.Type]bool))
	case *types.Slice:
		return typeMayCarryUnknownDynamic(audited, t.Elem(), make(map[types.Type]bool))
	case *types.Named:
		// The audited atomic transparency: the toolchain's atomic
		// pointer reads as *T, so it hands out an alias exactly when a
		// *T read would — the Pointer arm's judgment of T.
		if elem, ok := closure.AuditedAtomicPointerElem(audited, t); ok {
			return typeMayCarryUnknownDynamic(audited, elem, make(map[types.Type]bool))
		}
		return typeHandsOutDynamicAlias(audited, t.Underlying(), seen)
	case *types.TypeParam:
		return typeHandsOutDynamicAlias(audited, t.Constraint(), seen)
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if typeHandsOutDynamicAlias(audited, t.Field(i).Type(), seen) {
				return true
			}
		}
	case *types.Array:
		return typeHandsOutDynamicAlias(audited, t.Elem(), seen)
	case *types.Tuple:
		for i := 0; i < t.Len(); i++ {
			if typeHandsOutDynamicAlias(audited, t.At(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}
