package gofresh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/types"
	"sort"
	"sync"

	"github.com/greatliontech/gofresh/closure"
	"golang.org/x/tools/go/packages"
)

// dynamicStateFact is one package's contribution to the shared-dynamic-state
// downgrade (REQ-closure-shared-dynamic-state) plus its method-directive
// declarations: everything the analysis needs from the package's syntax, so a
// version-pinned package's syntax never loads twice per key.
type dynamicStateFact struct {
	// Declares holds the package's dynamic-capable package-level variable
	// keys (package path + name). Standard-library packages declare none
	// here by construction — the downgrade analysis has always excluded
	// module-less packages from its declaration side.
	Declares []string `json:"declares,omitempty"`
	// Mutates holds the variable keys this package's code mutates after
	// initialization, judged fail-closed by carrier shape.
	Mutates []string `json:"mutates,omitempty"`
	// PureMethods and ExternalMethods map "Recv.Method" to the declaration
	// key of a method declaration carrying the respective directive, so a
	// method promoted into a scanned type honors its directive without the
	// declaring package's syntax in hand (REQ-purity-directive,
	// REQ-external-directive).
	PureMethods     map[string]string `json:"pureMethods,omitempty"`
	ExternalMethods map[string]string `json:"externalMethods,omitempty"`
}

// dynamicStateFactOf derives one typed package's fact. Pure function of the
// package's selected syntax and type environment.
func dynamicStateFactOf(p *packages.Package) dynamicStateFact {
	var fact dynamicStateFact
	mutated := map[string]bool{}
	recordDynamicGlobalMutations(p, mutated)
	for key := range mutated {
		fact.Mutates = append(fact.Mutates, key)
	}
	sort.Strings(fact.Mutates)
	if p.Types != nil && p.Module != nil {
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			if variable, ok := scope.Lookup(name).(*types.Var); ok && typeMayCarryUnknownDynamic(variable.Type(), make(map[types.Type]bool)) {
				fact.Declares = append(fact.Declares, dynamicVarKey(variable))
			}
		}
		sort.Strings(fact.Declares)
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil {
				continue
			}
			recv := recvTypeName(fd)
			if recv == "" {
				continue
			}
			key := recv + "." + fd.Name.Name
			if hasDirective(fd.Doc, "//gofresh:pure") {
				if fact.PureMethods == nil {
					fact.PureMethods = map[string]string{}
				}
				fact.PureMethods[key] = nodeDeclarationKey(p, fd.Name)
			}
			if hasDirective(fd.Doc, "//gofresh:external") {
				if fact.ExternalMethods == nil {
					fact.ExternalMethods = map[string]string{}
				}
				fact.ExternalMethods[key] = nodeDeclarationKey(p, fd.Name)
			}
		}
	}
	return fact
}

// dynamicStateMissLoadHook observes the batched typed load of version-pinned
// packages whose facts neither cache layer served — the event tests pin to
// prove the memo actually substitutes for loading.
var dynamicStateMissLoadHook func(patterns []string)

// processFactCache serves version-pinned package facts within one process.
// Keyed by (scope, bucket, package path) — the same complete identity the
// persistent memo trusts, so a hit is sound wherever the persistent entry
// would be.
var processFactCache sync.Map

// viewDynamicState is the per-pass dynamic-state derivation over one view's
// metadata graph: fresh facts for every mutable-local node from the pass's
// own typed load, memoized facts for version-pinned modules (persistent under
// factScope, in-process always), standard-library nodes skipped — inert by
// construction: their declaration side is excluded and toolchain source
// cannot reach module variables (imports are acyclic).
type viewDynamicState struct {
	// facts by type-checker package path; test-variant facts merge into the
	// same key exactly as their compilations collapse there.
	facts map[string][]dynamicStateFact
	// downgraded marks the packages whose graphs carry mutated shared
	// dynamic state: every subject of such a package is unverifiable.
	downgraded map[string]bool
}

// methodDirectives resolves a promoted method's purity and externality
// directives from its declaring package's fact — the declaration keys, empty
// when absent. Toolchain source is not an authoring surface for gofresh
// directives, so standard-library methods resolve to none by construction.
func (s *viewDynamicState) methodDirectives(m *types.Func) (pureKey, externalKey string) {
	if s == nil || m == nil || m.Pkg() == nil {
		return "", ""
	}
	sig, ok := m.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return "", ""
	}
	t := types.Unalias(sig.Recv().Type())
	if pointer, ok := t.(*types.Pointer); ok {
		t = types.Unalias(pointer.Elem())
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj() == nil {
		return "", ""
	}
	key := named.Obj().Name() + "." + m.Name()
	for _, fact := range s.facts[m.Pkg().Path()] {
		if pureKey == "" {
			pureKey = fact.PureMethods[key]
		}
		if externalKey == "" {
			externalKey = fact.ExternalMethods[key]
		}
	}
	return pureKey, externalKey
}

func deriveViewDynamicState(ctx context.Context, hasher *closure.Hasher, factScope, dir string, env, buildFlags []string, load *closure.ViewLoad, viewPackages []string) (*viewDynamicState, error) {
	meta, err := hasher.GraphMetadata(viewPackages...)
	if err != nil {
		return nil, err
	}
	state := &viewDynamicState{facts: map[string][]dynamicStateFact{}, downgraded: map[string]bool{}}

	// Mutable-local facts come from the pass's own typed load — content
	// observed every pass, never cached (REQ-closure-mutable-local). The
	// load's roots are matched to metadata nodes by listing identity so a
	// local dependency's own test variants (loaded only because Tests is a
	// load-wide setting) contribute nothing the metadata graph doesn't name.
	nodesByListing := make(map[string]closure.GraphPackage, len(meta))
	for _, node := range meta {
		nodesByListing[node.ImportPath] = node
	}
	matched := map[string]bool{}
	for _, pkg := range load.Packages() {
		listing := pkg.PkgPath
		if pkg.ForTest != "" {
			listing = pkg.PkgPath + " [" + pkg.ForTest + ".test]"
		}
		node, ok := nodesByListing[listing]
		if !ok || node.Class != closure.MutableLocalPackage {
			continue
		}
		matched[listing] = true
		state.facts[pkg.PkgPath] = append(state.facts[pkg.PkgPath], dynamicStateFactOf(pkg))
	}
	// An intermediate recompilation ("r [a.test]") exists only inside a test
	// binary's graph: it is scanned from its own compilation — test-added
	// methods can lawfully change its selections, and its plain form need
	// not even compile — through one dependency-expanded load of the tested
	// packages, performed only when the test-cycle shape exists.
	var testedWithIntermediates []string
	seenTested := map[string]bool{}
	for _, node := range meta {
		if node.Class == closure.StandardPackage || matched[node.ImportPath] || node.TestMain || node.ForTest == "" {
			continue
		}
		if node.PkgPath == node.ForTest || node.PkgPath == node.ForTest+"_test" {
			continue
		}
		if !seenTested[node.ForTest] {
			seenTested[node.ForTest] = true
			testedWithIntermediates = append(testedWithIntermediates, node.ForTest)
		}
	}
	if len(testedWithIntermediates) > 0 {
		sort.Strings(testedWithIntermediates)
		graphLoad, err := closure.LoadViewGraphEnv(ctx, dir, env, buildFlags, testedWithIntermediates...)
		if err != nil {
			return nil, err
		}
		packages.Visit(graphLoad.Packages(), nil, func(pkg *packages.Package) {
			if pkg.ForTest == "" {
				return
			}
			listing := pkg.PkgPath + " [" + pkg.ForTest + ".test]"
			node, ok := nodesByListing[listing]
			if !ok || node.Class == closure.StandardPackage || matched[listing] {
				return
			}
			matched[listing] = true
			state.facts[pkg.PkgPath] = append(state.facts[pkg.PkgPath], dynamicStateFactOf(pkg))
		})
	}
	for _, node := range meta {
		if node.TestMain || node.Class == closure.StandardPackage || matched[node.ImportPath] {
			continue
		}
		if node.Class == closure.PinnedPackage && node.ForTest == "" {
			// The pinned fact path below derives it or fails loudly.
			continue
		}
		if node.Class == closure.PinnedPackage && (node.PkgPath == node.ForTest || node.PkgPath == node.ForTest+"_test") {
			// A test variant of a module-cache-resident package: the view
			// packages are the only test-expanded ones, and a subject
			// package inside the read-only cache has no runnable tests to
			// vouch for it — name the refusal rather than surfacing it as
			// a coverage gap.
			return nil, fmt.Errorf("gofresh: dynamic-state scan: view package %s resolves into the module cache; module-cache-resident subjects are unsupported", node.ForTest)
		}
		return nil, fmt.Errorf("gofresh: dynamic-state scan did not cover package %s", node.ImportPath)
	}

	// Version-pinned facts: in-process cache, then the persistent memo,
	// then one batched typed load of the missing packages. The bucket key
	// completes the pure function's identity with the module pin and its
	// import-cone version signature — a dependency bump that could reshape
	// a carrier type moves the key (REQ-closure-dynamic-state-memo).
	buckets, unkeyable := pinnedBuckets(meta)
	var missing []closure.GraphPackage
	persisted := map[string]map[string]json.RawMessage{}
	for _, node := range meta {
		if node.Class != closure.PinnedPackage || node.ForTest != "" || node.TestMain {
			continue
		}
		if unkeyable[node.Pin] {
			// Part of this module's type environment is mutable-local: no
			// key can pin its fact, so it derives fresh every pass and
			// enters no cache layer (REQ-closure-dynamic-state-memo).
			missing = append(missing, node)
			continue
		}
		bucket := buckets[node.Pin]
		cacheKey := factScope + "\x00" + bucket + "\x00" + node.PkgPath
		if cached, ok := processFactCache.Load(cacheKey); ok {
			state.facts[node.PkgPath] = append(state.facts[node.PkgPath], cached.(dynamicStateFact))
			continue
		}
		if persisted[bucket] == nil {
			if facts := closure.LoadDynamicStateFacts(factScope, bucket); facts != nil {
				persisted[bucket] = facts
			} else {
				persisted[bucket] = map[string]json.RawMessage{}
			}
		}
		if raw, ok := persisted[bucket][node.PkgPath]; ok {
			var fact dynamicStateFact
			if json.Unmarshal(raw, &fact) == nil {
				processFactCache.Store(cacheKey, fact)
				state.facts[node.PkgPath] = append(state.facts[node.PkgPath], fact)
				continue
			}
		}
		missing = append(missing, node)
	}
	if len(missing) > 0 {
		patterns := make([]string, 0, len(missing))
		for _, node := range missing {
			patterns = append(patterns, node.PkgPath)
		}
		sort.Strings(patterns)
		if dynamicStateMissLoadHook != nil {
			dynamicStateMissLoadHook(patterns)
		}
		missLoad, err := closure.LoadViewPackagesEnv(ctx, dir, env, buildFlags, patterns...)
		if err != nil {
			return nil, err
		}
		derived := map[string]dynamicStateFact{}
		for _, pkg := range missLoad.Packages() {
			if pkg.ForTest != "" || pkg.Name == "main" {
				continue
			}
			for _, loadErr := range pkg.Errors {
				return nil, fmt.Errorf("gofresh: dynamic-state scan: load %s: %s", pkg.PkgPath, loadErr)
			}
			derived[pkg.PkgPath] = dynamicStateFactOf(pkg)
		}
		store := map[string]map[string]json.RawMessage{}
		for _, node := range missing {
			fact, ok := derived[node.PkgPath]
			if !ok {
				return nil, fmt.Errorf("gofresh: dynamic-state scan did not load pinned package %s", node.PkgPath)
			}
			state.facts[node.PkgPath] = append(state.facts[node.PkgPath], fact)
			if unkeyable[node.Pin] {
				continue
			}
			bucket := buckets[node.Pin]
			processFactCache.Store(factScope+"\x00"+bucket+"\x00"+node.PkgPath, fact)
			if raw, err := json.Marshal(fact); err == nil {
				if store[bucket] == nil {
					store[bucket] = map[string]json.RawMessage{}
				}
				store[bucket][node.PkgPath] = raw
			}
		}
		for bucket, facts := range store {
			closure.StoreDynamicStateFacts(factScope, bucket, facts)
		}
	}

	// Compose: the mutated union across the graph, then per-node
	// declaration intersection, then reachability from each view package's
	// variants — exactly the whole-graph walk's semantics
	// (REQ-closure-shared-dynamic-state), with standard-library subgraphs
	// pruned as inert.
	mutated := map[string]bool{}
	for _, facts := range state.facts {
		for _, fact := range facts {
			for _, key := range fact.Mutates {
				mutated[key] = true
			}
		}
	}
	openWorld := map[string]bool{}
	for pkgPath, facts := range state.facts {
		for _, fact := range facts {
			for _, key := range fact.Declares {
				if mutated[key] {
					openWorld[pkgPath] = true
				}
			}
		}
	}
	imports := make(map[string][]string, len(meta))
	classes := make(map[string]closure.PackageClass, len(meta))
	pkgPathOf := make(map[string]string, len(meta))
	for _, node := range meta {
		imports[node.ImportPath] = node.Imports
		classes[node.ImportPath] = node.Class
		pkgPathOf[node.ImportPath] = node.PkgPath
	}
	isView := make(map[string]bool, len(viewPackages))
	for _, pkgPath := range viewPackages {
		isView[pkgPath] = true
	}
	var walk func(listing string, seen map[string]bool) bool
	walk = func(listing string, seen map[string]bool) bool {
		if seen[listing] {
			return false
		}
		seen[listing] = true
		if classes[listing] == closure.StandardPackage {
			return false
		}
		if openWorld[pkgPathOf[listing]] {
			return true
		}
		for _, imported := range imports[listing] {
			if _, ok := pkgPathOf[imported]; !ok {
				continue
			}
			if walk(imported, seen) {
				return true
			}
		}
		return false
	}
	for _, node := range meta {
		root := node.PkgPath
		if node.ForTest != "" {
			root = node.ForTest
		} else if node.TestMain {
			continue
		}
		if !isView[root] || state.downgraded[root] {
			continue
		}
		if walk(node.ImportPath, map[string]bool{}) {
			state.downgraded[root] = true
		}
	}
	return state, nil
}

// pinnedBuckets derives, per pinned module, the memo bucket completing its
// facts' input identity: the module's own pin plus the version signature of
// every pinned module reachable from its packages — its type environment's
// complete version surface (standard library rides the scope's toolchain).
// A pinned module whose cone reaches any mutable-local node is unkeyable —
// part of its type environment carries no version signal, so its facts must
// derive fresh every pass and never enter any cache layer
// (REQ-closure-dynamic-state-memo, REQ-closure-mutable-local).
func pinnedBuckets(meta []closure.GraphPackage) (buckets map[string]string, unkeyable map[string]bool) {
	imports := make(map[string][]string, len(meta))
	pins := make(map[string]string, len(meta))
	local := make(map[string]bool, len(meta))
	for _, node := range meta {
		imports[node.ImportPath] = node.Imports
		if node.Class == closure.PinnedPackage {
			pins[node.ImportPath] = node.Pin
		}
		if node.Class == closure.MutableLocalPackage {
			local[node.ImportPath] = true
		}
	}
	reachable := func(from string) (pinSet map[string]bool, localReached bool) {
		pinSet = map[string]bool{}
		seen := map[string]bool{}
		var walk func(string)
		walk = func(listing string) {
			if seen[listing] {
				return
			}
			seen[listing] = true
			if pin := pins[listing]; pin != "" {
				pinSet[pin] = true
			}
			if local[listing] {
				localReached = true
			}
			for _, imported := range imports[listing] {
				walk(imported)
			}
		}
		walk(from)
		return pinSet, localReached
	}
	coneByModule := map[string]map[string]bool{}
	unkeyable = map[string]bool{}
	for _, node := range meta {
		if node.Class != closure.PinnedPackage {
			continue
		}
		pinSet, localReached := reachable(node.ImportPath)
		if localReached {
			unkeyable[node.Pin] = true
			continue
		}
		if coneByModule[node.Pin] == nil {
			coneByModule[node.Pin] = map[string]bool{}
		}
		for pin := range pinSet {
			coneByModule[node.Pin][pin] = true
		}
	}
	buckets = make(map[string]string, len(coneByModule))
	for pin, cone := range coneByModule {
		if unkeyable[pin] {
			continue
		}
		keys := make([]string, 0, len(cone))
		for k := range cone {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sum := sha256.Sum256([]byte(fmt.Sprintf("%q", keys)))
		buckets[pin] = pin + "|" + hex.EncodeToString(sum[:8])
	}
	return buckets, unkeyable
}
