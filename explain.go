package gofresh

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/internal/processenv"
	"golang.org/x/tools/go/packages"
)

// explainMu serializes explain re-derivations - the observation hooks
// are package scope, and explain traffic is interactive diagnosis,
// never a throughput path.
var explainMu sync.Mutex

// The explain surface turns a refusal into its derivation chain
// (docs/specs/explain.md). Chains are re-derived on demand against
// the view's own package scope; the normal analysis path constructs
// none (REQ-explain-passive). Link text speaks the closure contract's
// clause vocabulary, never implementation identifiers
// (REQ-explain-vocabulary).

// ChainLink is one step of a refusal's derivation.
type ChainLink struct {
	// Kind is the link's role: "culprit", "store", "edge", or
	// "refusal".
	Kind string
	// Package and Symbol name the owning package and the variable or
	// function the link concerns.
	Package string
	Symbol  string
	// Callee names an edge's target function as package.Function;
	// empty on non-edge links.
	Callee string
	// Clause names the deciding clause family: the mark kind on
	// culprit links (mutation or escape), the refusing family on
	// refusal links; empty otherwise.
	Clause string
	// Pos is the deciding site as file:line; empty when the link is
	// a composition fact with no single site.
	Pos string
}

// Chain is a culprit's bounded derivation (REQ-explain-bounded).
type Chain struct {
	// Arm is the culprit class: "mutation", "escape", or
	// "environment-audit".
	Arm string
	// Links runs from the culprit toward the deepest deciding site;
	// the innermost refusing expression is never omitted.
	Links []ChainLink
	// Omitted counts links dropped by the bound.
	Omitted int
}

// chainLinkCap bounds a chain's link count; the remainder is counted,
// never silent (REQ-explain-bounded).
const chainLinkCap = 24

// explainHookSet carries the observation callbacks one explain
// re-derivation arms. Every callback receives the package whose
// analysis fired it: positions resolve against that package's file
// set, and refusal callbacks match on its path, so a concurrent
// analysis elsewhere can never inject a wrong-file link.
type explainHookSet struct {
	// site observes a mutation or escape mark for a watched variable
	// key.
	site func(p *packages.Package, kind, key string, pos token.Pos)
	// store observes an environment-audit registration mark for a
	// watched variable key.
	store func(p *packages.Package, key string, pos token.Pos)
	// deferral observes a deferred-use recording for a watched variable
	// key: kind 'p' is a call-argument parameter deferral, 'm' a method
	// use, 'f' a field-position use; resolvent is the persisted mark key
	// the composition resolves.
	deferral func(p *packages.Package, kind byte, key, resolvent string, at token.Pos)
	// refusal observes the judgment's refusing expressions, innermost
	// first.
	refusal func(p *packages.Package, fn string, e ast.Expr, clause string)
}

// explainHooks is nil outside an explain re-derivation
// (REQ-explain-passive). It is an atomic pointer because normal
// analysis may run concurrently on other views while an explain is
// armed: readers load one consistent set, the armed callbacks guard
// their own state, and collected links are read only after the hooks
// disarm.
var explainHooks atomic.Pointer[explainHookSet]

// ExplainDynamicState derives the refusal chain for a dynamic-state
// culprit a verdict's reason names: the variable varName declared in
// package pkgPath (REQ-explain-chain). The derivation re-loads the
// view's own package scope - test variants included, the same scope
// verdicts derive over - and re-runs the analysis with observation
// hooks armed; a variable that is not a culprit yields an empty chain
// and no error.
func (v *View) ExplainDynamicState(ctx context.Context, pkgPath, varName string) (Chain, error) {
	v.mu.RLock()
	dir := v.moduleDir
	env := v.engine.env
	flags := v.engine.buildFlags
	patterns := append([]string(nil), v.packages...)
	v.mu.RUnlock()
	if len(patterns) == 0 {
		patterns = []string{pkgPath}
	}
	packageEnv, err := processenv.ForGoPackages(env)
	if err != nil {
		return Chain{}, fmt.Errorf("explain: environment: %w", err)
	}
	cfg := &packages.Config{
		Context:    ctx,
		Mode:       packages.LoadAllSyntax | packages.NeedModule,
		Dir:        dir,
		BuildFlags: flags,
		Tests:      true,
		Env:        packageEnv,
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return Chain{}, fmt.Errorf("explain: load: %w", err)
	}
	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			return Chain{}, fmt.Errorf("explain: load %s: %v", p.PkgPath, p.Errors[0])
		}
	}
	varKey := pkgPath + "." + varName
	notice, err := closure.ToolchainSelectionNoticeResolvedContext(ctx, v.engine.dir, v.engine.env, v.engine.buildFlags, nil)
	if err != nil {
		return Chain{}, fmt.Errorf("explain: toolchain selection: %w", err)
	}
	return explainCulprit(notice == "", pkgs, pkgPath, varKey, varName, v.engine.singleSubjectExecution)
}

// explainCulprit re-derives every loaded package's fact with mark
// hooks armed - a culprit's deciding site may sit in an importing
// package or a test variant - and assembles the chain, following
// environment-audit dependency edges to the first locally refused
// proof.
func explainCulprit(audited bool, roots []*packages.Package, pkgPath, varKey, varName string, singleSubject bool) (Chain, error) {
	explainMu.Lock()
	defer explainMu.Unlock()

	variants := map[string][]*packages.Package{}
	var order []*packages.Package
	packages.Visit(roots, func(p *packages.Package) bool {
		// The fact universe mirrors the verdict's composition:
		// module-owned packages only - standard-library nodes are
		// inert absence there, and absence fails closed - and the
		// toolchain-generated test-main scaffolding (a main package
		// at the generated .test path) contributes nothing.
		if p.Module == nil || (p.Name == "main" && strings.HasSuffix(p.PkgPath, ".test")) {
			return true
		}
		variants[p.PkgPath] = append(variants[p.PkgPath], p)
		order = append(order, p)
		return true
	}, nil)

	var mu sync.Mutex
	var sites []ChainLink
	var stores []ChainLink
	type deferralObservation struct {
		kind      byte
		resolvent string
		link      ChainLink
	}
	var deferrals []deferralObservation
	pos := func(p *packages.Package, at token.Pos) string {
		if !at.IsValid() {
			return ""
		}
		position := p.Fset.Position(at)
		return fmt.Sprintf("%s:%d", position.Filename, position.Line)
	}
	explainHooks.Store(&explainHookSet{
		site: func(p *packages.Package, kind, key string, at token.Pos) {
			if key != varKey {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			sites = append(sites, ChainLink{Kind: "culprit", Package: p.PkgPath, Symbol: varName, Clause: kind, Pos: pos(p, at)})
		},
		store: func(p *packages.Package, key string, at token.Pos) {
			if key != varKey {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			stores = append(stores, ChainLink{Kind: "store", Package: p.PkgPath, Symbol: varName, Pos: pos(p, at)})
		},
		deferral: func(p *packages.Package, kind byte, key, resolvent string, at token.Pos) {
			if key != varKey {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			deferrals = append(deferrals, deferralObservation{kind: kind, resolvent: resolvent, link: ChainLink{Kind: "culprit", Package: p.PkgPath, Symbol: varName, Pos: pos(p, at)}})
		},
	})
	// Every compilation variant's fact joins the union, exactly as
	// the verdict's composition appends and unions per path.
	facts := map[string][]dynamicStateFact{}
	for _, p := range order {
		facts[p.PkgPath] = append(facts[p.PkgPath], dynamicStateFactOf(audited, p, singleSubject))
	}
	explainHooks.Store(nil)
	mu.Lock()
	collectedSites := append([]ChainLink(nil), sites...)
	collectedStores := append([]ChainLink(nil), stores...)
	collectedDeferrals := append([]deferralObservation(nil), deferrals...)
	mu.Unlock()

	// The verdict's composed proof state gates chains exactly as it
	// gated the refusal: an object-closed variable's escapes never
	// refused, so escape-kind sites and deferrals contribute no links
	// for it - a Valid verdict has no chain (REQ-explain-chain).
	resolution := newDeferralResolution(facts, nil)
	if !resolution.notOpaque[varKey] {
		kept := collectedSites[:0]
		for _, s := range collectedSites {
			if s.Clause == "mutation" {
				kept = append(kept, s)
			}
		}
		collectedSites = kept
	}
	// A deferred use whose resolvent no fact proves is the composition's
	// escape or mutation - the deciding site is the deferring use, the
	// clause names the unproven resolvent. Resolution runs over the same
	// composed proof state the verdict used, and direct sites and
	// unresolved deferrals combine into one chain whose arm follows the
	// verdict's ranking - mutation evidence anywhere names the chain
	// mutation, exactly as the verdict reason would say "is mutated"
	// (REQ-explain-chain).
	var mutationLinks, escapeLinks []ChainLink
	for _, s := range collectedSites {
		if s.Clause == "mutation" {
			mutationLinks = append(mutationLinks, s)
		} else {
			escapeLinks = append(escapeLinks, s)
		}
	}
	for _, obs := range collectedDeferrals {
		link := obs.link
		switch obs.kind {
		case 'p':
			if resolution.paramLeakFree[obs.resolvent] || !resolution.notOpaque[varKey] {
				continue
			}
			link.Clause = "a deferred argument's parameter unproven"
			link.Callee = paramKeyDisplay(obs.resolvent)
			escapeLinks = append(escapeLinks, link)
		case 'm':
			if resolution.readOnly[obs.resolvent] {
				continue
			}
			link.Clause = "a deferred method use unproven"
			link.Callee = strings.ReplaceAll(obs.resolvent, "\x00", ".")
			mutationLinks = append(mutationLinks, link)
		case 'q':
			// An init-region argument deferral resolves against either
			// parameter grade - writes through the parameter are init
			// flow's own exempt shape (REQ-explain-chain).
			if resolution.paramLeakFree[obs.resolvent] || resolution.paramRetentionFree[obs.resolvent] || !resolution.notOpaque[varKey] {
				continue
			}
			link.Clause = "an init-flow argument's parameter unproven"
			link.Callee = paramKeyDisplay(obs.resolvent)
			escapeLinks = append(escapeLinks, link)
		case 'n':
			// An init-region receiver deferral resolves against the
			// retention grade alone - read-only never substitutes, a
			// reading method can still retain its receiver
			// (REQ-explain-chain).
			if resolution.receiverRetention[obs.resolvent] || !resolution.notOpaque[varKey] {
				continue
			}
			link.Clause = "an init-flow receiver's method unproven"
			link.Callee = strings.ReplaceAll(obs.resolvent, "\x00", ".")
			escapeLinks = append(escapeLinks, link)
		case 'f':
			field, idx, ok := strings.Cut(obs.resolvent, "\x00")
			if !ok || !resolution.notOpaque[varKey] {
				continue
			}
			proves, failParam := resolution.fieldPopulationProves(varKey, field, idx)
			if proves {
				continue
			}
			link.Clause = "the registered population refused the field position"
			link.Callee = field + " parameter " + idx
			if failParam != "" {
				link.Callee += " (registrant " + paramKeyDisplay(failParam) + " unproven)"
			}
			escapeLinks = append(escapeLinks, link)
		case 'e':
			ownerKey, idx, ok := strings.Cut(obs.resolvent, "\x01")
			if !ok || !resolution.notOpaque[varKey] {
				continue
			}
			proves, failParam := resolution.fieldPopulationProves(ownerKey, elemPositionField, idx)
			if proves {
				continue
			}
			link.Clause = "the element population refused the position"
			link.Callee = ownerKey + " element parameter " + idx
			if failParam != "" {
				link.Callee += " (registrant " + paramKeyDisplay(failParam) + " unproven)"
			}
			escapeLinks = append(escapeLinks, link)
		}
	}
	if len(mutationLinks) > 0 || len(escapeLinks) > 0 {
		arm := "escape"
		if len(mutationLinks) > 0 {
			arm = "mutation"
		}
		deduped := dedupeLinks(append(mutationLinks, escapeLinks...))
		return boundChain(Chain{Arm: arm, Links: deduped}, len(deduped)-1), nil
	}

	// The environment-audit marks are unioned across every fact -
	// registrations land from any package (own or foreign), exactly
	// as composition unions them.
	carrying := false
	for _, fl := range facts {
		for _, f := range fl {
			for _, key := range f.EnvCarrying {
				if key == varKey {
					carrying = true
				}
			}
		}
	}
	edges, refusedFn, refusedPath := envAuditTrail(variants, facts, varKey, varName)
	// A fired store hook always rides an environment-carrying mark -
	// the same arm sets both - so the carrying union subsumes the
	// stores here.
	if !carrying && len(edges) == 0 {
		return Chain{}, nil
	}
	links := dedupeLinks(append(collectedStores, edges...))
	protect := len(links)
	if refusedFn != "" && refusedPath != "" {
		var refusals []ChainLink
		explainHooks.Store(&explainHookSet{
			refusal: func(p *packages.Package, fn string, e ast.Expr, clause string) {
				if fn != refusedFn || p.PkgPath != refusedPath {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				refusals = append(refusals, ChainLink{Kind: "refusal", Package: p.PkgPath, Symbol: fn, Clause: clause, Pos: pos(p, e.Pos())})
			},
		})
		// Every compilation variant of the refused path re-derives:
		// the refused function may exist only in the test variant, and
		// a production function judged in both variants dedupes to one
		// link set.
		for _, vp := range variants[refusedPath] {
			dynamicStateFactOf(audited, vp, singleSubject)
		}
		explainHooks.Store(nil)
		mu.Lock()
		collected := dedupeLinks(append([]ChainLink(nil), refusals...))
		mu.Unlock()
		// Innermost first: the first refusal is the deepest deciding
		// site and survives the bound (REQ-explain-bounded).
		links = append(links, collected...)
	}
	if protect >= len(links) {
		protect = len(links) - 1
	}
	return boundChain(Chain{Arm: "environment-audit", Links: links}, protect), nil
}

// envAuditTrail resolves the environment-audit least fixed point over
// the loaded facts and walks the unresolved dependency edges from the
// culprit's registrations to the first function whose proof failed
// locally. A registration whose every callee resolves contributes no
// edges: a proven constructor is no refusal (REQ-explain-chain).
func envAuditTrail(variants map[string][]*packages.Package, facts map[string][]dynamicStateFact, varKey, varName string) ([]ChainLink, string, string) {
	ea := resolveEnvAudit(facts, nil)
	// render splits an audit key: a function key yields (pkg, name); a
	// parameter key yields (pkg, name, index) with the edge label
	// carrying the parameter context - never a raw NUL
	// (REQ-explain-chain).
	renderEdge := func(key string) (string, string) {
		parts := strings.Split(key, "\x00")
		switch len(parts) {
		case 2:
			return parts[0], parts[1]
		case 3:
			return parts[0], parts[1] + " (parameter " + parts[2] + ")"
		}
		return key, key
	}
	renderSite := func(key string) (string, string) {
		parts := strings.Split(key, "\x00")
		if len(parts) >= 2 {
			return parts[0], parts[1]
		}
		return key, key
	}
	sortedKeys := func(m map[string]bool) []string {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return keys
	}

	// Registrations naming the culprit land from any package's fact;
	// the edge names the registering package.
	type rootedCallee struct{ from, callee string }
	var callees []rootedCallee
	for fromPath, fl := range facts {
		for _, f := range fl {
			for _, use := range f.EnvCallUses {
				key, callee, ok := strings.Cut(use, "\x01")
				if ok && key == varKey && !ea.resolved[callee] {
					callees = append(callees, rootedCallee{fromPath, callee})
				}
			}
		}
	}
	sort.Slice(callees, func(i, j int) bool {
		if callees[i].from != callees[j].from {
			return callees[i].from < callees[j].from
		}
		return callees[i].callee < callees[j].callee
	})

	var edges []ChainLink
	visited := map[string]bool{}
	// Depth-first along unresolved conditions of BOTH kinds - a return
	// claim's function and insertion edges, an insertion claim's own
	// edges - the first key with no local declaration is the local
	// refusal; a cycle of declared claims refuses at the fixed point
	// with no single refusing site, leaving an edges-only chain.
	var walk func(key string) (string, string)
	walk = func(key string) (string, string) {
		if visited[key] {
			return "", ""
		}
		visited[key] = true
		pkgPath, name := renderSite(key)
		insertionKey := strings.Count(key, "\x00") == 2
		declaredHere := ea.declared[key]
		var depSets []map[string]bool
		if insertionKey {
			declaredHere = ea.insDeclared[key]
			depSets = []map[string]bool{ea.insDeps[key]}
		} else {
			depSets = []map[string]bool{ea.retDeps[key], ea.retInsDeps[key]}
		}
		if !declaredHere {
			if len(variants[pkgPath]) > 0 {
				return name, pkgPath
			}
			return "", ""
		}
		for _, set := range depSets {
			for _, dep := range sortedKeys(set) {
				if ea.depResolved(dep) {
					continue
				}
				depPkg, depName := renderEdge(dep)
				_, symbol := renderEdge(key)
				edges = append(edges, ChainLink{Kind: "edge", Package: pkgPath, Symbol: symbol, Callee: depPkg + "." + depName})
				if fn, p := walk(dep); fn != "" {
					return fn, p
				}
			}
		}
		return "", ""
	}
	for _, rc := range callees {
		calleePkg, calleeName := renderEdge(rc.callee)
		edges = append(edges, ChainLink{Kind: "edge", Package: rc.from, Symbol: varName, Callee: calleePkg + "." + calleeName})
		if fn, p := walk(rc.callee); fn != "" {
			return edges, fn, p
		}
	}
	return edges, "", ""
}

// dedupeLinks removes byte-identical links - plain and test-variant
// compilations of one package fire the same production-file marks.
func dedupeLinks(links []ChainLink) []ChainLink {
	seen := map[ChainLink]bool{}
	out := links[:0]
	for _, l := range links {
		if seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	return out
}

// boundChain applies the link cap, always keeping the protected link
// - the innermost refusing expression or deepest deciding site
// (REQ-explain-bounded).
func boundChain(c Chain, protect int) Chain {
	if len(c.Links) <= chainLinkCap {
		return c
	}
	if protect < 0 || protect >= len(c.Links) {
		protect = len(c.Links) - 1
	}
	kept := append([]ChainLink(nil), c.Links[:chainLinkCap-1]...)
	if protect >= chainLinkCap-1 {
		kept = append(kept, c.Links[protect])
	} else {
		kept = append(kept, c.Links[len(c.Links)-1])
	}
	c.Omitted = len(c.Links) - len(kept)
	c.Links = kept
	return c
}

// paramKeyDisplay renders a persisted parameter key - package path,
// function name, zero-based index NUL-joined - in source vocabulary.
func paramKeyDisplay(paramKey string) string {
	parts := strings.SplitN(paramKey, "\x00", 3)
	if len(parts) != 3 {
		return strings.ReplaceAll(paramKey, "\x00", ".")
	}
	return parts[0] + "." + parts[1] + " parameter " + parts[2]
}
