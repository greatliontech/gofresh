package gofresh

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/dynstate"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

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

// ExplainDynamicState derives the refusal chain for a dynamic-state
// culprit a verdict's reason names: the variable varName declared in
// package pkgPath (REQ-explain-chain). The derivation re-loads the
// view's own package scope - test variants included, the same scope
// verdicts derive over - and re-runs the analysis with observation
// hooks armed; a variable that is not a culprit yields an empty chain
// and no error.
func (v *Snapshot) ExplainDynamicState(ctx context.Context, pkgPath, varName string) (Chain, error) {
	refreshTraceFromEnv()
	if v == nil || v.session == nil {
		return Chain{}, errors.New("gofresh: uninitialized snapshot")
	}
	v.mu.RLock()
	dir := v.moduleDir
	flags := v.session.buildFlags
	patterns := append([]string(nil), v.packages...)
	var snapshot *gotool.EnvSnapshot
	if v.facts != nil {
		snapshot = v.facts.snapshot
	}
	v.mu.RUnlock()
	if len(patterns) == 0 {
		patterns = []string{pkgPath}
	}
	loadDir := dir
	if loadDir == "" {
		loadDir = v.session.dir
	}
	loadReader := gotool.NewEnvReader(v.session.runner, loadDir, v.session.env)
	if snapshot != nil {
		loadReader = gotool.PrimedEnvReader(v.session.runner, loadDir, v.session.env, snapshot)
	}
	load, err := closure.LoadViewGraph(ctx, loadReader, flags, patterns...)
	if err != nil {
		return Chain{}, fmt.Errorf("explain: load: %w", err)
	}
	pkgs := load.Packages()
	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			return Chain{}, fmt.Errorf("explain: load %s: %v", p.PkgPath, p.Errors[0])
		}
	}
	varKey := pkgPath + "." + varName
	reader := loadReader
	if v.session.dir != "" && v.session.dir != loadDir {
		reader = v.session.newPassReader()
		if snapshot != nil {
			reader = gotool.PrimedEnvReader(v.session.runner, v.session.dir, v.session.env, snapshot)
		}
	}
	sel, err := resolveToolchainSelection(ctx, reader, flags...)
	if err != nil {
		return Chain{}, fmt.Errorf("explain: toolchain selection: %w", err)
	}
	modCache, err := reader.Value(ctx, "GOMODCACHE")
	if err != nil {
		return Chain{}, fmt.Errorf("explain: env: %w", err)
	}
	execModel := v.effectiveExecutionModel()
	return explainCulpritCtx(ctx, sel.SelectionNotice == "", pkgs, pkgPath, varKey, varName, execModel.singleSubject(), execModel.packageProcess(), modCache)
}

func explainCulprit(audited bool, roots []*packages.Package, pkgPath, varKey, varName string, singleSubject, packageProcess bool, modCache string) (Chain, error) {
	return explainCulpritCtx(nil, audited, roots, pkgPath, varKey, varName, singleSubject, packageProcess, modCache)
}

// explainCulpritCtx re-derives every loaded package's fact with mark
// hooks armed - a culprit's deciding site may sit in an importing
// package or a test variant - and assembles the chain, following
// environment-audit dependency edges to the first locally refused
// proof.
func explainCulpritCtx(ctx context.Context, audited bool, roots []*packages.Package, pkgPath, varKey, varName string, singleSubject, packageProcess bool, modCache string) (Chain, error) {
	variants := map[string][]*packages.Package{}
	var order []*packages.Package
	packages.Visit(roots, func(p *packages.Package) bool {
		if p.Module == nil || gotool.IsGeneratedTestMainPackage(p) {
			return true
		}
		variants[p.PkgPath] = append(variants[p.PkgPath], p)
		order = append(order, p)
		return true
	}, nil)

	type siteObservation struct {
		key         string
		enclosingFn syntaxutil.FuncKey
		literal     bool
		link        ChainLink
	}
	type storeObservation struct {
		key  string
		link ChainLink
	}
	type deferralObservation struct {
		key       string
		kind      byte
		resolvent syntaxutil.DeferralResolvent
		link      ChainLink
	}
	type exportedSeamObservation struct {
		key  string
		fn   syntaxutil.FuncKey
		link ChainLink
	}
	var allSites []siteObservation
	var allExportedSeams []exportedSeamObservation
	var allStores []storeObservation
	var allDeferrals []deferralObservation
	pos := func(p *packages.Package, at token.Pos) string {
		if !at.IsValid() {
			return ""
		}
		position := p.Fset.Position(at)
		return fmt.Sprintf("%s:%d", position.Filename, position.Line)
	}
	bareSym := func(key string) string {
		return bareSymbol(key, varName)
	}
	hooks := &syntaxutil.ExplainHookSet{
		Site: func(p *packages.Package, kind, key string, fn syntaxutil.FuncKey, literal bool, at token.Pos) {
			allSites = append(allSites, siteObservation{
				key:         key,
				enclosingFn: fn,
				literal:     literal,
				link:        ChainLink{Kind: "culprit", Package: p.PkgPath, Symbol: bareSym(key), Clause: kind, Pos: pos(p, at)},
			})
		},
		ExportedSeamSite: func(p *packages.Package, fn syntaxutil.FuncKey, key string, at token.Pos) {
			allExportedSeams = append(allExportedSeams, exportedSeamObservation{
				key:  key,
				fn:   fn,
				link: ChainLink{Kind: "culprit", Package: p.PkgPath, Symbol: bareSym(key), Clause: "mutation", Pos: pos(p, at)},
			})
		},
		Store: func(p *packages.Package, key string, at token.Pos) {
			allStores = append(allStores, storeObservation{key: key, link: ChainLink{Kind: "store", Package: p.PkgPath, Symbol: bareSym(key), Pos: pos(p, at)}})
		},
		Deferral: func(p *packages.Package, kind byte, key string, resolvent syntaxutil.DeferralResolvent, at token.Pos) {
			allDeferrals = append(allDeferrals, deferralObservation{key: key, kind: kind, resolvent: resolvent, link: ChainLink{Kind: "culprit", Package: p.PkgPath, Symbol: bareSym(key), Pos: pos(p, at)}})
		},
	}
	facts := map[string][]dynstate.Fact{}
	var meta []dynstate.GraphPackage
	seenMetaID := map[string]bool{}
	for _, p := range order {
		facts[p.PkgPath] = append(facts[p.PkgPath], dynstate.FactOfWithHooksCtx(ctx, audited, p, singleSubject, hooks))
		nodeID := gotool.LoadedListingID(p)
		if !seenMetaID[nodeID] {
			seenMetaID[nodeID] = true
			class, pin := closure.ClassifyLoadedPackage(p, modCache)
			var impPaths []string
			if len(p.Imports) > 0 {
				impPaths = make([]string, 0, len(p.Imports))
				for impPath, impPkg := range p.Imports {
					if impPkg != nil {
						impPaths = append(impPaths, gotool.LoadedListingID(impPkg))
					} else {
						impPaths = append(impPaths, impPath)
					}
				}
				sort.Strings(impPaths)
			}
			meta = append(meta, dynstate.GraphPackage{
				ImportPath: nodeID,
				PkgPath:    p.PkgPath,
				ForTest:    p.ForTest,
				Imports:    impPaths,
				Class:      class,
				Pin:        pin,
			})
		}
	}
	cone := dynstate.AnalyzeCone(dynstate.ConeQuery{
		Ctx:            ctx,
		Meta:           meta,
		Facts:          facts,
		SingleSubject:  singleSubject,
		PackageProcess: packageProcess,
	})
	if cone.NonVouchDischarged[varKey] {
		return Chain{}, nil
	}
	resolution := cone.Deferral
	blockedSeams := cone.BlockedSeams
	for _, obs := range allExportedSeams {
		if blockedSeams[obs.key][obs.fn] {
			allSites = append(allSites, siteObservation{key: obs.key, link: obs.link})
		}
	}

	refRegions := resolution.RefRegions
	initOnlyFn := resolution.InitOnlyFn
	isInitOnlyPlain := func(fn syntaxutil.FuncKey) bool {
		return !fn.IsZero() && refRegions[fn] != nil && initOnlyFn[fn]
	}
	linkAdj := cone.LinkAdj
	linkedKeys := map[string]bool{varKey: true}
	for changed := len(linkAdj[varKey]) > 0; changed; {
		changed = false
		for a := range linkedKeys {
			for b := range linkAdj[a] {
				if !linkedKeys[b] {
					linkedKeys[b] = true
					changed = true
				}
			}
		}
	}

	var collectedSites []ChainLink
	for _, obs := range allSites {
		if !linkedKeys[obs.key] {
			continue
		}
		if obs.link.Clause == "mutation" && !obs.literal && isInitOnlyPlain(obs.enclosingFn) {
			continue
		}
		if obs.link.Clause != "mutation" && !resolution.NotOpaque[varKey] {
			continue
		}
		collectedSites = append(collectedSites, obs.link)
	}
	var collectedStores []ChainLink
	for _, obs := range allStores {
		if linkedKeys[obs.key] {
			collectedStores = append(collectedStores, obs.link)
		}
	}
	var collectedDeferrals []deferralObservation
	for _, obs := range allDeferrals {
		if linkedKeys[obs.key] {
			collectedDeferrals = append(collectedDeferrals, obs)
		}
	}
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
			if resolution.ParamLeakFree[obs.resolvent.Param] || !resolution.NotOpaque[varKey] {
				continue
			}
			if !obs.resolvent.Literal && isInitOnlyPlain(obs.resolvent.EnclosingFn) && resolution.ParamRetentionFree[obs.resolvent.Param] {
				continue
			}
			link.Clause = "a deferred argument's parameter unproven"
			link.Callee = obs.resolvent.Param.Display()
			escapeLinks = append(escapeLinks, link)
		case 'm':
			if resolution.ReadOnly[obs.resolvent.Method] {
				continue
			}
			if !obs.resolvent.Literal && isInitOnlyPlain(obs.resolvent.EnclosingFn) && resolution.ReceiverRetention[obs.resolvent.Method] {
				continue
			}
			link.Clause = "a deferred method use unproven"
			link.Callee = obs.resolvent.Method.Pkg + "." + obs.resolvent.Method.Name
			mutationLinks = append(mutationLinks, link)
		case 'q':
			if resolution.ParamLeakFree[obs.resolvent.Param] || resolution.ParamRetentionFree[obs.resolvent.Param] || !resolution.NotOpaque[varKey] {
				continue
			}
			link.Clause = "an init-flow argument's parameter unproven"
			link.Callee = obs.resolvent.Param.Display()
			escapeLinks = append(escapeLinks, link)
		case 'n':
			if resolution.ReceiverRetention[obs.resolvent.Method] || !resolution.NotOpaque[varKey] {
				continue
			}
			link.Clause = "an init-flow receiver's method unproven"
			link.Callee = obs.resolvent.Method.Pkg + "." + obs.resolvent.Method.Name
			escapeLinks = append(escapeLinks, link)
		case 'f':
			if !obs.resolvent.FieldPos.Valid(0) || !resolution.NotOpaque[varKey] {
				continue
			}
			proves, failParam := resolution.FieldPopulationProves(obs.key, obs.resolvent.FieldPos.Field, obs.resolvent.FieldPos.Index)
			if proves {
				continue
			}
			link.Clause = "the registered population refused the field position"
			link.Callee = obs.resolvent.FieldPos.Field + " parameter " + strconv.Itoa(obs.resolvent.FieldPos.Index)
			if failParam != (syntaxutil.ParamKey{}) {
				link.Callee += " (registrant " + failParam.Display() + " unproven)"
			}
			escapeLinks = append(escapeLinks, link)
		case 'e':
			if !obs.resolvent.ElemUse.Valid() || !resolution.NotOpaque[varKey] {
				continue
			}
			proves, failParam := resolution.FieldPopulationProves(obs.resolvent.ElemUse.Owner, syntaxutil.ElemPositionField, obs.resolvent.ElemUse.Index)
			if proves {
				continue
			}
			link.Clause = "the element population refused the position"
			link.Callee = obs.resolvent.ElemUse.Owner + " element parameter " + strconv.Itoa(obs.resolvent.ElemUse.Index)
			if failParam != (syntaxutil.ParamKey{}) {
				link.Callee += " (registrant " + failParam.Display() + " unproven)"
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

	carrying := false
	for _, fl := range facts {
		for _, f := range fl {
			for _, key := range f.EnvCarrying {
				if linkedKeys[key] {
					carrying = true
				}
			}
		}
	}
	edges, refusedFn, refusedPath := envAuditTrailWith(cone.EnvAudit, variants, facts, linkedKeys, varName)
	if !carrying && len(edges) == 0 {
		return Chain{}, nil
	}
	links := dedupeLinks(append(collectedStores, edges...))
	protect := len(links)
	if refusedFn != "" && refusedPath != "" {
		var refusals []ChainLink
		refusalHooks := &syntaxutil.ExplainHookSet{
			Refusal: func(p *packages.Package, fn string, e ast.Expr, clause string) {
				if fn != refusedFn || p.PkgPath != refusedPath {
					return
				}
				refusals = append(refusals, ChainLink{Kind: "refusal", Package: p.PkgPath, Symbol: fn, Clause: clause, Pos: pos(p, e.Pos())})
			},
		}
		for _, vp := range variants[refusedPath] {
			dynstate.FactOfWithHooksCtx(ctx, audited, vp, singleSubject, refusalHooks)
		}
		links = append(links, dedupeLinks(refusals)...)
	}
	if protect >= len(links) {
		protect = len(links) - 1
	}
	return boundChain(Chain{Arm: "environment-audit", Links: links}, protect), nil
}

func envAuditTrail(variants map[string][]*packages.Package, facts map[string][]dynstate.Fact, linkedKeys map[string]bool, varName string) ([]ChainLink, string, string) {
	return envAuditTrailWith(dynstate.ResolveEnvAudit(facts, nil), variants, facts, linkedKeys, varName)
}

func envAuditTrailWith(ea *dynstate.EnvAuditResolution, variants map[string][]*packages.Package, facts map[string][]dynstate.Fact, linkedKeys map[string]bool, varName string) ([]ChainLink, string, string) {
	renderEdge := func(key syntaxutil.EnvAuditTarget) (string, string) {
		if key.IsParam() {
			return key.Func.Pkg, key.Func.Name + " (parameter " + strconv.Itoa(key.ParamIndex) + ")"
		}
		return key.Func.Pkg, key.Func.Name
	}
	renderSite := func(key syntaxutil.EnvAuditTarget) (string, string) {
		return key.Func.Pkg, key.Func.Name
	}
	sortedFuncs := func(m map[syntaxutil.FuncKey]bool) []syntaxutil.EnvAuditTarget {
		keys := make([]syntaxutil.FuncKey, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, func(a, b syntaxutil.FuncKey) int { return a.Compare(b) })
		out := make([]syntaxutil.EnvAuditTarget, len(keys))
		for i, k := range keys {
			out[i] = syntaxutil.FuncAuditTarget(k)
		}
		return out
	}
	sortedTargets := func(m map[syntaxutil.EnvAuditTarget]bool) []syntaxutil.EnvAuditTarget {
		keys := make([]syntaxutil.EnvAuditTarget, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, func(a, b syntaxutil.EnvAuditTarget) int { return a.Compare(b) })
		return keys
	}
	sortedParams := func(m map[syntaxutil.ParamKey]bool) []syntaxutil.ParamKey {
		keys := make([]syntaxutil.ParamKey, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, syntaxutil.ParamKey.Compare)
		return keys
	}
	sortedRawFuncs := func(m map[syntaxutil.FuncKey]bool) []syntaxutil.FuncKey {
		keys := make([]syntaxutil.FuncKey, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, syntaxutil.FuncKey.Compare)
		return keys
	}
	formatParamEdge := func(pk syntaxutil.ParamKey) string {
		return pk.Func.Pkg + "." + pk.Func.Name + " (parameter " + strconv.Itoa(pk.Index) + ")"
	}
	formatMethodEdge := func(mk syntaxutil.FuncKey) string {
		return mk.Pkg + "." + mk.Name
	}

	type rootedCallee struct {
		from   string
		key    string
		callee syntaxutil.FuncKey
	}
	type rootedParam struct {
		from  string
		key   string
		param syntaxutil.ParamKey
	}
	type rootedMethod struct {
		from   string
		key    string
		method syntaxutil.FuncKey
	}
	var callees []rootedCallee
	var directParams []rootedParam
	var directMethods []rootedMethod
	for fromPath, fl := range facts {
		for _, f := range fl {
			for _, use := range f.EnvCallUses {
				if use.Valid() && linkedKeys[use.Key] && !ea.Resolved[use.Callee] {
					callees = append(callees, rootedCallee{from: fromPath, key: use.Key, callee: use.Callee})
				}
			}
			for _, use := range f.EnvCallParamUses {
				if use.Valid() && linkedKeys[use.Key] && !ea.ParamLeakFree[use.Param] {
					directParams = append(directParams, rootedParam{from: fromPath, key: use.Key, param: use.Param})
				}
			}
			for _, use := range f.EnvCallMethodUses {
				if use.Valid() && linkedKeys[use.Key] && !ea.ReadOnly[use.Method] {
					directMethods = append(directMethods, rootedMethod{from: fromPath, key: use.Key, method: use.Method})
				}
			}
		}
	}
	sort.Slice(callees, func(i, j int) bool {
		if callees[i].from != callees[j].from {
			return callees[i].from < callees[j].from
		}
		if callees[i].key != callees[j].key {
			return callees[i].key < callees[j].key
		}
		return callees[i].callee.Compare(callees[j].callee) < 0
	})
	sort.Slice(directParams, func(i, j int) bool {
		if directParams[i].from != directParams[j].from {
			return directParams[i].from < directParams[j].from
		}
		if directParams[i].key != directParams[j].key {
			return directParams[i].key < directParams[j].key
		}
		return directParams[i].param.Compare(directParams[j].param) < 0
	})
	sort.Slice(directMethods, func(i, j int) bool {
		if directMethods[i].from != directMethods[j].from {
			return directMethods[i].from < directMethods[j].from
		}
		if directMethods[i].key != directMethods[j].key {
			return directMethods[i].key < directMethods[j].key
		}
		return directMethods[i].method.Compare(directMethods[j].method) < 0
	})

	var edges []ChainLink
	visited := map[syntaxutil.EnvAuditTarget]bool{}
	visitedParamConf := map[syntaxutil.ParamKey]bool{}
	visitedMethodConf := map[syntaxutil.FuncKey]bool{}
	var walkParamConfinement func(pk syntaxutil.ParamKey)
	var walkMethodConfinement func(mk syntaxutil.FuncKey)
	walkParamConfinement = func(pk syntaxutil.ParamKey) {
		if !pk.Valid() || visitedParamConf[pk] || ea.ParamLeakFree[pk] {
			return
		}
		visitedParamConf[pk] = true
		sym := pk.Func.Name + " (parameter " + strconv.Itoa(pk.Index) + ")"
		for _, dep := range sortedParams(ea.ParamDeps[pk]) {
			if ea.ParamLeakFree[dep] {
				continue
			}
			edges = append(edges, ChainLink{Kind: "edge", Package: pk.Func.Pkg, Symbol: sym, Callee: formatParamEdge(dep)})
			walkParamConfinement(dep)
		}
		for _, mk := range sortedRawFuncs(ea.ParamMethodDeps[pk]) {
			if ea.ReadOnly[mk] {
				continue
			}
			edges = append(edges, ChainLink{Kind: "edge", Package: pk.Func.Pkg, Symbol: sym, Callee: formatMethodEdge(mk)})
			walkMethodConfinement(mk)
		}
	}
	walkMethodConfinement = func(mk syntaxutil.FuncKey) {
		if !mk.Valid() || visitedMethodConf[mk] || ea.ReadOnly[mk] {
			return
		}
		visitedMethodConf[mk] = true
		for _, dep := range sortedRawFuncs(ea.MethodDeps[mk]) {
			if ea.ReadOnly[dep] {
				continue
			}
			edges = append(edges, ChainLink{Kind: "edge", Package: mk.Pkg, Symbol: mk.Name, Callee: formatMethodEdge(dep)})
			walkMethodConfinement(dep)
		}
		for _, pk := range sortedParams(ea.MethodParamDeps[mk]) {
			if ea.ParamLeakFree[pk] {
				continue
			}
			edges = append(edges, ChainLink{Kind: "edge", Package: mk.Pkg, Symbol: mk.Name, Callee: formatParamEdge(pk)})
			walkParamConfinement(pk)
		}
	}

	var walk func(key syntaxutil.EnvAuditTarget) (string, string)
	walk = func(key syntaxutil.EnvAuditTarget) (string, string) {
		if !key.Valid() || visited[key] {
			return "", ""
		}
		visited[key] = true
		pkgPath, name := renderSite(key)
		var declaredHere bool
		var depSets [][]syntaxutil.EnvAuditTarget
		if key.IsParam() {
			p := key.Param()
			declaredHere = ea.InsDeclared[p]
			depSets = [][]syntaxutil.EnvAuditTarget{sortedTargets(ea.InsDeps[p])}
		} else {
			declaredHere = ea.Declared[key.Func]
			depSets = [][]syntaxutil.EnvAuditTarget{sortedFuncs(ea.RetDeps[key.Func]), sortedTargets(ea.RetInsDeps[key.Func])}
		}
		if !declaredHere {
			if len(variants[pkgPath]) > 0 {
				return name, pkgPath
			}
			return "", ""
		}
		_, symbol := renderEdge(key)
		for _, set := range depSets {
			for _, dep := range set {
				if ea.DepResolved(dep) {
					continue
				}
				depPkg, depName := renderEdge(dep)
				edges = append(edges, ChainLink{Kind: "edge", Package: pkgPath, Symbol: symbol, Callee: depPkg + "." + depName})
				if fn, p := walk(dep); fn != "" {
					return fn, p
				}
			}
		}
		if key.IsParam() {
			p := key.Param()
			for _, pk := range sortedParams(ea.InsParamDeps[p]) {
				if ea.ParamLeakFree[pk] {
					continue
				}
				edges = append(edges, ChainLink{Kind: "edge", Package: pkgPath, Symbol: symbol, Callee: formatParamEdge(pk)})
				walkParamConfinement(pk)
			}
			for _, mk := range sortedRawFuncs(ea.InsMethodDeps[p]) {
				if ea.ReadOnly[mk] {
					continue
				}
				edges = append(edges, ChainLink{Kind: "edge", Package: pkgPath, Symbol: symbol, Callee: formatMethodEdge(mk)})
				walkMethodConfinement(mk)
			}
		} else {
			for _, pk := range sortedParams(ea.RetParamDeps[key.Func]) {
				if ea.ParamLeakFree[pk] {
					continue
				}
				edges = append(edges, ChainLink{Kind: "edge", Package: pkgPath, Symbol: symbol, Callee: formatParamEdge(pk)})
				walkParamConfinement(pk)
			}
			for _, mk := range sortedRawFuncs(ea.RetMethodDeps[key.Func]) {
				if ea.ReadOnly[mk] {
					continue
				}
				edges = append(edges, ChainLink{Kind: "edge", Package: pkgPath, Symbol: symbol, Callee: formatMethodEdge(mk)})
				walkMethodConfinement(mk)
			}
		}
		return "", ""
	}
	for _, rc := range callees {
		target := syntaxutil.FuncAuditTarget(rc.callee)
		calleePkg, calleeName := renderEdge(target)
		edges = append(edges, ChainLink{Kind: "edge", Package: rc.from, Symbol: bareSymbol(rc.key, varName), Callee: calleePkg + "." + calleeName})
		if fn, p := walk(target); fn != "" {
			return edges, fn, p
		}
	}
	for _, rp := range directParams {
		edges = append(edges, ChainLink{Kind: "edge", Package: rp.from, Symbol: bareSymbol(rp.key, varName), Callee: formatParamEdge(rp.param)})
		walkParamConfinement(rp.param)
	}
	for _, rm := range directMethods {
		edges = append(edges, ChainLink{Kind: "edge", Package: rm.from, Symbol: bareSymbol(rm.key, varName), Callee: formatMethodEdge(rm.method)})
		walkMethodConfinement(rm.method)
	}
	return edges, "", ""
}

func bareSymbol(key, fallback string) string {
	if i := strings.LastIndexByte(key, '.'); i >= 0 {
		return key[i+1:]
	}
	return fallback
}

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
