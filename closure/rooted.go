package closure

import (
	"context"
	"fmt"
	"go/types"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// rootedFunctionKey names one reachable function in the attributed
// mark-site spelling: "path\x00name" for a plain function,
// "path\x00Recv.Name" for a method (the method-fact spelling, pointer
// star and type parameters stripped). An anonymous function or an
// unnameable receiver yields no key — their marks are never attributed,
// so no site can reference them.
func rootedFunctionKey(fn *ssa.Function) string {
	if fn == nil || fn.Object() == nil || isUnnamedStructPromotedWrapper(fn) {
		return ""
	}
	name := functionSymbolName(fn)
	if obj, ok := fn.Object().(*types.Func); ok {
		if sig, ok := obj.Type().(*types.Signature); ok && sig.Recv() != nil {
			t := types.Unalias(sig.Recv().Type())
			if pointer, ok := t.(*types.Pointer); ok {
				t = types.Unalias(pointer.Elem())
			}
			named, ok := t.(*types.Named)
			if !ok || named.Obj() == nil {
				return ""
			}
			name = named.Obj().Name() + "." + name
		}
	}
	return funcPkgPath(fn) + "\x00" + name
}

// RootedFunctions is one subject's rooted-flow function inventory under
// the single-subject-process execution model: the named functions the
// subject's POST-INITIALIZATION execution can run — the subject flow
// and, where the subject runs through the harness, the user TestMain
// flow — as "path\x00name" keys over the attributed reachable set.
// Package initialization is deliberately excluded, on the model's own
// ground: with no prior subject in the process, the whole
// subject-owned process's state — initialization, init-spawned
// goroutines, and all — is a function of the hashed source, the priced
// inputs, and scheduling noise alone, so a site the
// post-initialization rooted flow cannot execute adds no channel the
// closure hash and the input pricing do not already cover
// (init-spawned goroutines' marks are unattributed and never
// discharge). Complete
// reports whether the inventory bounds the execution: an unrooted
// subject symbol or an open-world widening (a root able to receive
// unknown dynamic values) leaves Complete false, and an incomplete
// inventory grants nothing — fail-closed
// (REQ-closure-shared-dynamic-state-reachability).
type RootedFunctions struct {
	Fns      map[string]bool
	Complete bool
}

// ComputeRootedFunctions derives per-subject rooted-flow inventories
// from the same attributed RTA the observability proof rides — the
// masks are conservative over-approximations (address-taken functions
// of matching signature included), so a spurious member only withholds
// a discharge, never grants one. When the hasher's AnalysisScope arms
// Rooted(), completed package inventories persist under (scope.Rooted(),
// testBinaryClosureKey) and serve across passes without rebuilding SSA.
// ctx governs the analysis and must descend from the Hasher's own: the
// caller's analysis budget rides it (REQ-fresh-context), so a cut ends
// the pass with the context's error and memoizes no load failure or
// partial package derivation — the discharge then grants nothing,
// exactly as every other gap.
func (h *Hasher) ComputeRootedFunctions(ctx context.Context, subjects []Subject) (map[Subject]RootedFunctions, error) {
	h.resetCallScope()
	defer func() { h.contents = nil }()
	prevCtx := h.ctx
	h.ctx = ctx
	defer func() { h.ctx = prevCtx }()
	results := make(map[Subject]RootedFunctions, len(subjects))
	byPackage := map[string]*packageBatch{}
	var groups []*packageBatch
	seen := map[Subject]bool{}
	for _, subject := range subjects {
		if seen[subject] {
			continue
		}
		seen[subject] = true
		group := byPackage[subject.Package]
		if group == nil {
			group = &packageBatch{path: subject.Package}
			byPackage[subject.Package] = group
			groups = append(groups, group)
		}
		group.subjects = append(group.subjects, subject)
	}
	resolveGroupMemo := func(group *packageBatch) {
		if !group.rootedMemoChecked && ctx.Err() == nil {
			group.rootedMemoChecked = true
			group.closureHash, group.rootedMemo = h.rootedGroupMemo(group.path)
		}
	}
	currentIdx := 0
	bp := &batchPreparer{
		h: h,
		candidates: func() []string {
			var uncached []string
			for _, g := range groups[currentIdx:] {
				if ctx.Err() != nil {
					break
				}
				if _, ok := h.progs[g.path]; ok {
					continue
				}
				if _, failed := h.progErrs[g.path]; failed {
					continue
				}
				resolveGroupMemo(g)
				allMemoized := len(g.rootedMemo) > 0
				if allMemoized {
					for _, s := range g.subjects {
						if _, ok := g.rootedMemo[s.Symbol]; !ok {
							allMemoized = false
							break
						}
					}
				}
				if !allMemoized {
					uncached = append(uncached, g.path)
				}
			}
			return uncached
		},
	}
	for i, group := range groups {
		currentIdx = i
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
		}
		resolveGroupMemo(group)
		if len(group.rootedMemo) > 0 {
			remaining := group.subjects[:0:0]
			for _, subject := range group.subjects {
				if inv, ok := group.rootedMemo[subject.Symbol]; ok {
					results[subject] = inv
					continue
				}
				remaining = append(remaining, subject)
			}
			if len(remaining) < len(group.subjects) {
				h.Served("rooted functions", group.path)
			}
			group.subjects = remaining
			if len(group.subjects) == 0 {
				continue
			}
		}
		if err := h.rootedGroup(ctx, group, bp, results); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	return results, nil
}

func rootedFunctionsFromReachability(reach attributedReachability) RootedFunctions {
	if reach.unavailable != "" || reach.openWorld || reach.rootedIncomplete {
		return RootedFunctions{}
	}
	fns := make(map[string]bool, len(reach.subjectFunctions)+len(reach.rootedExtraFunctions)+len(reach.testMainFunctions)+len(reach.cleanupFunctions))
	for _, provenance := range []map[*ssa.Function]bool{reach.subjectFunctions, reach.rootedExtraFunctions, reach.testMainFunctions, reach.cleanupFunctions} {
		for fn := range provenance {
			if key := rootedFunctionKey(fn); key != "" {
				fns[key] = true
			}
		}
	}
	return RootedFunctions{Fns: fns, Complete: true}
}

// rootedGroup derives one package group's inventories into results. The
// group's whole-program SSA is released on every exit of the group — a
// cut's or an error's included — never retained across groups, so peak
// memory does not grow with the pass's package count (the observability
// batch's measured discipline).
func (h *Hasher) rootedGroup(ctx context.Context, group *packageBatch, bp *batchPreparer, results map[Subject]RootedFunctions) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	h.emitUnit("prove", group.path, 1, 1)
	prog, err := h.loadCachedFrom(ctx, group.path, bp)
	if err != nil {
		return err
	}
	defer h.releaseProgram(group.path)
	computed := make(map[string]RootedFunctions, len(group.subjects))
	rooted := group.subjects[:0:0]
	for _, subject := range group.subjects {
		if prog.Roots[subject.Symbol] == nil {
			// An absent or ambiguous root grants no inventory for
			// that subject alone — incomplete, fail-closed.
			results[subject] = RootedFunctions{}
			computed[subject.Symbol] = RootedFunctions{}
			continue
		}
		rooted = append(rooted, subject)
	}
	for start := 0; start < len(rooted); start += maxAttributedSubjects {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("closure: analysis cancelled: %w", err)
		}
		end := min(start+maxAttributedSubjects, len(rooted))
		batch := rooted[start:end]
		reachable, err := attributedReachableSets(ctx, h.SelectionAudited(), prog, batch)
		if err != nil {
			return err
		}
		for i, subject := range batch {
			// An isolated analysis failure degrades this subject
			// alone, in the surface's own fail-closed vocabulary
			// - the incomplete RootedFunctions an absent root and
			// an open world already produce
			// (REQ-closure-analysis).
			inv := rootedFunctionsFromReachability(reachable[i])
			results[subject] = inv
			computed[subject.Symbol] = inv
		}
		if memoScope := h.scope.Rooted(); memoScope != "" && group.closureHash != "" && len(computed) > 0 && ctx.Err() == nil {
			storeRootedMemo(memoScope, group.closureHash, computed)
		}
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	if memoScope := h.scope.Rooted(); memoScope != "" && group.closureHash != "" && len(computed) > 0 {
		storeRootedMemo(memoScope, group.closureHash, computed)
	}
	return nil
}

// harnessRootName reports whether a top-level function name is one the
// go test harness can invoke: Test, Benchmark, Fuzz, or Example, bare
// or followed by a non-lowercase rune. Signature is deliberately not
// consulted — a name-matching function the harness would refuse only
// widens the root set, and a spurious root withholds a discharge,
// never grants one.
func harnessRootName(name string) bool {
	for _, prefix := range []string{"Test", "Benchmark", "Fuzz", "Example"} {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		rest := name[len(prefix):]
		if rest == "" {
			return true
		}
		r, _ := utf8.DecodeRuneInString(rest)
		if !unicode.IsLower(r) {
			return true
		}
	}
	return false
}

// ComputeBinaryRootedFunctions derives per-package BINARY rooted-flow
// inventories: the union of every harness root's post-initialization
// attributed reach — every Test, Benchmark, Fuzz, and Example function
// of both test variants, each riding its own TestMain flow where the
// harness runs one. The quantification is the unattested execution
// model's ground: a sibling subject in the same process is itself one
// of these roots, so a site no root reaches cannot have executed after
// initialization whatever the process's subject schedule was. Complete
// is fail-closed: an ambiguous harness-named root (the in-package and
// external variants sharing a top-level name), an unrooted harness
// name, or any root's open-world widening leaves the package's
// inventory incomplete, and an incomplete inventory grants nothing. A
// package whose binary declares no harness roots is vacuously
// complete with an empty inventory — nothing executes past
// initialization in its test process
// (REQ-closure-shared-dynamic-state-reachability). ctx is the analysis
// context exactly as ComputeRootedFunctions takes it.
func (h *Hasher) ComputeBinaryRootedFunctions(ctx context.Context, pkgPaths []string) (map[string]RootedFunctions, error) {
	h.resetCallScope()
	defer func() { h.contents = nil }()
	prevCtx := h.ctx
	h.ctx = ctx
	defer func() { h.ctx = prevCtx }()
	results := make(map[string]RootedFunctions, len(pkgPaths))
	seen := map[string]bool{}
	var paths []string
	for _, path := range pkgPaths {
		if seen[path] {
			continue
		}
		seen[path] = true
		paths = append(paths, path)
	}
	type binaryEntry struct {
		closureHash string
		inventory   RootedFunctions
		memoized    bool
		checked     bool
	}
	memoByPath := make(map[string]*binaryEntry, len(paths))
	resolveBinaryMemo := func(path string) *binaryEntry {
		entry := memoByPath[path]
		if entry == nil {
			entry = &binaryEntry{}
			memoByPath[path] = entry
		}
		if !entry.checked && ctx.Err() == nil {
			entry.checked = true
			entry.closureHash, entry.inventory, entry.memoized = h.binaryRootedMemo(path)
		}
		return entry
	}
	currentIdx := 0
	bp := &batchPreparer{
		h: h,
		candidates: func() []string {
			var uncached []string
			for _, p := range paths[currentIdx:] {
				if ctx.Err() != nil {
					break
				}
				if _, ok := h.progs[p]; ok {
					continue
				}
				if _, failed := h.progErrs[p]; failed {
					continue
				}
				if resolveBinaryMemo(p).memoized {
					continue
				}
				uncached = append(uncached, p)
			}
			return uncached
		},
	}
	for i, path := range paths {
		currentIdx = i
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
		}
		entry := resolveBinaryMemo(path)
		if entry.memoized {
			h.Served("binary rooted functions", path)
			results[path] = entry.inventory
			continue
		}
		inventory, err := h.binaryRootedPackage(ctx, path, entry.closureHash, bp)
		if err != nil {
			return nil, err
		}
		results[path] = inventory
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	return results, nil
}

// binaryRootedPackage derives one package's binary inventory in one
// all-roots attributed RTA walk, releasing the binary's program on every
// exit of the package — the incomplete (tombstoned-root) exit included.
func (h *Hasher) binaryRootedPackage(ctx context.Context, path, closureHash string, bp *batchPreparer) (RootedFunctions, error) {
	if err := ctx.Err(); err != nil {
		return RootedFunctions{}, fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	prog, err := h.loadCachedFrom(ctx, path, bp)
	if err != nil {
		return RootedFunctions{}, err
	}
	defer h.releaseProgram(path)
	persist := func(inv RootedFunctions) (RootedFunctions, error) {
		if err := ctx.Err(); err != nil {
			return RootedFunctions{}, fmt.Errorf("closure: analysis cancelled: %w", err)
		}
		if memoScope := h.scope.Rooted(); memoScope != "" && closureHash != "" {
			storeBinaryRootedMemo(memoScope, closureHash, inv)
		}
		return inv, nil
	}
	var subjects []Subject
	for name := range prog.Ambiguous {
		if harnessRootName(name) {
			// A tombstoned harness name is a root whose flow cannot
			// be bounded: the binary runs one of the colliding
			// functions, and the inventory cannot say which.
			return persist(RootedFunctions{})
		}
	}
	for name := range prog.Roots {
		if strings.ContainsAny(name, ".#") || !harnessRootName(name) {
			continue
		}
		subjects = append(subjects, Subject{Package: path, Symbol: name})
	}
	if len(subjects) == 0 {
		return persist(RootedFunctions{Fns: map[string]bool{}, Complete: true})
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].Symbol < subjects[j].Symbol })
	h.emitUnit("prove", path, 1, 1)
	inv, err := binaryReachableUnion(ctx, h.SelectionAudited(), prog, subjects)
	if err != nil {
		return RootedFunctions{}, err
	}
	return persist(inv)
}
