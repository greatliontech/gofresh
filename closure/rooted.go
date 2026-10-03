package closure

import (
	"context"
	"fmt"
	"go/types"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/tools/go/ssa"
)

// rootedFunctionKey names one reachable function in the attributed
// mark-site spelling: "path\x00name" for a plain function,
// "path\x00Recv.Name" for a method (the method-fact spelling, pointer
// star and type parameters stripped). An anonymous function or an
// unnameable receiver yields no key — their marks are never attributed,
// so no site can reference them.
func rootedFunctionKey(fn *ssa.Function) string {
	if fn == nil || fn.Object() == nil {
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
// a discharge, never grants one. No memo layer: the inventory is
// recomputed per pass, exactly as the pass's fact composition is. ctx
// governs the analysis and must descend from the Hasher's own: the
// caller's analysis budget rides it (REQ-fresh-context), so a cut ends
// the pass with the context's error and memoizes no load failure — the
// discharge then grants nothing, exactly as every other gap.
func (h *Hasher) ComputeRootedFunctions(ctx context.Context, subjects []Subject) (map[Subject]RootedFunctions, error) {
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
	for _, group := range groups {
		if err := h.rootedGroup(ctx, group, results); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	return results, nil
}

// rootedGroup derives one package group's inventories into results. The
// group's whole-program SSA is released on every exit of the group — a
// cut's or an error's included — never retained across groups, so peak
// memory does not grow with the pass's package count (the observability
// batch's measured discipline).
func (h *Hasher) rootedGroup(ctx context.Context, group *packageBatch, results map[Subject]RootedFunctions) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	h.emitUnit("prove", group.path, 1, 1)
	prog, err := h.loadCachedContext(ctx, group.path)
	if err != nil {
		return err
	}
	defer delete(h.progs, group.path)
	rooted := group.subjects[:0:0]
	for _, subject := range group.subjects {
		if prog.Roots[subject.Symbol] == nil {
			// An absent or ambiguous root grants no inventory for
			// that subject alone — incomplete, fail-closed.
			results[subject] = RootedFunctions{}
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
			reach := reachable[i]
			if reach.unavailable != "" {
				// An isolated analysis failure degrades this subject
				// alone, in the surface's own fail-closed vocabulary
				// - the incomplete RootedFunctions an absent root and
				// an open world already produce
				// (REQ-closure-analysis).
				results[subject] = RootedFunctions{}
				continue
			}
			if reach.openWorld {
				results[subject] = RootedFunctions{}
				continue
			}
			fns := make(map[string]bool, len(reach.subjectFunctions)+len(reach.testMainFunctions))
			for _, provenance := range []map[*ssa.Function]bool{reach.subjectFunctions, reach.testMainFunctions} {
				for fn := range provenance {
					if key := rootedFunctionKey(fn); key != "" {
						fns[key] = true
					}
				}
			}
			results[subject] = RootedFunctions{Fns: fns, Complete: true}
		}
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
	results := make(map[string]RootedFunctions, len(pkgPaths))
	seen := map[string]bool{}
	for _, path := range pkgPaths {
		if seen[path] {
			continue
		}
		seen[path] = true
		inventory, err := h.binaryRootedPackage(ctx, path)
		if err != nil {
			return nil, err
		}
		results[path] = inventory
	}
	return results, nil
}

// binaryRootedPackage derives one package's binary inventory, releasing
// the binary's program on every exit of the package — the incomplete
// (tombstoned-root) exit included; the per-root pass releases it again
// per group, harmlessly.
func (h *Hasher) binaryRootedPackage(ctx context.Context, path string) (RootedFunctions, error) {
	if err := ctx.Err(); err != nil {
		return RootedFunctions{}, fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	prog, err := h.loadCachedContext(ctx, path)
	if err != nil {
		return RootedFunctions{}, err
	}
	defer delete(h.progs, path)
	var subjects []Subject
	for name := range prog.Ambiguous {
		if harnessRootName(name) {
			// A tombstoned harness name is a root whose flow cannot
			// be bounded: the binary runs one of the colliding
			// functions, and the inventory cannot say which.
			return RootedFunctions{}, nil
		}
	}
	for name := range prog.Roots {
		if strings.ContainsAny(name, ".#") || !harnessRootName(name) {
			continue
		}
		subjects = append(subjects, Subject{Package: path, Symbol: name})
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].Symbol < subjects[j].Symbol })
	perRoot, err := h.ComputeRootedFunctions(ctx, subjects)
	if err != nil {
		return RootedFunctions{}, err
	}
	union := map[string]bool{}
	for _, subject := range subjects {
		rooted := perRoot[subject]
		if !rooted.Complete {
			return RootedFunctions{}, nil
		}
		for fn := range rooted.Fns {
			union[fn] = true
		}
	}
	return RootedFunctions{Fns: union, Complete: true}, nil
}
