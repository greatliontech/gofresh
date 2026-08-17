package closure

import (
	"fmt"
	"go/types"

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
// (REQ-closure-shared-dynamic-state's reachability scoping).
type RootedFunctions struct {
	Fns      map[string]bool
	Complete bool
}

// ComputeRootedFunctions derives per-subject rooted-flow inventories
// from the same attributed RTA the observability proof rides — the
// masks are conservative over-approximations (address-taken functions
// of matching signature included), so a spurious member only withholds
// a discharge, never grants one. No memo layer: the inventory is
// recomputed per pass, exactly as the pass's fact composition is.
func (h *Hasher) ComputeRootedFunctions(subjects []Subject) (map[Subject]RootedFunctions, error) {
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
		if err := h.ctx.Err(); err != nil {
			return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
		}
		h.emitProgress("prove", group.path)
		prog, err := h.loadCached(group.path)
		if err != nil {
			return nil, err
		}
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
			if err := h.ctx.Err(); err != nil {
				return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
			}
			end := min(start+maxAttributedSubjects, len(rooted))
			batch := rooted[start:end]
			reachable, err := attributedReachableSets(h.ctx, prog, batch)
			if err != nil {
				return nil, err
			}
			for i, subject := range batch {
				reach := reachable[i]
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
		// Per-package test-binary programs are never reused across
		// groups; retaining them would grow peak memory with the batch's
		// package count (the observability batch's measured discipline).
		delete(h.progs, group.path)
	}
	if err := h.ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	return results, nil
}
