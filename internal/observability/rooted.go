package observability

import (
	"context"
	"errors"
	"fmt"
	"go/types"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
)

func rootedFunctionKey(fn *ssa.Function) string {
	if fn == nil || fn.Object() == nil || fn.Object().Pkg() == nil || isUnnamedStructPromotedWrapper(fn) {
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
// the single-subject-process execution model
// (REQ-closure-shared-dynamic-state-reachability).
type RootedFunctions struct {
	Fns      map[string]bool
	Complete bool
}

// ComputeRootedFunctions derives per-subject rooted-flow inventories
// from attributed RTA.
func (p *Prover) ComputeRootedFunctions(ctx context.Context, subjects []Subject) (map[Subject]RootedFunctions, error) {
	p.ResetCallScope()
	defer p.Hasher.DropCallBuffers()
	var results map[Subject]RootedFunctions
	err := p.Hasher.WithContext(ctx, func() error {
		var runErr error
		results, runErr = runSubjectBatch(p, ctx, subjects, "rooted functions", p.rootedGroupMemo, func(group *packageBatch, bp *batchPreparer, out map[Subject]RootedFunctions) error {
			return p.rootedGroup(ctx, group, bp, out)
		})
		return runErr
	})
	return results, err
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

func (p *Prover) rootedGroup(ctx context.Context, group *packageBatch, bp *batchPreparer, results map[Subject]RootedFunctions) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	p.Hasher.Unit("prove", group.path, 1, 1)
	prog, err := p.loadCachedFrom(ctx, group.path, bp)
	if err != nil {
		return err
	}
	defer p.releaseProgram(group.path)
	return p.rootedOnProgram(ctx, group.path, group.closureHash, group.subjects, prog, results)
}

func (p *Prover) rootedOnProgram(ctx context.Context, pkgPath, closureHash string, subjects []Subject, prog *Program, results map[Subject]RootedFunctions) error {
	computed := make(map[string]RootedFunctions, len(subjects))
	var rooted []Subject
	for _, subject := range subjects {
		if prog.Roots[subject.Symbol] == nil {
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
		reachable, err := attributedReachableSets(ctx, p.Hasher.SelectionAudited(), p.Hasher.PureDelegates(), prog, batch)
		if err != nil {
			return err
		}
		for i, subject := range batch {
			inv := rootedFunctionsFromReachability(reachable[i])
			results[subject] = inv
			computed[subject.Symbol] = inv
		}
		if memoScope := p.Hasher.Scope().Rooted(); memoScope != "" && closureHash != "" && len(computed) > 0 && ctx.Err() == nil {
			storeRootedMemo(memoScope, closureHash, computed)
		}
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	if memoScope := p.Hasher.Scope().Rooted(); memoScope != "" && closureHash != "" && len(computed) > 0 {
		storeRootedMemo(memoScope, closureHash, computed)
	}
	return nil
}

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

// ComputeBinaryRootedFunctions derives per-package BINARY rooted-flow inventories.
func (p *Prover) ComputeBinaryRootedFunctions(ctx context.Context, pkgPaths []string) (map[string]RootedFunctions, error) {
	p.ResetCallScope()
	defer p.Hasher.DropCallBuffers()
	var results map[string]RootedFunctions
	err := p.Hasher.WithContext(ctx, func() error {
		results = make(map[string]RootedFunctions, len(pkgPaths))
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
				entry.closureHash, entry.inventory, entry.memoized = p.binaryRootedMemo(path)
			}
			return entry
		}
		currentIdx := 0
		bp := &batchPreparer{
			p: p,
			candidates: func() []string {
				var uncached []string
				for _, path := range paths[currentIdx:] {
					if ctx.Err() != nil {
						break
					}
					if _, ok := p.progs[path]; ok {
						continue
					}
					if _, failed := p.progErrs[path]; failed {
						continue
					}
					if resolveBinaryMemo(path).memoized {
						continue
					}
					uncached = append(uncached, path)
				}
				return uncached
			},
		}
		for i, path := range paths {
			currentIdx = i
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("closure: analysis cancelled: %w", err)
			}
			entry := resolveBinaryMemo(path)
			if entry.memoized {
				p.Hasher.Served("binary rooted functions", path)
				results[path] = entry.inventory
				continue
			}
			inventory, err := p.binaryRootedPackage(ctx, path, entry.closureHash, bp)
			if err != nil {
				return err
			}
			results[path] = inventory
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("closure: analysis cancelled: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

func (p *Prover) binaryRootedPackage(ctx context.Context, path, closureHash string, bp *batchPreparer) (RootedFunctions, error) {
	if err := ctx.Err(); err != nil {
		return RootedFunctions{}, fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	prog, err := p.loadCachedFrom(ctx, path, bp)
	if err != nil {
		return RootedFunctions{}, err
	}
	defer p.releaseProgram(path)
	return p.binaryRootedOnProgram(ctx, path, closureHash, prog, true)
}

func (p *Prover) binaryRootedOnProgram(ctx context.Context, path, closureHash string, prog *Program, emitUnit bool) (RootedFunctions, error) {
	persist := func(inv RootedFunctions) (RootedFunctions, error) {
		if err := ctx.Err(); err != nil {
			return RootedFunctions{}, fmt.Errorf("closure: analysis cancelled: %w", err)
		}
		if memoScope := p.Hasher.Scope().Rooted(); memoScope != "" && closureHash != "" {
			storeBinaryRootedMemo(memoScope, closureHash, inv)
		}
		return inv, nil
	}
	var subjects []Subject
	for name := range prog.Ambiguous {
		if harnessRootName(name) {
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
	if emitUnit {
		p.Hasher.Unit("prove", path, 1, 1)
	}
	inv, err := binaryReachableUnion(ctx, p.Hasher.SelectionAudited(), p.Hasher.PureDelegates(), prog, subjects)
	if err != nil {
		return RootedFunctions{}, err
	}
	return persist(inv)
}

// ComputeRootedAndBinaryFunctions derives both per-subject rooted-flow
// inventories and per-package binary rooted-flow inventories in a single pass,
// loading and building at most one SSA program per uncached package.
func (p *Prover) ComputeRootedAndBinaryFunctions(ctx context.Context, subjects []Subject, binaryPaths []string) (map[Subject]RootedFunctions, map[string]RootedFunctions, error) {
	p.ResetCallScope()
	defer p.Hasher.DropCallBuffers()
	var (
		rootedResults map[Subject]RootedFunctions
		binaryResults map[string]RootedFunctions
	)
	err := p.Hasher.WithContext(ctx, func() error {
		rootedResults = make(map[Subject]RootedFunctions, len(subjects))
		binaryResults = make(map[string]RootedFunctions, len(binaryPaths))

		type combinedPkg struct {
			path            string
			subjects        []Subject
			wantBinary      bool
			closureHash     string
			rootedMemo      map[string]RootedFunctions
			binaryInventory RootedFunctions
			binaryMemoized  bool
			checked         bool
		}
		byPath := map[string]*combinedPkg{}
		var pkgs []*combinedPkg
		ensurePkg := func(path string) *combinedPkg {
			cp := byPath[path]
			if cp == nil {
				cp = &combinedPkg{path: path}
				byPath[path] = cp
				pkgs = append(pkgs, cp)
			}
			return cp
		}
		seenSubj := map[Subject]bool{}
		for _, subj := range subjects {
			if seenSubj[subj] {
				continue
			}
			seenSubj[subj] = true
			cp := ensurePkg(subj.Package)
			cp.subjects = append(cp.subjects, subj)
		}
		for _, path := range binaryPaths {
			ensurePkg(path).wantBinary = true
		}

		resolveMemos := func(cp *combinedPkg) (needRooted, needBinary bool) {
			if !cp.checked && ctx.Err() == nil {
				cp.checked = true
				if len(cp.subjects) > 0 {
					cp.closureHash, cp.rootedMemo = p.rootedGroupMemo(cp.path)
				}
				if cp.wantBinary {
					var binHash string
					binHash, cp.binaryInventory, cp.binaryMemoized = p.binaryRootedMemo(cp.path)
					if cp.closureHash == "" {
						cp.closureHash = binHash
					}
				}
			}
			if len(cp.subjects) > 0 {
				if len(cp.rootedMemo) == 0 {
					needRooted = true
				} else {
					for _, s := range cp.subjects {
						if _, ok := cp.rootedMemo[s.Symbol]; !ok {
							needRooted = true
							break
						}
					}
				}
			}
			if cp.wantBinary && !cp.binaryMemoized {
				needBinary = true
			}
			return needRooted, needBinary
		}

		currentIdx := 0
		bp := &batchPreparer{
			p: p,
			candidates: func() []string {
				var uncached []string
				for _, cp := range pkgs[currentIdx:] {
					if ctx.Err() != nil {
						break
					}
					if _, ok := p.progs[cp.path]; ok {
						continue
					}
					if _, failed := p.progErrs[cp.path]; failed {
						continue
					}
					if nr, nb := resolveMemos(cp); nr || nb {
						uncached = append(uncached, cp.path)
					}
				}
				return uncached
			},
		}

		for i, cp := range pkgs {
			currentIdx = i
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("closure: analysis cancelled: %w", err)
			}
			needRooted, needBinary := resolveMemos(cp)
			var remainingSubjects []Subject
			if len(cp.subjects) > 0 {
				if len(cp.rootedMemo) > 0 {
					for _, s := range cp.subjects {
						if val, ok := cp.rootedMemo[s.Symbol]; ok {
							rootedResults[s] = val
						} else {
							remainingSubjects = append(remainingSubjects, s)
						}
					}
					if len(remainingSubjects) < len(cp.subjects) {
						p.Hasher.Served("rooted functions", cp.path)
					}
				} else {
					remainingSubjects = cp.subjects
				}
			}
			if cp.wantBinary && cp.binaryMemoized {
				p.Hasher.Served("binary rooted functions", cp.path)
				binaryResults[cp.path] = cp.binaryInventory
			}
			if !needRooted && !needBinary {
				continue
			}
			if len(remainingSubjects) > 0 {
				p.Hasher.Unit("prove", cp.path, 1, 1)
			}
			prog, err := p.loadCachedFrom(ctx, cp.path, bp)
			if err != nil {
				return err
			}
			var runErr error
			if len(remainingSubjects) > 0 {
				runErr = p.rootedOnProgram(ctx, cp.path, cp.closureHash, remainingSubjects, prog, rootedResults)
			}
			if runErr == nil && needBinary {
				var inv RootedFunctions
				inv, runErr = p.binaryRootedOnProgram(ctx, cp.path, cp.closureHash, prog, len(remainingSubjects) == 0)
				if runErr == nil {
					binaryResults[cp.path] = inv
				}
			}
			p.releaseProgram(cp.path)
			if runErr != nil {
				return runErr
			}
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("closure: analysis cancelled: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return rootedResults, binaryResults, nil
}

// InMemoryRootedFunctions derives per-subject rooted-flow inventories in memory
// from pre-loaded or in-memory *packages.Package nodes without invoking any go
// subprocess.
func InMemoryRootedFunctions(ctx context.Context, audited bool, pkgs []*packages.Package, pkgMain string, subjects []Subject) (map[Subject]RootedFunctions, error) {
	prog, err := FromPackages(ctx, pkgMain, pkgs)
	if err != nil {
		return nil, err
	}
	results := make(map[Subject]RootedFunctions, len(subjects))
	var rooted []Subject
	for _, subject := range subjects {
		if prog.Roots[subject.Symbol] == nil {
			results[subject] = RootedFunctions{}
			continue
		}
		rooted = append(rooted, subject)
	}
	if len(rooted) == 0 {
		return results, nil
	}
	for start := 0; start < len(rooted); start += maxAttributedSubjects {
		end := min(start+maxAttributedSubjects, len(rooted))
		batch := rooted[start:end]
		reachable, err := attributedReachableSets(ctx, audited, nil, prog, batch)
		if err != nil {
			return nil, err
		}
		for i, subject := range batch {
			results[subject] = rootedFunctionsFromReachability(reachable[i])
		}
	}
	return results, nil
}

// InMemoryBinaryRootedFunctions derives a package's binary rooted-flow inventory
// in memory from pre-loaded or in-memory *packages.Package nodes without invoking
// any go subprocess.
func InMemoryBinaryRootedFunctions(ctx context.Context, audited bool, pkgs []*packages.Package, pkgMain string) (RootedFunctions, error) {
	prog, err := FromPackages(ctx, pkgMain, pkgs)
	if err != nil {
		return RootedFunctions{}, err
	}
	for name := range prog.Ambiguous {
		if harnessRootName(name) {
			return RootedFunctions{}, nil
		}
	}
	var subjects []Subject
	for name := range prog.Roots {
		if strings.ContainsAny(name, ".#") || !harnessRootName(name) {
			continue
		}
		subjects = append(subjects, Subject{Package: pkgMain, Symbol: name})
	}
	if len(subjects) == 0 {
		return RootedFunctions{Fns: map[string]bool{}, Complete: true}, nil
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].Symbol < subjects[j].Symbol })
	return binaryReachableUnion(ctx, audited, nil, prog, subjects)
}

func (p *Prover) loadCached(pkgPath string) (*Program, error) {
	return p.loadCachedContext(p.Hasher.Context(), pkgPath)
}

type batchPreparer struct {
	p          *Prover
	candidates func() []string
	attempted  bool
	prepared   *Prepared
}

func (bp *batchPreparer) prepare(ctx context.Context) (*Prepared, error) {
	if bp == nil {
		return nil, nil
	}
	if !bp.attempted {
		bp.attempted = true
		var err error
		bp.prepared, err = bp.p.prepareBatch(ctx, bp.candidates())
		if err != nil {
			return nil, err
		}
	}
	return bp.prepared, nil
}

func (bp *batchPreparer) release(pkgPath string) {
	if bp != nil && bp.prepared != nil {
		bp.prepared.Release(pkgPath)
	}
}

func (p *Prover) loadCachedContext(ctx context.Context, pkgPath string) (*Program, error) {
	return p.loadCachedFrom(ctx, pkgPath, nil)
}

func (p *Prover) loadCachedFrom(ctx context.Context, pkgPath string, bp *batchPreparer) (*Program, error) {
	if prog, ok := p.progs[pkgPath]; ok {
		if prog != nil && prog.Prog == nil && len(prog.Pkgs) > 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			built, err := FromPackages(ctx, pkgPath, prog.Pkgs)
			if err != nil {
				return nil, err
			}
			bindProgramHasher(p.Hasher, built)
			p.progs[pkgPath] = built
			return built, nil
		}
		bindProgramHasher(p.Hasher, prog)
		return prog, nil
	}
	if err, ok := p.progErrs[pkgPath]; ok {
		return nil, err
	}
	p.Hasher.EmitProgress("load", pkgPath)
	if p.loadProgramOnMiss != nil {
		if prog, ok, err := p.loadProgramOnMiss(ctx, p, pkgPath); ok {
			if err != nil {
				if ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					p.progErrs[pkgPath] = err
				}
				return nil, err
			}
			bindProgramHasher(p.Hasher, prog)
			p.progs[pkgPath] = prog
			return prog, nil
		}
	}
	prepared, err := bp.prepare(ctx)
	if err != nil {
		return nil, err
	}
	defer bp.release(pkgPath)
	var prog *Program
	if prepared != nil && prepared.HasRoots(pkgPath) {
		prog, err = prepared.Build(ctx, pkgPath)
	} else {
		prog, err = Load(ctx, p.Hasher.Dir(), p.Hasher.PackageEnv(), p.Hasher.BuildFlags(), pkgPath)
	}
	if err != nil {
		if ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			p.progErrs[pkgPath] = err
		}
		return nil, err
	}
	bindProgramHasher(p.Hasher, prog)
	p.progs[pkgPath] = prog
	return prog, nil
}

func (p *Prover) releaseProgram(pkgPath string) {
	if prog := p.progs[pkgPath]; prog != nil {
		delete(p.progs, pkgPath)
	}
}

func (p *Prover) prepareBatch(ctx context.Context, uncached []string) (*Prepared, error) {
	if len(uncached) <= 1 {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	prepared, err := Prepare(ctx, p.Hasher.Dir(), p.Hasher.PackageEnv(), p.Hasher.BuildFlags(), uncached...)
	if err != nil {
		if cause := ctx.Err(); cause != nil {
			return nil, fmt.Errorf("closure: analysis cancelled: %w", cause)
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
		}
		return nil, nil
	}
	return prepared, nil
}

type packageBatch struct {
	path        string
	closureHash string
	subjects    []Subject
	memoSymbols map[string]bool
}

func runSubjectBatch[V any](
	p *Prover,
	ctx context.Context,
	subjects []Subject,
	servedKind string,
	loadMemo func(pkgPath string) (string, map[string]V),
	runGroup func(group *packageBatch, bp *batchPreparer, results map[Subject]V) error,
) (map[Subject]V, error) {
	results := make(map[Subject]V, len(subjects))
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
	memoByGroup := make(map[*packageBatch]map[string]V, len(groups))
	memoChecked := make(map[*packageBatch]bool, len(groups))
	resolveGroupMemo := func(group *packageBatch) map[string]V {
		if !memoChecked[group] && ctx.Err() == nil {
			memoChecked[group] = true
			var m map[string]V
			group.closureHash, m = loadMemo(group.path)
			memoByGroup[group] = m
		}
		return memoByGroup[group]
	}
	currentIdx := 0
	bp := &batchPreparer{
		p: p,
		candidates: func() []string {
			var uncached []string
			for _, g := range groups[currentIdx:] {
				if ctx.Err() != nil {
					break
				}
				if _, ok := p.progs[g.path]; ok {
					continue
				}
				if _, failed := p.progErrs[g.path]; failed {
					continue
				}
				memo := resolveGroupMemo(g)
				allMemoized := len(memo) > 0
				if allMemoized {
					for _, s := range g.subjects {
						if _, ok := memo[s.Symbol]; !ok {
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
		memo := resolveGroupMemo(group)
		if len(memo) > 0 {
			group.memoSymbols = make(map[string]bool, len(memo))
			for sym := range memo {
				group.memoSymbols[sym] = true
			}
			remaining := group.subjects[:0:0]
			for _, subject := range group.subjects {
				if val, ok := memo[subject.Symbol]; ok {
					results[subject] = val
					continue
				}
				remaining = append(remaining, subject)
			}
			if len(remaining) < len(group.subjects) {
				p.Hasher.Served(servedKind, group.path)
			}
			group.subjects = remaining
			if len(group.subjects) == 0 {
				continue
			}
		}
		if err := runGroup(group, bp, results); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	return results, nil
}
