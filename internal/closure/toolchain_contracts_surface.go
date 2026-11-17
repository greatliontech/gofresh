package closure

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/cachefile"
	"github.com/greatliontech/gofresh/internal/closure/internal/cprep"
	"github.com/greatliontech/gofresh/internal/closure/internal/toolchain"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/trace"
)

type verifiedPackageVerdict struct {
	OK                           bool                `json:"ok"`
	Delegates                    []string            `json:"delegates,omitempty"`
	PureMathFuncs                []string            `json:"pureMathFuncs,omitempty"`
	InactiveRuntimeGates         map[string][]string `json:"inactiveRuntimeGates,omitempty"`
	VerifiedRuntimeLineWriters   []string            `json:"verifiedRuntimeLineWriters,omitempty"`
	RuntimeLinknamePulls         []string            `json:"runtimeLinknamePulls,omitempty"`
	ExternalLinknamePulls        []string            `json:"externalLinknamePulls,omitempty"`
	RequiredInactiveRuntimeGates []string            `json:"requiredInactiveRuntimeGates,omitempty"`
	RequiredRuntimeLineWriters   []string            `json:"requiredRuntimeLineWriters,omitempty"`
}

var (
	verifiedPackageMemo      cachefile.SyncMemo[verifiedPackageVerdict]
	verifiedPureDelegateMemo cachefile.SyncMemo[verifiedPackageVerdict]
	verifiedOffSurfaceMemo   cachefile.SyncMemo[toolchain.OffSurfaceVerdict]
	pkgIncludeDigestCache    cachefile.SyncMemo[string]
	verifiedSurfaceMemo      cachefile.SyncMemo[memoizedSurfaceVerdict]
	toolchainSurfaceVerifyMu sync.Mutex
)

type memoizedSurfaceVerdict struct {
	failed        []string
	pureDelegates map[string]bool
}

func listedPackageNeedsPkgIncludeSalt(lp listedPackage) bool {
	if lp.ImportPath == "runtime" {
		return false
	}
	for _, name := range lp.Files {
		switch strings.ToLower(filepath.Ext(name)) {
		case ".s", ".h", ".c", ".cc", ".cpp", ".cxx", ".m":
			return true
		}
	}
	return false
}

func verifiedPackageMemoKey(importPath, digest string) string {
	return verifiedPackageMemoKeyWithPolicy("", importPath, digest, "")
}

func verifiedPackageMemoKeyWithPolicy(policy, importPath, digest, pkgIncludeSalt string) string {
	if policy == "" {
		policy = admissionPolicy()
	}
	key := toolchainVerifierVersion + "|" + policy + "|" + importPath + "|" + digest
	if pkgIncludeSalt != "" {
		key += "|inc:" + pkgIncludeSalt
	}
	return key
}

func verifiedPureDelegateMemoKeyWithPolicy(policy, importPath, digest, pkgIncludeSalt string) string {
	if policy == "" {
		policy = admissionPolicy()
	}
	key := toolchainVerifierVersion + "|delegate|" + policy + "|" + importPath + "|" + digest
	if pkgIncludeSalt != "" {
		key += "|inc:" + pkgIncludeSalt
	}
	return key
}

func verifiedOffSurfaceMemoKeyWithPolicy(policy, importPath, digest, pkgIncludeSalt string) string {
	if policy == "" {
		policy = admissionPolicy()
	}
	key := toolchainVerifierVersion + "|offsurface|" + policy + "|" + importPath + "|" + digest
	if pkgIncludeSalt != "" {
		key += "|inc:" + pkgIncludeSalt
	}
	return key
}

func verifyToolchainSurface(d sourceDigests) []string {
	failed, _, ioErr, _ := verifyToolchainSurfaceAndDelegatesWithIO(context.Background(), d)
	if ioErr != nil {
		return sortedKeys(boolKeys(d.Packages))
	}
	return failed
}

func verifyToolchainSurfaceContext(ctx context.Context, d sourceDigests) ([]string, error) {
	failed, _, ioErr, ctxErr := verifyToolchainSurfaceAndDelegatesWithIO(ctx, d)
	if ctxErr != nil {
		return nil, ctxErr
	}
	if ioErr != nil {
		return nil, ioErr
	}
	return failed, nil
}

func verifyToolchainSurfaceWithIO(ctx context.Context, d sourceDigests) (failed []string, ioErr error, ctxErr error) {
	failed, _, ioErr, ctxErr = verifyToolchainSurfaceAndDelegatesWithIO(ctx, d)
	return failed, ioErr, ctxErr
}

func surfaceVerificationMemoKey(d sourceDigests, policy, pkgIncludeSalt string, keys []string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(toolchainVerifierVersion))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(policy))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(pkgIncludeSalt))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(d.Content))
	_, _ = h.Write([]byte{0})
	for _, k := range keys {
		_, _ = h.Write([]byte(k))
		_, _ = h.Write([]byte{'='})
		_, _ = h.Write([]byte(d.Packages[k]))
		_, _ = h.Write([]byte{0})
	}
	invKeys := make([]string, 0, len(d.inventory))
	for k := range d.inventory {
		invKeys = append(invKeys, k)
	}
	slices.Sort(invKeys)
	for _, k := range invKeys {
		lp := d.inventory[k]
		_, _ = h.Write([]byte(k))
		_, _ = h.Write([]byte{'|'})
		_, _ = h.Write([]byte(lp.Dir))
		_, _ = h.Write([]byte{'|'})
		_, _ = h.Write([]byte(lp.digest))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func pkgIncludeDigestForSurface(ctx context.Context, d sourceDigests) (string, error) {
	rtLP, ok := d.inventory["runtime"]
	if !ok {
		return "", nil
	}
	goroot, ok := stdPackageGOROOT(rtLP.Dir, rtLP.ImportPath)
	if !ok {
		return rtLP.digest, nil
	}
	cacheKey := ""
	if d.Content != "" && rtLP.digest != "" && !hasDigestReadTestHook() && ctx.Err() == nil {
		cacheKey = rtLP.Dir + "|" + rtLP.digest
		if v, ok := pkgIncludeDigestCache.Load(cacheKey); ok {
			return v, nil
		}
	}
	pkgIncludeDir, rels, notDir, err := resolvePkgIncludeDirAndFiles(ctx, goroot)
	if err != nil {
		return "", fmt.Errorf("pkg/include: %w", err)
	}
	if notDir {
		return "non-dir", nil
	}
	if pkgIncludeDir == "" {
		if cacheKey != "" {
			pkgIncludeDigestCache.Store(cacheKey, "none")
		}
		return "none", nil
	}
	var buf [32 * 1024]byte
	res, err := digestFilesWithExtraBuffered(ctx, pkgIncludeDir, nil, pkgIncludeDir, rels, buf[:])
	if err == nil && cacheKey != "" {
		pkgIncludeDigestCache.Store(cacheKey, res)
	}
	return res, err
}

func verifyToolchainSurfaceAndDelegatesWithIO(ctx context.Context, d sourceDigests) (failed []string, pureDelegates map[string]bool, ioErr error, ctxErr error) {
	if len(d.Packages) == 0 {
		var missing []string
		for _, root := range auditedSurfaceTables() {
			first, _, _ := strings.Cut(root, "/")
			if !strings.Contains(first, ".") {
				missing = append(missing, root)
			}
		}
		return missing, nil, nil, nil
	}
	keys := sortedKeys(boolKeys(d.Packages))
	if len(d.inventory) == 0 {
		return keys, nil, nil, nil
	}
	failedSet := map[string]bool{}
	for _, root := range auditedSurfaceTables() {
		first, _, _ := strings.Cut(root, "/")
		if strings.Contains(first, ".") {
			continue
		}
		if d.Packages[root] == "" {
			failedSet[root] = true
		}
	}
	policy := d.Policy
	if policy == "" {
		policy = admissionPolicy()
	}
	pkgIncludeSalt, incErr := pkgIncludeDigestForSurface(ctx, d)
	if incErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, nil, ctxErr
		}
		return nil, nil, incErr, nil
	}
	surfaceKey := ""
	if d.Content != "" && !hasPackageVerdictOverrideHook() && !hasDigestReadTestHook() && ctx.Err() == nil {
		surfaceKey = surfaceVerificationMemoKey(d, policy, pkgIncludeSalt, keys)
		if cached, ok := verifiedSurfaceMemo.Load(surfaceKey); ok {
			return slices.Clone(cached.failed), maps.Clone(cached.pureDelegates), nil, nil
		}
		toolchainSurfaceVerifyMu.Lock()
		defer toolchainSurfaceVerifyMu.Unlock()
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, err
		}
		if cached, ok := verifiedSurfaceMemo.Load(surfaceKey); ok {
			return slices.Clone(cached.failed), maps.Clone(cached.pureDelegates), nil, nil
		}
	}
	rootDelegates := map[string][]string{}
	surfaceVerdicts := map[string]verifiedPackageVerdict{}
	workers := 1
	if surfaceKey != "" {
		workers = min(len(keys), max(1, runtime.GOMAXPROCS(0)))
	}
	if workers <= 1 {
		for _, pkg := range keys {
			if err := ctx.Err(); err != nil {
				return nil, nil, nil, err
			}
			wantDigest := d.Packages[pkg]
			lp, ok := d.inventory[pkg]
			if !ok || wantDigest == "" || lp.digest == "" || lp.digest != wantDigest {
				failedSet[pkg] = true
				continue
			}
			verdict, err := verifyListedPackageMemoized(ctx, lp, policy, pkgIncludeSalt)
			if err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return nil, nil, nil, ctxErr
				}
				return nil, nil, err, nil
			}
			if !verdict.OK {
				failedSet[pkg] = true
				continue
			}
			surfaceVerdicts[pkg] = verdict
			if (auditset.PurePackage(pkg) || pkg == "path/filepath") && len(verdict.Delegates) > 0 {
				rootDelegates[pkg] = verdict.Delegates
			}
		}
	} else {
		type pkgVerifyOutcome struct {
			verdict verifiedPackageVerdict
			missing bool
			ioErr   error
			ctxErr  error
		}
		outcomes := make([]pkgVerifyOutcome, len(keys))
		var next atomic.Int32
		var wg sync.WaitGroup
		wg.Add(workers)
		for range workers {
			go func() {
				defer wg.Done()
				for {
					idx := int(next.Add(1) - 1)
					if idx >= len(keys) {
						return
					}
					if err := ctx.Err(); err != nil {
						outcomes[idx] = pkgVerifyOutcome{ctxErr: err}
						return
					}
					pkg := keys[idx]
					wantDigest := d.Packages[pkg]
					lp, ok := d.inventory[pkg]
					if !ok || wantDigest == "" || lp.digest == "" || lp.digest != wantDigest {
						outcomes[idx] = pkgVerifyOutcome{missing: true}
						continue
					}
					verdict, err := verifyListedPackageMemoized(ctx, lp, policy, pkgIncludeSalt)
					if err != nil {
						if ctxErr := ctx.Err(); ctxErr != nil {
							outcomes[idx] = pkgVerifyOutcome{ctxErr: ctxErr}
							return
						}
						outcomes[idx] = pkgVerifyOutcome{ioErr: err}
						continue
					}
					outcomes[idx] = pkgVerifyOutcome{verdict: verdict}
				}
			}()
		}
		wg.Wait()
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, err
		}
		for i, pkg := range keys {
			out := outcomes[i]
			if out.ctxErr != nil {
				return nil, nil, nil, out.ctxErr
			}
			if out.ioErr != nil {
				return nil, nil, out.ioErr, nil
			}
			if out.missing || !out.verdict.OK {
				failedSet[pkg] = true
				continue
			}
			surfaceVerdicts[pkg] = out.verdict
			if (auditset.PurePackage(pkg) || pkg == "path/filepath") && len(out.verdict.Delegates) > 0 {
				rootDelegates[pkg] = out.verdict.Delegates
			}
		}
	}

	const (
		delUnseen uint8 = iota
		delVisiting
		delValid
		delFailedInSurface
		delFailedOffSurface
	)
	state := map[string]uint8{}
	pureDelegates = map[string]bool{}
	delegateVerdicts := map[string]verifiedPackageVerdict{}
	var walkDelegate func(pkg string) (uint8, error, error)
	walkDelegate = func(pkg string) (uint8, error, error) {
		switch s := state[pkg]; s {
		case delValid, delFailedInSurface, delFailedOffSurface:
			return s, nil, nil
		case delVisiting:
			if d.Packages[pkg] != "" {
				failedSet[pkg] = true
				state[pkg] = delFailedInSurface
				return delFailedInSurface, nil, nil
			}
			state[pkg] = delFailedOffSurface
			return delFailedOffSurface, nil, nil
		}
		if err := ctx.Err(); err != nil {
			return 0, nil, err
		}
		state[pkg] = delVisiting
		lp, ok := d.inventory[pkg]
		wantDigest := d.Packages[pkg]
		if !ok || lp.digest == "" || (wantDigest != "" && lp.digest != wantDigest) {
			if wantDigest != "" {
				failedSet[pkg] = true
				state[pkg] = delFailedInSurface
				return delFailedInSurface, nil, nil
			}
			state[pkg] = delFailedOffSurface
			return delFailedOffSurface, nil, nil
		}
		verdict, err := verifyPureDelegateMemoized(ctx, lp, policy, pkgIncludeSalt)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return 0, nil, ctxErr
			}
			return 0, err, nil
		}
		if !verdict.OK {
			if wantDigest != "" {
				failedSet[pkg] = true
				state[pkg] = delFailedInSurface
				return delFailedInSurface, nil, nil
			}
			state[pkg] = delFailedOffSurface
			return delFailedOffSurface, nil, nil
		}
		var subStatus uint8 = delValid
		for _, sub := range verdict.Delegates {
			st, ioE, ctxE := walkDelegate(sub)
			if ioE != nil || ctxE != nil {
				return 0, ioE, ctxE
			}
			if st == delFailedOffSurface {
				subStatus = delFailedOffSurface
			} else if st == delFailedInSurface && subStatus == delValid {
				subStatus = delFailedInSurface
			}
		}
		if subStatus == delValid {
			pureDelegates[pkg] = true
			delegateVerdicts[pkg] = verdict
		}
		state[pkg] = subStatus
		return subStatus, nil, nil
	}

	rootKeys := make([]string, 0, len(rootDelegates))
	for k := range rootDelegates {
		rootKeys = append(rootKeys, k)
	}
	slices.Sort(rootKeys)
	for _, rootPkg := range rootKeys {
		for _, del := range rootDelegates[rootPkg] {
			st, ioE, ctxE := walkDelegate(del)
			if ioE != nil || ctxE != nil {
				return nil, nil, ioE, ctxE
			}
			if st == delFailedOffSurface {
				failedSet[rootPkg] = true
			}
		}
	}

	pulledRuntimeTargets := map[string]bool{}
	externalLinknameSeeds := []toolchain.OffSurfaceCrossEdge{}
	needsInactiveGateCheck := false
	for _, pkg := range keys {
		if len(surfaceVerdicts[pkg].RequiredInactiveRuntimeGates) > 0 {
			needsInactiveGateCheck = true
		}
		if pkg != "runtime" {
			for _, sym := range surfaceVerdicts[pkg].RuntimeLinknamePulls {
				pulledRuntimeTargets[sym] = true
			}
		}
		for _, ext := range surfaceVerdicts[pkg].ExternalLinknamePulls {
			if tPkg, tSym, ok := cprep.SplitLinknameTarget(ext); ok {
				externalLinknameSeeds = append(externalLinknameSeeds, toolchain.OffSurfaceCrossEdge{Pkg: tPkg, Sym: tSym})
			}
		}
	}
	for delPkg := range pureDelegates {
		for _, sym := range delegateVerdicts[delPkg].RuntimeLinknamePulls {
			pulledRuntimeTargets[sym] = true
		}
		for _, ext := range delegateVerdicts[delPkg].ExternalLinknamePulls {
			if tPkg, tSym, ok := cprep.SplitLinknameTarget(ext); ok {
				externalLinknameSeeds = append(externalLinknameSeeds, toolchain.OffSurfaceCrossEdge{Pkg: tPkg, Sym: tSym})
			}
		}
	}
	rtVerdict, hasVerifiedRuntime := surfaceVerdicts["runtime"]
	if failedSet["runtime"] {
		hasVerifiedRuntime = false
	}
	if needsInactiveGateCheck && hasVerifiedRuntime && !pulledRuntimeTargets["runtime.*"] {
		if ioE, ctxE := collectOffSurfaceStartupRuntimePulls(ctx, d, policy, pkgIncludeSalt, pureDelegates, externalLinknameSeeds, pulledRuntimeTargets); ioE != nil || ctxE != nil {
			return nil, nil, ioE, ctxE
		}
	}
	verifiedLineWriters := map[string]bool{}
	if hasVerifiedRuntime {
		for _, w := range rtVerdict.VerifiedRuntimeLineWriters {
			verifiedLineWriters[w] = true
		}
	}
	for _, pkg := range keys {
		reqWriters := surfaceVerdicts[pkg].RequiredRuntimeLineWriters
		if len(reqWriters) > 0 {
			if !hasVerifiedRuntime {
				failedSet[pkg] = true
				continue
			}
			for _, w := range reqWriters {
				if !verifiedLineWriters[w] {
					failedSet[pkg] = true
					break
				}
			}
			if failedSet[pkg] {
				continue
			}
		}
		reqGates := surfaceVerdicts[pkg].RequiredInactiveRuntimeGates
		if len(reqGates) == 0 {
			continue
		}
		if !hasVerifiedRuntime || pulledRuntimeTargets["runtime.*"] {
			failedSet[pkg] = true
			continue
		}
		for _, gate := range reqGates {
			mutators, ok := rtVerdict.InactiveRuntimeGates[gate]
			if !ok {
				failedSet[pkg] = true
				break
			}
			mutatorPulled := false
			for _, mut := range mutators {
				if pulledRuntimeTargets[mut] {
					mutatorPulled = true
					break
				}
			}
			if mutatorPulled {
				failedSet[pkg] = true
				break
			}
		}
	}

	if !failedSet["math"] {
		for _, fnName := range surfaceVerdicts["math"].PureMathFuncs {
			pureDelegates["math:"+fnName] = true
		}
	}

	if len(failedSet) == 0 {
		if surfaceKey != "" {
			verifiedSurfaceMemo.Store(surfaceKey, memoizedSurfaceVerdict{
				pureDelegates: maps.Clone(pureDelegates),
			})
		}
		return nil, pureDelegates, nil, nil
	}
	failed = sortedKeys(failedSet)
	if surfaceKey != "" {
		verifiedSurfaceMemo.Store(surfaceKey, memoizedSurfaceVerdict{
			failed: slices.Clone(failed),
		})
	}
	return failed, nil, nil, nil
}

func memoizePackageVerdict[V any](
	ctx context.Context,
	memo *cachefile.SyncMemo[V],
	lp listedPackage,
	policy, pkgIncludeSalt string,
	scopePrefix string,
	memoKeyFn func(policy, importPath, digest, salt string) string,
	compute func(context.Context, listedPackage, string) (V, error),
) (V, error) {
	var zero V
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if policy == "" {
		policy = admissionPolicy()
	}
	needsIncSalt := listedPackageNeedsPkgIncludeSalt(lp)
	canMemo := !needsIncSalt || pkgIncludeSalt != ""
	salt := ""
	if needsIncSalt {
		salt = pkgIncludeSalt
	}
	memoKey := memoKeyFn(policy, lp.ImportPath, lp.digest, salt)
	cacheKey := lp.ImportPath + "|" + lp.digest
	if salt != "" {
		cacheKey += "|inc:" + salt
	}
	scope := scopePrefix + "|" + toolchainVerifierVersion + "|" + policy
	if canMemo {
		if v, ok := memo.Load(memoKey); ok {
			return v, nil
		}
		var cached V
		if cachefile.Load(sourceDigestsDirName, scope, cacheKey, &cached) {
			memo.Store(memoKey, cached)
			return cached, nil
		}
	}
	verdict, ioErr := compute(ctx, lp, pkgIncludeSalt)
	if ioErr != nil {
		return zero, ioErr
	}
	if canMemo {
		memo.Store(memoKey, verdict)
		if lp.digest != "" {
			cachefile.Store(sourceDigestsDirName, scope, cacheKey, verdict)
		}
	}
	return verdict, nil
}

func verifyListedPackageMemoized(ctx context.Context, lp listedPackage, policy, pkgIncludeSalt string) (verifiedPackageVerdict, error) {
	if hasPackageVerdictOverrideHook() {
		salt := ""
		if listedPackageNeedsPkgIncludeSalt(lp) {
			salt = pkgIncludeSalt
		}
		if v, ok := lookupPackageVerdictOverrideHook(verifiedPackageMemoKeyWithPolicy(policy, lp.ImportPath, lp.digest, salt)); ok {
			return v, nil
		}
	}
	return memoizePackageVerdict(
		ctx, &verifiedPackageMemo, lp, policy, pkgIncludeSalt,
		"verified-package",
		verifiedPackageMemoKeyWithPolicy,
		func(ctx context.Context, lp listedPackage, salt string) (verifiedPackageVerdict, error) {
			verdict, verdictErr, ioErr := verifyListedPackageWithIOAndSalt(ctx, lp, salt)
			if ioErr != nil {
				trace.Emit(ctx, trace.DomainToolchain, "package_io_error", lp.ImportPath, trace.Err(ioErr))
				return verifiedPackageVerdict{}, ioErr
			}
			if verdictErr != nil {
				trace.Emit(ctx, trace.DomainToolchain, "package_verdict_error", lp.ImportPath, trace.Err(verdictErr))
				return verifiedPackageVerdict{OK: false}, nil
			}
			verdict.OK = true
			return verdict, nil
		},
	)
}

func verifyPureDelegateMemoized(ctx context.Context, lp listedPackage, policy, pkgIncludeSalt string) (verifiedPackageVerdict, error) {
	return memoizePackageVerdict(
		ctx, &verifiedPureDelegateMemo, lp, policy, pkgIncludeSalt,
		"verified-pure-delegate",
		verifiedPureDelegateMemoKeyWithPolicy,
		func(ctx context.Context, lp listedPackage, salt string) (verifiedPackageVerdict, error) {
			verdict, verdictErr, ioErr := verifyPureCandidateWithIOAndSalt(ctx, lp, salt)
			if ioErr != nil {
				trace.Emit(ctx, trace.DomainToolchain, "package_io_error", lp.ImportPath,
					trace.String("tier", "pure_delegate"),
					trace.Err(ioErr),
				)
				return verifiedPackageVerdict{}, ioErr
			}
			if verdictErr != nil {
				trace.Emit(ctx, trace.DomainToolchain, "package_verdict_error", lp.ImportPath,
					trace.String("tier", "pure_delegate"),
					trace.Err(verdictErr),
				)
				return verifiedPackageVerdict{OK: false}, nil
			}
			verdict.OK = true
			return verdict, nil
		},
	)
}

func verifyOffSurfacePackageMemoized(ctx context.Context, lp listedPackage, policy, pkgIncludeSalt string) (toolchain.OffSurfaceVerdict, error) {
	return memoizePackageVerdict(
		ctx, &verifiedOffSurfaceMemo, lp, policy, pkgIncludeSalt,
		"verified-offsurface",
		verifiedOffSurfaceMemoKeyWithPolicy,
		verifyOffSurfacePackageWithIO,
	)
}

func resolveStdInventoryImport(inventory map[string]listedPackage, importPath string) (string, bool) {
	if _, ok := inventory[importPath]; ok {
		return importPath, true
	}
	if !strings.HasPrefix(importPath, "vendor/") {
		vend := "vendor/" + importPath
		if _, ok := inventory[vend]; ok {
			return vend, true
		}
	}
	return "", false
}

func collectOffSurfaceStartupRuntimePulls(ctx context.Context, d sourceDigests, policy, pkgIncludeSalt string, pureDelegates map[string]bool, externalSeeds []toolchain.OffSurfaceCrossEdge, pulledRuntimeTargets map[string]bool) (ioErr error, ctxErr error) {
	invKeys := make([]string, 0, len(d.inventory))
	for pkg := range d.inventory {
		if pkg == "runtime" || d.Packages[pkg] != "" || pureDelegates[pkg] {
			continue
		}
		invKeys = append(invKeys, pkg)
	}
	slices.Sort(invKeys)
	if len(invKeys) == 0 {
		return nil, nil
	}

	offVerdicts := make(map[string]toolchain.OffSurfaceVerdict, len(invKeys))
	for _, pkg := range invKeys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lp := d.inventory[pkg]
		if lp.digest == "" {
			pulledRuntimeTargets["runtime.*"] = true
			return nil, nil
		}
		ov, err := verifyOffSurfacePackageMemoized(ctx, lp, policy, pkgIncludeSalt)
		if err != nil {
			if cErr := ctx.Err(); cErr != nil {
				return nil, cErr
			}
			return err, nil
		}
		offVerdicts[pkg] = ov
		for _, rt := range ov.DirectRuntimePulls {
			pulledRuntimeTargets[rt] = true
		}
		if pulledRuntimeTargets["runtime.*"] {
			return nil, nil
		}
	}

	toolchain.PropagateOffSurfaceRuntimePulls(
		invKeys,
		offVerdicts,
		func(raw string) (string, bool) {
			return resolveStdInventoryImport(d.inventory, raw)
		},
		externalSeeds,
		pulledRuntimeTargets,
	)
	return nil, nil
}

type selectionDegradation struct {
	axis, remedy string
}

var unresolvedSelection = selectionDegradation{
	axis:   "verdict unresolved: this Hasher was built without construction (NewAt or NewBracketAt)",
	remedy: "; a resolved verdict needs the constructor's selection and toolchain reads",
}

func (d selectionDegradation) audited() bool { return d.axis == "" }

func (d selectionDegradation) notice() string {
	const consequence = " — standard-library observation admissions are disabled (observation proofs strip and serving degrades to execution)"
	if d.axis == "" {
		return ""
	}
	return "toolchain-selection audit: " + d.axis + consequence + d.remedy
}

func toolchainSourceDegradation(version string, d sourceDigests, listErr error) selectionDegradation {
	deg, _ := toolchainSourceDegradationContext(context.Background(), version, d, listErr)
	return deg
}

func toolchainSourceDegradationContext(ctx context.Context, version string, d sourceDigests, listErr error) (selectionDegradation, error) {
	deg, _, err := toolchainSourceDegradationAndDelegatesContext(ctx, version, d, listErr)
	return deg, err
}

func toolchainSourceDegradationAndDelegatesContext(ctx context.Context, version string, d sourceDigests, listErr error) (selectionDegradation, map[string]bool, error) {
	deg, pureDelegates, _, err := toolchainSourceDegradationDetailsContext(ctx, version, d, listErr)
	return deg, pureDelegates, err
}

func toolchainSourceDegradationDetailsContext(ctx context.Context, version string, d sourceDigests, listErr error) (selectionDegradation, map[string]bool, []string, error) {
	if listErr != nil {
		return selectionDegradation{
			fmt.Sprintf("the audited surface of %s could not be read: %v", version, listErr),
			"; the admission needs the toolchain's standard-library source listed and readable",
		}, nil, nil, nil
	}
	failed, pureDelegates, ioErr, ctxErr := verifyToolchainSurfaceAndDelegatesWithIO(ctx, d)
	if ctxErr != nil {
		return selectionDegradation{}, nil, nil, ctxErr
	}
	if ioErr != nil {
		return selectionDegradation{
			fmt.Sprintf("the audited surface of %s could not be read: %v", version, ioErr),
			"; the admission needs the toolchain's standard-library source listed and readable",
		}, nil, nil, nil
	}
	if len(failed) == 0 {
		return selectionDegradation{}, pureDelegates, nil, nil
	}
	return selectionDegradation{
		fmt.Sprintf("the audited surface of %s moved in %d keys: %s", version, len(failed), namedMoved(failed)),
		"; the admission needs every audited standard-library package to satisfy the structural source contracts",
	}, nil, failed, nil
}

func resolveSelection(ctx context.Context, reader *gotool.EnvReader, buildFlags []string) (selectionDegradation, sourceDigests, error) {
	snapshot, err := reader.Snapshot(ctx)
	if err != nil {
		return selectionDegradation{}, sourceDigests{}, err
	}
	normalized, err := gotool.NormalizeEnv(reader.Env)
	if err != nil {
		return selectionDegradation{}, sourceDigests{}, err
	}
	d, listErr := toolchainSourceDigests(ctx, reader.Runner, reader.Dir, normalized, snapshot, buildFlags)
	d.Policy = admissionPolicy()
	if listErr == nil {
		for _, root := range auditedSurfaceTables() {
			first, _, _ := strings.Cut(root, "/")
			if strings.Contains(first, ".") {
				continue
			}
			if _, ok := d.inventory[root]; !ok {
				listErr = fmt.Errorf("required audited standard package %s was not inventoried", root)
				d.Content = ""
				break
			}
		}
	}
	if ctx.Err() != nil {
		return selectionDegradation{}, sourceDigests{}, ctx.Err()
	}
	goversion := snapshot.Value("GOVERSION")
	deg, pureDelegates, failedPkgs, err := toolchainSourceDegradationDetailsContext(ctx, goversion, d, listErr)
	if err != nil {
		return selectionDegradation{}, sourceDigests{}, err
	}
	if deg.audited() {
		d.pureDelegates = pureDelegates
	}
	if trace.Enabled(ctx, trace.DomainToolchain, goversion) {
		trace.Emit(ctx, trace.DomainToolchain, "selection_resolved", goversion,
			trace.Bool("audited", deg.audited()),
			trace.String("content_digest", d.Content),
			trace.String("policy_digest", d.Policy),
			trace.Int("pure_delegates", len(d.pureDelegates)),
			trace.Strings("failed_packages", failedPkgs),
			trace.String("degradation", deg.notice()),
		)
	}
	return deg, d, nil
}

func isInternalStdPackagePath(pkgPath string) bool {
	return pkgPath == "internal" || strings.HasPrefix(pkgPath, "internal/") || strings.HasSuffix(pkgPath, "/internal") || strings.Contains(pkgPath, "/internal/")
}

// ResolveToolchainSelection resolves the toolchain content digest, admission
// policy digest, and toolchain-source audit notice for reader and buildFlags.
func ResolveToolchainSelection(ctx context.Context, reader *gotool.EnvReader, buildFlags []string) (content, policy, notice string, err error) {
	if reader == nil {
		return "", "", "", fmt.Errorf("closure: nil environment reader")
	}
	verdict, source, err := resolveSelection(ctx, reader, buildFlags)
	if err != nil {
		return "", "", "", err
	}
	return source.Content, source.Policy, verdict.notice(), nil
}

// SelectionAudited reports this Hasher's toolchain-source audit verdict.
func (h *Hasher) SelectionAudited() bool {
	return h.verdict().audited()
}

func (h *Hasher) verdict() selectionDegradation {
	if !h.selectionResolved {
		return unresolvedSelection
	}
	return h.selection
}

// SelectionNotice renders this Hasher's verdict as the owned notice: empty when audited.
func (h *Hasher) SelectionNotice() string {
	return h.verdict().notice()
}

// SelectionAttribution is the verdict's axis; empty when audited.
func (h *Hasher) SelectionAttribution() string {
	return h.verdict().axis
}

// AttributeSelection appends the selection's attribution to a tier refusal's reason.
func AttributeSelection(reason, axis string) string {
	if axis == "" || reason == "" {
		return reason
	}
	return reason + " (judged under an unaudited toolchain selection: " + axis + ")"
}
