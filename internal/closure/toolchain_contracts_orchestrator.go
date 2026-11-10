package closure

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
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
	InactiveRuntimeGates         map[string][]string `json:"inactiveRuntimeGates,omitempty"`
	RuntimeLinknamePulls         []string            `json:"runtimeLinknamePulls,omitempty"`
	ExternalLinknamePulls        []string            `json:"externalLinknamePulls,omitempty"`
	RequiredInactiveRuntimeGates []string            `json:"requiredInactiveRuntimeGates,omitempty"`
}

// verifiedPackageMemo caches structural verification verdicts per
// verifiedPackageMemoKey in memory.
var verifiedPackageMemo cachefile.SyncMemo[verifiedPackageVerdict]

// verifiedPureDelegateMemo caches pure-delegate verification verdicts per
// verifiedPureDelegateMemoKeyWithPolicy in memory.
var verifiedPureDelegateMemo cachefile.SyncMemo[verifiedPackageVerdict]

// verifiedOffSurfaceMemo caches off-surface runtime-pull/startup graphs per
// verifiedOffSurfaceMemoKeyWithPolicy in memory.
var verifiedOffSurfaceMemo cachefile.SyncMemo[toolchain.OffSurfaceVerdict]

// pkgIncludeHeaderCache caches GOROOT/pkg/include header contents keyed by
// goroot+"|"+pkgIncludeSalt when pkgIncludeSalt is non-empty.
var pkgIncludeHeaderCache cachefile.SyncMemo[[]string]

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

func packageGOROOTForInclude(dir, importPath string) (string, bool) {
	if goroot, ok := stdPackageGOROOT(dir, importPath); ok {
		return goroot, true
	}
	if dir == "" {
		return "", false
	}
	cleanDir := filepath.Clean(dir)
	marker := string(filepath.Separator) + filepath.Join("lib", "fips140") + string(filepath.Separator)
	if idx := strings.Index(cleanDir, marker); idx > 0 {
		return cleanDir[:idx], true
	}
	return "", false
}

func loadPkgIncludeHeadersForPackage(ctx context.Context, lp listedPackage, pkgIncludeSalt string) (headers []string, verdictErr error, ioErr error) {
	goroot, ok := packageGOROOTForInclude(lp.Dir, lp.ImportPath)
	if !ok {
		return nil, nil, nil
	}
	cacheKey := ""
	if pkgIncludeSalt != "" {
		cacheKey = goroot + "|" + pkgIncludeSalt
		if v, okC := pkgIncludeHeaderCache.Load(cacheKey); okC {
			return v, nil, nil
		}
	}
	pkgIncludeDir := filepath.Join(goroot, "pkg", "include")
	info, err := os.Stat(pkgIncludeDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("pkg/include: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("pkg/include: not a directory"), nil
	}
	rels, err := pkgIncludeRelativeFiles(ctx, pkgIncludeDir)
	if err != nil {
		return nil, nil, fmt.Errorf("pkg/include: %w", err)
	}
	headers = make([]string, 0, len(rels))
	for _, rel := range rels {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		fullPath := filepath.Join(pkgIncludeDir, filepath.FromSlash(rel))
		finfo, err := os.Lstat(fullPath)
		if err != nil {
			return nil, nil, fmt.Errorf("pkg/include/%s: %w", rel, err)
		}
		if !finfo.Mode().IsRegular() {
			return nil, fmt.Errorf("pkg/include/%s: non-regular entry", rel), nil
		}
		raw, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, nil, fmt.Errorf("pkg/include/%s: %w", rel, err)
		}
		headers = append(headers, string(raw))
	}
	if cacheKey != "" {
		pkgIncludeHeaderCache.Store(cacheKey, headers)
	}
	return headers, nil, nil
}

// verifyToolchainSurface checks every audited standard-library package in d
// against gofresh's structural boundary contracts. It returns the sorted list
// of package paths that failed verification (empty when the entire surface is
// verified).
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

var (
	pkgIncludeDigestCache    cachefile.SyncMemo[string]
	verifiedSurfaceMemo      cachefile.SyncMemo[memoizedSurfaceVerdict]
	toolchainSurfaceVerifyMu sync.Mutex
)

type memoizedSurfaceVerdict struct {
	failed        []string
	pureDelegates map[string]bool
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
	pkgIncludeDir := filepath.Join(goroot, "pkg", "include")
	info, err := os.Stat(pkgIncludeDir)
	if err != nil {
		if os.IsNotExist(err) {
			if cacheKey != "" {
				pkgIncludeDigestCache.Store(cacheKey, "none")
			}
			return "none", nil
		}
		return "", fmt.Errorf("pkg/include: %w", err)
	}
	if !info.IsDir() {
		return "non-dir", nil
	}
	rels, err := pkgIncludeRelativeFiles(ctx, pkgIncludeDir)
	if err != nil {
		return "", fmt.Errorf("pkg/include: %w", err)
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
	for _, pkg := range keys {
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
				trace.Emit(ctx, trace.DomainToolchain, "package_io_error", lp.ImportPath,
					trace.Err(ioErr),
				)
				return verifiedPackageVerdict{}, ioErr
			}
			if verdictErr != nil {
				trace.Emit(ctx, trace.DomainToolchain, "package_verdict_error", lp.ImportPath,
					trace.Err(verdictErr),
				)
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

func verifyOffSurfacePackageWithIO(ctx context.Context, lp listedPackage, pkgIncludeSalt string) (toolchain.OffSurfaceVerdict, error) {
	if err := ctx.Err(); err != nil {
		return toolchain.OffSurfaceVerdict{}, err
	}
	if lp.Dir == "" {
		return toolchain.OffSurfaceVerdict{}, fmt.Errorf("%s: empty directory", lp.ImportPath)
	}
	var goFiles, nonGoFiles []string
	for _, name := range lp.Files {
		if strings.EqualFold(filepath.Ext(name), ".go") {
			goFiles = append(goFiles, name)
		} else {
			nonGoFiles = append(nonGoFiles, name)
		}
	}
	var readCache map[string]trackedFileRead
	if lp.digest != "" {
		readCache = make(map[string]trackedFileRead, len(lp.Files))
	}
	directRuntime := map[string]bool{}
	seedCrossMap := map[toolchain.OffSurfaceCrossEdge]bool{}
	var nonGoTexts []string
	for _, name := range nonGoFiles {
		ext := strings.ToLower(filepath.Ext(name))
		switch ext {
		case ".s", ".h", ".c", ".cc", ".cpp", ".cxx", ".m", ".syso":
			if err := ctx.Err(); err != nil {
				return toolchain.OffSurfaceVerdict{}, err
			}
			raw, err := readPackageFileTracked(lp.Dir, name, readCache)
			if err != nil {
				return toolchain.OffSurfaceVerdict{}, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
			}
			if ext == ".syso" {
				cprep.CollectRawBytesRuntimeSymbolRefs(raw, directRuntime)
			} else {
				nonGoTexts = append(nonGoTexts, string(raw))
			}
		}
	}

	var linkDirectives []toolchain.OffSurfaceLinkDirective
	fset := token.NewFileSet()
	parsed := make([]*ast.File, 0, len(goFiles))
	for _, name := range goFiles {
		if err := ctx.Err(); err != nil {
			return toolchain.OffSurfaceVerdict{}, err
		}
		src, err := readPackageFileTracked(lp.Dir, name, readCache)
		if err != nil {
			return toolchain.OffSurfaceVerdict{}, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		text := string(src)
		toolchain.ScanOffSurfaceGoDirectives(text, directRuntime, func(localSym, target string) {
			linkDirectives = append(linkDirectives, toolchain.OffSurfaceLinkDirective{LocalSym: localSym, Target: target})
		})
		mode := parser.Mode(0)
		if cprep.SourceMayImportC(text) {
			mode = parser.ParseComments
		}
		file, err := parser.ParseFile(fset, name, src, mode)
		if err != nil {
			// Unparseable off-surface Go file fails closed on runtime.*
			directRuntime["runtime.*"] = true
			continue
		}
		if mode == parser.ParseComments {
			nonGoTexts = append(nonGoTexts, cprep.ExtractFileCgoPreambles(file)...)
		}
		parsed = append(parsed, file)
	}
	if len(nonGoTexts) > 0 {
		extAsm := map[string]bool{}
		incHdrs, vErr, iErr := loadPkgIncludeHeadersForPackage(ctx, lp, pkgIncludeSalt)
		if iErr != nil {
			return toolchain.OffSurfaceVerdict{}, iErr
		}
		if vErr != nil {
			directRuntime["runtime.*"] = true
		} else {
			if cprep.ScanPreprocessedNonGoSymbolRefs(lp.ImportPath, incHdrs, nonGoTexts, directRuntime, extAsm, nil) {
				directRuntime["runtime.*"] = true
			}
			for ext := range extAsm {
				if tPkg, tSym, ok := cprep.SplitLinknameTarget(ext); ok && tPkg != lp.ImportPath {
					seedCrossMap[toolchain.OffSurfaceCrossEdge{Pkg: tPkg, Sym: tSym}] = true
				}
			}
		}
	}
	if lp.digest != "" {
		curDigest, err := verifyReadPackageDigest(ctx, lp, readCache)
		if err != nil {
			return toolchain.OffSurfaceVerdict{}, fmt.Errorf("%s: %w", lp.ImportPath, err)
		}
		if curDigest != lp.digest {
			return toolchain.OffSurfaceVerdict{}, fmt.Errorf("%s: source moved during verification", lp.ImportPath)
		}
	}
	return toolchain.BuildOffSurfaceGraph(lp.ImportPath, parsed, linkDirectives, directRuntime, seedCrossMap), nil
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

// verifyListedPackage checks the structural AST and directive contracts for one
// standard-library package's selected files.
func verifyListedPackage(lp listedPackage) error {
	verdict, verdictErr, ioErr := verifyListedPackageWithIO(context.Background(), lp)
	if ioErr != nil {
		return ioErr
	}
	if verdictErr != nil {
		return verdictErr
	}
	if len(verdict.RequiredInactiveRuntimeGates) > 0 {
		return fmt.Errorf("%s: requires cross-package runtime gate verification %v", lp.ImportPath, verdict.RequiredInactiveRuntimeGates)
	}
	return nil
}

// verifyListedPurePackage checks the pure/delegate AST, assembly, native-file,
// and directive contracts for one standard-library package's selected files.
func verifyListedPurePackage(lp listedPackage) error {
	_, verdictErr, ioErr := verifyPureCandidateWithIO(context.Background(), lp)
	if ioErr != nil {
		return ioErr
	}
	return verdictErr
}

func verifyPureCandidateWithIO(ctx context.Context, lp listedPackage) (verdict verifiedPackageVerdict, verdictErr error, ioErr error) {
	return verifyPureCandidateWithIOAndSalt(ctx, lp, "")
}

func verifyPureCandidateWithIOAndSalt(ctx context.Context, lp listedPackage, pkgIncludeSalt string) (verdict verifiedPackageVerdict, verdictErr error, ioErr error) {
	if err := ctx.Err(); err != nil {
		return verifiedPackageVerdict{}, nil, err
	}
	if lp.Dir == "" {
		return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: empty directory", lp.ImportPath)
	}
	var goFiles, asmFiles, headerFiles []string
	selectedHeaders := map[string]bool{}
	for _, name := range lp.Files {
		ext := strings.ToLower(filepath.Ext(name))
		switch ext {
		case ".c", ".cc", ".cpp", ".cxx", ".f", ".m", ".swig", ".swigcxx", ".syso":
			return verifiedPackageVerdict{}, fmt.Errorf("%s: pure package selects native file %s", lp.ImportPath, name), nil
		case ".s":
			asmFiles = append(asmFiles, name)
		case ".h":
			headerFiles = append(headerFiles, name)
			selectedHeaders[name] = true
		case ".go":
			goFiles = append(goFiles, name)
		}
	}
	if len(goFiles) == 0 {
		return verifiedPackageVerdict{}, fmt.Errorf("%s: no selected Go files", lp.ImportPath), nil
	}
	var readCache map[string]trackedFileRead
	if lp.digest != "" {
		readCache = make(map[string]trackedFileRead, len(lp.Files))
	}
	runtimePullTargets := map[string]bool{}
	externalPullTargets := map[string]bool{}
	var nonGoTexts []string
	for _, name := range append(slices.Clone(asmFiles), headerFiles...) {
		if err := ctx.Err(); err != nil {
			return verifiedPackageVerdict{}, nil, err
		}
		src, err := readPackageFileTracked(lp.Dir, name, readCache)
		if err != nil {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		if len(asmFiles) > 0 {
			if err := toolchain.VerifyToolchainAssemblyFile(ctx, lp.ImportPath, name, string(src), selectedHeaders); err != nil {
				return verifiedPackageVerdict{}, err, nil
			}
		}
		if lp.ImportPath != "runtime" {
			nonGoTexts = append(nonGoTexts, string(src))
		}
	}
	if len(nonGoTexts) > 0 && lp.ImportPath != "runtime" {
		incHdrs, vErr, iErr := loadPkgIncludeHeadersForPackage(ctx, lp, pkgIncludeSalt)
		if iErr != nil {
			return verifiedPackageVerdict{}, nil, iErr
		}
		if vErr != nil {
			return verifiedPackageVerdict{}, vErr, nil
		}
		if cprep.ScanPreprocessedNonGoSymbolRefs(lp.ImportPath, incHdrs, nonGoTexts, runtimePullTargets, externalPullTargets, nil) {
			return verifiedPackageVerdict{}, fmt.Errorf("%s: non-Go macro expansion budget exceeded", lp.ImportPath), nil
		}
	}

	fset := token.NewFileSet()
	parsed := make([]*ast.File, 0, len(goFiles))
	for _, name := range goFiles {
		if err := ctx.Err(); err != nil {
			return verifiedPackageVerdict{}, nil, err
		}
		src, err := readPackageFileTracked(lp.Dir, name, readCache)
		if err != nil {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		text := string(src)
		if err := toolchain.VerifyFileLinknameDirectives(lp.ImportPath, text); err != nil {
			return verifiedPackageVerdict{}, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err), nil
		}
		if lp.ImportPath != "runtime" {
			toolchain.CollectGoLinknameTargets(lp.ImportPath, text, runtimePullTargets, externalPullTargets)
		}
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			return verifiedPackageVerdict{}, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err), nil
		}
		parsed = append(parsed, file)
	}
	if lp.digest != "" {
		curDigest, err := verifyReadPackageDigest(ctx, lp, readCache)
		if err != nil {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: %w", lp.ImportPath, err)
		}
		if curDigest != lp.digest {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: source moved during verification", lp.ImportPath)
		}
	}
	if err := toolchain.VerifyPurePackageAST(lp.ImportPath, parsed); err != nil {
		return verifiedPackageVerdict{}, err, nil
	}
	if lp.ImportPath == "bufio" {
		if err := toolchain.VerifyBufioWriterAST(parsed); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
	}
	delegateSet := map[string]bool{}
	for _, f := range parsed {
		for _, imp := range f.Imports {
			importPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return verifiedPackageVerdict{}, err, nil
			}
			if !toolchain.IsPureSupportImport(lp.ImportPath, importPath) && !auditset.PurePackage(importPath) {
				delegateSet[importPath] = true
			}
		}
	}
	if len(delegateSet) > 0 {
		verdict.Delegates = sortedKeys(delegateSet)
	}
	if len(runtimePullTargets) > 0 {
		verdict.RuntimeLinknamePulls = sortedKeys(runtimePullTargets)
	}
	if len(externalPullTargets) > 0 {
		verdict.ExternalLinknamePulls = sortedKeys(externalPullTargets)
	}
	return verdict, nil, nil
}

func verifyListedPackageWithIO(ctx context.Context, lp listedPackage) (verdict verifiedPackageVerdict, verdictErr error, ioErr error) {
	return verifyListedPackageWithIOAndSalt(ctx, lp, "")
}

func verifyListedPackageWithIOAndSalt(ctx context.Context, lp listedPackage, pkgIncludeSalt string) (verdict verifiedPackageVerdict, verdictErr error, ioErr error) {
	if err := ctx.Err(); err != nil {
		return verifiedPackageVerdict{}, nil, err
	}
	if lp.Dir == "" {
		return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: empty directory", lp.ImportPath)
	}
	if auditset.PurePackage(lp.ImportPath) {
		return verifyPureCandidateWithIOAndSalt(ctx, lp, pkgIncludeSalt)
	}
	var goFiles, runtimeAsmHeaders, nonGoFiles []string
	for _, name := range lp.Files {
		if strings.EqualFold(filepath.Ext(name), ".go") {
			goFiles = append(goFiles, name)
		} else if lp.ImportPath == "runtime" && cprep.AllowedPureAsmStandardHeaders[name] {
			runtimeAsmHeaders = append(runtimeAsmHeaders, name)
		} else if lp.ImportPath == "os" || lp.ImportPath == "internal/testlog" || lp.ImportPath == "testing/internal/testdeps" || lp.ImportPath == "testing" {
			return verifiedPackageVerdict{}, fmt.Errorf("%s: unexpected non-Go file %s", lp.ImportPath, name), nil
		} else {
			nonGoFiles = append(nonGoFiles, name)
		}
	}
	var readCache map[string]trackedFileRead
	if lp.digest != "" {
		readCache = make(map[string]trackedFileRead, len(lp.Files)+8)
	}
	runtimePullTargets := map[string]bool{}
	externalPullTargets := map[string]bool{}
	runtimeNonGoIdents := map[string]bool{}
	var nonGoTexts []string
	var runtimeIncludeHdrs []string
	var runtimeNonGoTexts []string
	for _, name := range nonGoFiles {
		ext := strings.ToLower(filepath.Ext(name))
		switch ext {
		case ".s", ".h", ".c", ".cc", ".cpp", ".cxx", ".m", ".syso":
			if err := ctx.Err(); err != nil {
				return verifiedPackageVerdict{}, nil, err
			}
			raw, err := readPackageFileTracked(lp.Dir, name, readCache)
			if err != nil {
				return verifiedPackageVerdict{}, nil, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
			}
			if lp.ImportPath == "runtime" {
				if ext == ".syso" {
					cprep.CollectRuntimeIdentsAndMachO(raw, runtimeNonGoIdents)
				} else {
					text := string(raw)
					toolchain.CollectStrippedAsmRuntimeIdents(text, runtimeNonGoIdents)
					if ext == ".h" {
						runtimeIncludeHdrs = append(runtimeIncludeHdrs, text)
					}
					runtimeNonGoTexts = append(runtimeNonGoTexts, text)
				}
			} else {
				if ext == ".syso" {
					cprep.CollectRawBytesRuntimeSymbolRefs(raw, runtimePullTargets)
				} else {
					nonGoTexts = append(nonGoTexts, string(raw))
				}
			}
		}
	}
	if len(goFiles) == 0 {
		if lp.ImportPath == "os" || lp.ImportPath == "internal/testlog" || lp.ImportPath == "testing" || lp.ImportPath == "testing/internal/testdeps" || lp.ImportPath == "runtime" || lp.ImportPath == "sync" || lp.ImportPath == "reflect" || lp.ImportPath == "time" || lp.ImportPath == "math" || lp.ImportPath == "math/rand" || lp.ImportPath == "context" || lp.ImportPath == "crypto/fips140" || lp.ImportPath == "path/filepath" {
			return verifiedPackageVerdict{}, fmt.Errorf("%s: no selected Go files", lp.ImportPath), nil
		}
		if len(nonGoTexts) > 0 && lp.ImportPath != "runtime" {
			incHdrs, vErr, iErr := loadPkgIncludeHeadersForPackage(ctx, lp, pkgIncludeSalt)
			if iErr != nil {
				return verifiedPackageVerdict{}, nil, iErr
			}
			if vErr != nil {
				return verifiedPackageVerdict{}, vErr, nil
			}
			if cprep.ScanPreprocessedNonGoSymbolRefs(lp.ImportPath, incHdrs, nonGoTexts, runtimePullTargets, externalPullTargets, nil) {
				return verifiedPackageVerdict{}, fmt.Errorf("%s: non-Go macro expansion budget exceeded", lp.ImportPath), nil
			}
		}
		if lp.digest != "" && len(nonGoFiles) > 0 {
			curDigest, err := verifyReadPackageDigest(ctx, lp, readCache)
			if err != nil {
				return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: %w", lp.ImportPath, err)
			}
			if curDigest != lp.digest {
				return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: source moved during verification", lp.ImportPath)
			}
		}
		if len(runtimePullTargets) > 0 {
			verdict.RuntimeLinknamePulls = sortedKeys(runtimePullTargets)
		}
		if len(externalPullTargets) > 0 {
			verdict.ExternalLinknamePulls = sortedKeys(externalPullTargets)
		}
		return verdict, nil, nil
	}

	for _, name := range runtimeAsmHeaders {
		if err := ctx.Err(); err != nil {
			return verifiedPackageVerdict{}, nil, err
		}
		src, err := readPackageFileTracked(lp.Dir, name, readCache)
		if err != nil {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		text := string(src)
		if err := toolchain.VerifyToolchainAssemblyFile(ctx, "", lp.ImportPath+"/"+name, text, nil); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
		toolchain.CollectStrippedAsmRuntimeIdents(text, runtimeNonGoIdents)
		if lp.ImportPath == "runtime" {
			runtimeIncludeHdrs = append(runtimeIncludeHdrs, text)
		}
	}
	if lp.ImportPath == "runtime" {
		if goroot, ok := stdPackageGOROOT(lp.Dir, lp.ImportPath); ok {
			pkgIncludeDir := filepath.Join(goroot, "pkg", "include")
			info, err := os.Stat(pkgIncludeDir)
			if err != nil && !os.IsNotExist(err) {
				return verifiedPackageVerdict{}, nil, fmt.Errorf("pkg/include: %w", err)
			}
			if err == nil {
				if !info.IsDir() {
					return verifiedPackageVerdict{}, fmt.Errorf("pkg/include: not a directory"), nil
				}
				hdrs, err := pkgIncludeRelativeFiles(ctx, pkgIncludeDir)
				if err != nil {
					return verifiedPackageVerdict{}, nil, fmt.Errorf("pkg/include: %w", err)
				}
				for _, rel := range hdrs {
					if err := ctx.Err(); err != nil {
						return verifiedPackageVerdict{}, nil, err
					}
					fullPath := filepath.Join(pkgIncludeDir, filepath.FromSlash(rel))
					finfo, err := os.Lstat(fullPath)
					if err != nil {
						return verifiedPackageVerdict{}, nil, fmt.Errorf("pkg/include/%s: %w", rel, err)
					}
					if !finfo.Mode().IsRegular() {
						return verifiedPackageVerdict{}, fmt.Errorf("pkg/include/%s: non-regular entry", rel), nil
					}
					src, err := readFileTracked(fullPath, "../../pkg/include/"+rel, readCache)
					if err != nil {
						return verifiedPackageVerdict{}, nil, fmt.Errorf("pkg/include/%s: %w", rel, err)
					}
					text := string(src)
					if err := toolchain.VerifyToolchainAssemblyFile(ctx, "", "pkg/include/"+rel, text, nil); err != nil {
						return verifiedPackageVerdict{}, err, nil
					}
					toolchain.CollectStrippedAsmRuntimeIdents(text, runtimeNonGoIdents)
					runtimeIncludeHdrs = append(runtimeIncludeHdrs, text)
				}
			}
		}
	}

	fset := token.NewFileSet()
	parsed := make([]*ast.File, 0, len(goFiles))
	var runtimeGoSrcs []string
	runtimePullLinknames := map[string]bool{}
	osRuntimePullMap := map[string]string{}
	osAnyLinknameLocals := map[string]bool{}
	selfPushLinknames := map[string]bool{}
	isHarnessPkg := lp.ImportPath == "os" || lp.ImportPath == "internal/testlog" || lp.ImportPath == "testing/internal/testdeps" || lp.ImportPath == "testing"
	for _, name := range goFiles {
		if err := ctx.Err(); err != nil {
			return verifiedPackageVerdict{}, nil, err
		}
		src, err := readPackageFileTracked(lp.Dir, name, readCache)
		if err != nil {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		text := string(src)
		if lp.ImportPath == "runtime" {
			runtimeGoSrcs = append(runtimeGoSrcs, text)
			toolchain.CollectGoLinknameTargets(lp.ImportPath, text, nil, externalPullTargets)
		} else {
			toolchain.CollectGoLinknameTargets(lp.ImportPath, text, runtimePullTargets, externalPullTargets)
		}
		if isHarnessPkg {
			if err := toolchain.VerifyHarnessFileDirectives(lp.ImportPath, text, runtimePullLinknames, selfPushLinknames, osRuntimePullMap, osAnyLinknameLocals); err != nil {
				return verifiedPackageVerdict{}, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err), nil
			}
		}
		mode := parser.Mode(0)
		if cprep.SourceMayImportC(text) {
			mode = parser.ParseComments
		}
		file, err := parser.ParseFile(fset, name, src, mode)
		if err != nil {
			return verifiedPackageVerdict{}, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err), nil
		}
		if mode == parser.ParseComments {
			preambles := cprep.ExtractFileCgoPreambles(file)
			if lp.ImportPath == "runtime" {
				runtimeNonGoTexts = append(runtimeNonGoTexts, preambles...)
			} else {
				nonGoTexts = append(nonGoTexts, preambles...)
			}
		}
		parsed = append(parsed, file)
	}
	if lp.ImportPath == "runtime" && len(runtimeNonGoTexts) > 0 {
		if cprep.ScanPreprocessedNonGoSymbolRefs(lp.ImportPath, runtimeIncludeHdrs, runtimeNonGoTexts, nil, externalPullTargets, runtimeNonGoIdents) {
			return verifiedPackageVerdict{}, fmt.Errorf("%s: non-Go macro expansion budget exceeded", lp.ImportPath), nil
		}
	} else if len(nonGoTexts) > 0 && lp.ImportPath != "runtime" {
		incHdrs, vErr, iErr := loadPkgIncludeHeadersForPackage(ctx, lp, pkgIncludeSalt)
		if iErr != nil {
			return verifiedPackageVerdict{}, nil, iErr
		}
		if vErr != nil {
			return verifiedPackageVerdict{}, vErr, nil
		}
		if cprep.ScanPreprocessedNonGoSymbolRefs(lp.ImportPath, incHdrs, nonGoTexts, runtimePullTargets, externalPullTargets, nil) {
			return verifiedPackageVerdict{}, fmt.Errorf("%s: non-Go macro expansion budget exceeded", lp.ImportPath), nil
		}
	}
	if lp.digest != "" {
		curDigest, err := verifyReadPackageDigest(ctx, lp, readCache)
		if err != nil {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: %w", lp.ImportPath, err)
		}
		if curDigest != lp.digest {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: source moved during verification", lp.ImportPath)
		}
	}

	switch lp.ImportPath {
	case "runtime":
		verdict.InactiveRuntimeGates = toolchain.DiscoverRuntimeInactiveGates(parsed, runtimeGoSrcs, runtimeNonGoIdents)
	case "os":
		reqGates, err := toolchain.VerifyOSPackageAST(parsed, osRuntimePullMap, osAnyLinknameLocals)
		if err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
		verdict.RequiredInactiveRuntimeGates = reqGates
	case "internal/testlog":
		if err := toolchain.VerifyInternalTestlogPackageAST(parsed); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
	case "testing/internal/testdeps":
		if err := toolchain.VerifyTestdepsPackageAST(parsed); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
	case "testing":
		if err := toolchain.VerifyTestingPackageAST(parsed, runtimePullLinknames, selfPushLinknames); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
	case "path/filepath":
		delegateSet := map[string]bool{}
		for _, f := range parsed {
			for _, imp := range f.Imports {
				importPath, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					return verifiedPackageVerdict{}, err, nil
				}
				if strings.HasPrefix(importPath, "internal/") && !toolchain.ForbiddenPureImport(lp.ImportPath, importPath) && !toolchain.IsPureSupportImport(lp.ImportPath, importPath) && !auditset.PurePackage(importPath) {
					delegateSet[importPath] = true
				}
			}
		}
		if len(delegateSet) > 0 {
			verdict.Delegates = sortedKeys(delegateSet)
		}
	}
	if len(runtimePullTargets) > 0 {
		verdict.RuntimeLinknamePulls = sortedKeys(runtimePullTargets)
	}
	if len(externalPullTargets) > 0 {
		verdict.ExternalLinknamePulls = sortedKeys(externalPullTargets)
	}
	return verdict, nil, nil
}

// selectionDegradation is one toolchain-source audit verdict: the axis
// that refused (empty when audited) and the remedy clause the notice
// appends.
type selectionDegradation struct {
	axis, remedy string
}

// unresolvedSelection is the verdict of a Hasher built without
// construction (the zero value): refused, never admitted by default.
var unresolvedSelection = selectionDegradation{
	axis:   "verdict unresolved: this Hasher was built without construction (NewAt or NewBracketAt)",
	remedy: "; a resolved verdict needs the constructor's selection and toolchain reads",
}

func (d selectionDegradation) audited() bool { return d.axis == "" }

// notice renders the verdict as the one owned notice consumers serve:
// empty exactly when audited, else the axis, the consequence, and the
// remedy — text and verdict can never disagree.
func (d selectionDegradation) notice() string {
	const consequence = " — standard-library observation admissions are disabled (observation proofs strip and serving degrades to execution)"
	if d.axis == "" {
		return ""
	}
	return "toolchain-selection audit: " + d.axis + consequence + d.remedy
}

// toolchainSourceDegradation derives the verdict over the running
// toolchain's surface digests and inventory: a surface that could not be
// listed or read refuses naming the fault; a surface where any audited
// package fails structural verification refuses naming the failed packages;
// otherwise the selection is audited.
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

// resolveSelection derives a pass's toolchain-source verdict through
// its environment reader: the audited surface's digests under the
// explicit build flags in the environment the reader resolves (the go
// command merges GOFLAGS itself), read from the GOROOT the snapshot
// names, the listing memoized per selection scope.
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
			} // module-version audits
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

// SelectionAudited reports this Hasher's toolchain-source audit verdict
// — a constructor-resolved verdict with an empty notice, one derivation
// with the rendering: the consumer-tier scans (purity, dynamic state)
// and the view surfaces answer their audited-set consultations from the
// same verdict the closure tiers thread internally. An unresolved
// (zero-value) Hasher refuses.
func (h *Hasher) SelectionAudited() bool {
	return h.verdict().audited()
}

func (h *Hasher) verdict() selectionDegradation {
	if !h.selectionResolved {
		return unresolvedSelection
	}
	return h.selection
}

// SelectionNotice renders this Hasher's verdict as the owned notice:
// empty when audited.
func (h *Hasher) SelectionNotice() string {
	return h.verdict().notice()
}

// SelectionAttribution is the verdict's axis — the text a tier refusal
// composed under an unaudited selection carries as its attribution
// (REQ-closure-refusal-channels); empty when audited.
func (h *Hasher) SelectionAttribution() string {
	return h.verdict().axis
}

// AttributeSelection appends the selection's attribution to a tier
// refusal's reason: a refusal judged under an unaudited selection names
// it, so a consumer sees that the selection, not the subject, may be
// the cause; an audited selection or an empty reason is unchanged.
func AttributeSelection(reason, axis string) string {
	if axis == "" || reason == "" {
		return reason
	}
	return reason + " (judged under an unaudited toolchain selection: " + axis + ")"
}
