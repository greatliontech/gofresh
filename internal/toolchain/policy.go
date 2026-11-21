package toolchain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/greatliontech/gofresh/internal/asmverify"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/cprep"
	"github.com/greatliontech/gofresh/internal/gotool"
)

// AnalyzingFrontend returns the Go language/compiler version of the running
// gofresh binary (runtime.Version()), never the analyzed selection's ambient
// toolchain (REQ-closure-identity-strategy, REQ-fresh-toolchain-skew).
func AnalyzingFrontend() string { return runtime.Version() }

// InventoriedPackage describes one standard-library package's directory and
// sorted selected source files for hermetic Selection test fixtures.
type InventoriedPackage struct {
	Dir   string
	Files []string
}

// Selection holds the two-axis toolchain-audit verdict and selected
// standard-library source digests/inventory for one build configuration.
// Its zero value is unresolved and fails closed (Audited() == false).
type Selection struct {
	resolved bool
	deg      selectionDegradation
	source   sourceDigests
}

func (s Selection) verdict() selectionDegradation {
	if !s.resolved {
		return unresolvedSelection
	}
	return s.deg
}

// Audited reports whether the toolchain-source audit succeeded.
func (s Selection) Audited() bool {
	return s.verdict().audited()
}

// Notice renders the unaudited degradation notice, or "" when audited.
func (s Selection) Notice() string {
	return s.verdict().notice()
}

// Attribution returns the unaudited selection axis, or "" when audited.
func (s Selection) Attribution() string {
	return s.verdict().axis
}

// Content returns the complete selected standard-library content digest.
func (s Selection) Content() string {
	return s.source.Content
}

// Policy returns the admission policy digest governing the source audit.
func (s Selection) Policy() string {
	return s.source.Policy
}

// PureDelegates returns the verified pure-delegate map when audited, or nil.
func (s Selection) PureDelegates() map[string]bool {
	if !s.Audited() {
		return nil
	}
	return s.source.pureDelegates
}

// HasPureDelegate reports whether s is audited and key is in its verified
// pure-delegate set.
func (s Selection) HasPureDelegate(key string) bool {
	return s.Audited() && s.source.pureDelegates[key]
}

// StandardPackageMeta returns the inventoried directory and sorted selected
// source files for standard package importPath when present in s.
func (s Selection) StandardPackageMeta(importPath string) (dir string, files []string, ok bool) {
	lp, found := s.source.inventory[importPath]
	if !found {
		return "", nil, false
	}
	return lp.Dir, slices.Clone(lp.Files), true
}

// CoversStandardPackages verifies that every standard-library package in pkgs
// matches s's inventoried directory and selected source file list when s carries
// a non-empty Content digest.
func (s Selection) CoversStandardPackages(pkgs []gotool.ListedPackage) error {
	if s.source.Content == "" {
		return nil
	}
	for _, p := range pkgs {
		if !p.Standard {
			continue
		}
		inventory, ok := s.source.inventory[p.SourcePath()]
		if !ok || filepath.Clean(inventory.Dir) != filepath.Clean(p.Dir) || !slices.Equal(inventory.Files, p.SortedSourceFiles()) {
			return fmt.Errorf("closure: selected standard package %s is not covered by the toolchain content inventory", p.ImportPath)
		}
	}
	return nil
}

// WithPureDelegatesForTest returns a copy of s with pureDelegates replaced for
// hermetic delegate-admission tests while preserving s's inventory and digests.
func (s Selection) WithPureDelegatesForTest(pureDelegates map[string]bool) Selection {
	s.source.pureDelegates = pureDelegates
	return s
}

// SelectionForTest constructs a Selection for hermetic unit tests in consumer
// packages without exposing internal digest representations.
func SelectionForTest(
	resolved bool,
	axis, remedy string,
	content, policy string,
	inventory map[string]InventoriedPackage,
	pureDelegates map[string]bool,
) Selection {
	var inv map[string]listedPackage
	if inventory != nil {
		inv = make(map[string]listedPackage, len(inventory))
		for k, v := range inventory {
			inv[k] = listedPackage{
				ImportPath: k,
				Dir:        v.Dir,
				Files:      slices.Clone(v.Files),
			}
		}
	}
	return Selection{
		resolved: resolved,
		deg:      selectionDegradation{axis: axis, remedy: remedy},
		source: sourceDigests{
			Content:       content,
			Policy:        policy,
			inventory:     inv,
			pureDelegates: pureDelegates,
		},
	}
}

// ResolveSelection resolves the toolchain-audit Selection for reader and buildFlags.
func ResolveSelection(ctx context.Context, reader *gotool.EnvReader, buildFlags []string) (Selection, error) {
	if reader == nil {
		return Selection{}, fmt.Errorf("closure: nil environment reader")
	}
	deg, src, err := resolveSelection(ctx, reader, buildFlags)
	if err != nil {
		return Selection{}, err
	}
	return Selection{
		resolved: true,
		deg:      deg,
		source:   src,
	}, nil
}

// ResolveToolchainSelection resolves the toolchain content digest, admission
// policy digest, and toolchain-source audit notice for reader and buildFlags.
func ResolveToolchainSelection(ctx context.Context, reader *gotool.EnvReader, buildFlags []string) (content, policy, notice string, err error) {
	sel, err := ResolveSelection(ctx, reader, buildFlags)
	if err != nil {
		return "", "", "", err
	}
	return sel.Content(), sel.Policy(), sel.Notice(), nil
}

type policyInputs struct {
	verifier    string
	asmVerifier string
	audit       string
	packages    map[string]bool
	linknames   map[string]bool
	seeds       []string
}

func capturePolicyInputs() policyInputs {
	packages := map[string]bool{}
	appendPolicyPackages(packages)
	for k, v := range cprep.AllowedPureAsmStandardHeaders {
		packages["pure-asm-hdr-allow:"+k] = v
	}
	linknames := map[string]bool{}
	for k, v := range cprep.AllowedPureLinknameTargets {
		linknames["pure-link2:"+k] = v
	}
	for k, v := range cprep.AllowedPureSingleArgLinknames {
		linknames["pure-link1:"+k] = v
	}
	for k, v := range cprep.AllowedPureAsmCrossPkgSymbols {
		linknames["pure-asm-sym:"+k] = v
	}
	return policyInputs{
		verifier:    toolchainVerifierVersion,
		asmVerifier: asmverify.NonStdAsmVerifierVersion,
		audit:       auditset.Identity(),
		packages:    packages,
		linknames:   linknames,
		seeds:       surfaceSeeds(),
	}
}

// AdmissionPolicy returns the digest identifying the data governing the
// toolchain-source audit, separately from derivation versions and memo shape.
func AdmissionPolicy() string {
	return capturePolicyInputs().derive()
}

func admissionPolicy() string {
	return AdmissionPolicy()
}

func (in policyInputs) derive() string {
	seeds := slices.Clone(in.seeds)
	sort.Strings(seeds)
	seeds = slices.Compact(seeds)
	data, _ := json.Marshal([]any{"gofresh/toolchain-policy@2", in.verifier, in.asmVerifier, in.audit,
		in.packages, in.linknames, seeds})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

type toolchainTestHookSet struct {
	packageVerdictOverride func(memoKey string) (verifiedPackageVerdict, bool)
	digestRead             func(name string)
}

var (
	toolchainTestHooksMu sync.Mutex
	toolchainTestHooks   atomic.Pointer[toolchainTestHookSet]
)

func withToolchainTestHooks(hooks toolchainTestHookSet, fn func()) {
	toolchainTestHooksMu.Lock()
	defer toolchainTestHooksMu.Unlock()
	defer toolchainTestHooks.Store(nil)
	toolchainTestHooks.Store(&hooks)
	fn()
}

func hasPackageVerdictOverrideHook() bool {
	h := toolchainTestHooks.Load()
	return h != nil && h.packageVerdictOverride != nil
}

func lookupPackageVerdictOverrideHook(memoKey string) (verifiedPackageVerdict, bool) {
	if h := toolchainTestHooks.Load(); h != nil && h.packageVerdictOverride != nil {
		return h.packageVerdictOverride(memoKey)
	}
	return verifiedPackageVerdict{}, false
}

func hasDigestReadTestHook() bool {
	h := toolchainTestHooks.Load()
	return h != nil && h.digestRead != nil
}

func emitDigestReadHook(name string) {
	if h := toolchainTestHooks.Load(); h != nil && h.digestRead != nil {
		h.digestRead(name)
	}
}

// WithUnverifiedPackageForTest runs fn with pkgPath forced to fail toolchain
// package verification during ResolveSelection.
func WithUnverifiedPackageForTest(pkgPath string, fn func()) {
	withToolchainTestHooks(toolchainTestHookSet{
		packageVerdictOverride: func(memoKey string) (verifiedPackageVerdict, bool) {
			if strings.Contains(memoKey, "|"+pkgPath+"|") {
				return verifiedPackageVerdict{OK: false}, true
			}
			return verifiedPackageVerdict{}, false
		},
	}, fn)
}
