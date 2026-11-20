package closure

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/closure/internal/cprep"
	"github.com/greatliontech/gofresh/internal/closure/internal/toolchain"
)

type listedPackageReadOptions struct {
	forbidNativeFiles      bool
	forbidAnyNonGoFiles    bool
	requireGoFiles         bool
	parseCgoComments       bool
	unparseableFailsClosed bool
	onNonGoFile            func(name, ext string, raw []byte) error
	onGoSource             func(name, text string) error
}

type listedPackageReadResult struct {
	parsed            []*ast.File
	goSrcs            []string
	asmSources        map[string]string
	selectedHeaders   map[string]bool
	hdrTexts          []string
	nonGoTexts        []string
	cgoPreambles      []string
	runtimeAsmHeaders []string
	hasUnparseable    bool
	readCache         map[string]trackedFileRead
}

func (r listedPackageReadResult) mergeIncludeHeaders(incHdrs []string) []string {
	if len(r.hdrTexts) == 0 {
		return incHdrs
	}
	out := make([]string, 0, len(incHdrs)+len(r.hdrTexts))
	out = append(out, incHdrs...)
	out = append(out, r.hdrTexts...)
	return out
}

func isRecognizedNonGoSourceExt(ext string) bool {
	switch ext {
	case ".s", ".h", ".c", ".cc", ".cpp", ".cxx", ".m", ".syso":
		return true
	}
	return false
}

func isNativeCompiledExt(ext string) bool {
	switch ext {
	case ".c", ".cc", ".cpp", ".cxx", ".f", ".m", ".swig", ".swigcxx", ".syso":
		return true
	}
	return false
}

// readListedPackageFiles classifies, reads, and parses all selected files of lp
// through readPackageFileTracked so all three package verification tiers share
// one file-reading, cgo-preamble-extraction, and digest-consistency pipeline.
func readListedPackageFiles(ctx context.Context, lp listedPackage, opts listedPackageReadOptions) (listedPackageReadResult, error, error) {
	if err := ctx.Err(); err != nil {
		return listedPackageReadResult{}, nil, err
	}
	if lp.Dir == "" {
		return listedPackageReadResult{}, nil, fmt.Errorf("%s: empty directory", lp.ImportPath)
	}
	res := listedPackageReadResult{
		asmSources:      map[string]string{},
		selectedHeaders: map[string]bool{},
	}
	if lp.digest != "" {
		res.readCache = make(map[string]trackedFileRead, len(lp.Files)+8)
	}

	var goFiles, nonGoFiles []string
	for _, name := range lp.Files {
		ext := strings.ToLower(filepath.Ext(name))
		if ext == ".go" {
			goFiles = append(goFiles, name)
			continue
		}
		if opts.forbidAnyNonGoFiles {
			return listedPackageReadResult{}, fmt.Errorf("%s: unexpected non-Go file %s", lp.ImportPath, name), nil
		}
		if opts.forbidNativeFiles && isNativeCompiledExt(ext) {
			return listedPackageReadResult{}, fmt.Errorf("%s: pure package selects native file %s", lp.ImportPath, name), nil
		}
		if lp.ImportPath == "runtime" && cprep.AllowedPureAsmStandardHeaders[name] {
			res.runtimeAsmHeaders = append(res.runtimeAsmHeaders, name)
			continue
		}
		if ext == ".h" {
			res.selectedHeaders[name] = true
		}
		nonGoFiles = append(nonGoFiles, name)
	}

	if opts.requireGoFiles && len(goFiles) == 0 {
		return listedPackageReadResult{}, fmt.Errorf("%s: no selected Go files", lp.ImportPath), nil
	}

	for _, name := range nonGoFiles {
		ext := strings.ToLower(filepath.Ext(name))
		if !isRecognizedNonGoSourceExt(ext) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return listedPackageReadResult{}, nil, err
		}
		raw, err := readPackageFileTracked(lp.Dir, name, res.readCache)
		if err != nil {
			return listedPackageReadResult{}, nil, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		if ext == ".s" {
			res.asmSources[name] = string(raw)
		}
		if ext == ".h" {
			res.hdrTexts = append(res.hdrTexts, string(raw))
		}
		if ext != ".syso" {
			res.nonGoTexts = append(res.nonGoTexts, string(raw))
		}
		if opts.onNonGoFile != nil {
			if vErr := opts.onNonGoFile(name, ext, raw); vErr != nil {
				return listedPackageReadResult{}, vErr, nil
			}
		}
	}

	if len(goFiles) == 0 {
		return res, nil, nil
	}

	fset := token.NewFileSet()
	res.parsed = make([]*ast.File, 0, len(goFiles))
	res.goSrcs = make([]string, 0, len(goFiles))
	for _, name := range goFiles {
		if err := ctx.Err(); err != nil {
			return listedPackageReadResult{}, nil, err
		}
		src, err := readPackageFileTracked(lp.Dir, name, res.readCache)
		if err != nil {
			return listedPackageReadResult{}, nil, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		text := string(src)
		res.goSrcs = append(res.goSrcs, text)
		if opts.onGoSource != nil {
			if vErr := opts.onGoSource(name, text); vErr != nil {
				return listedPackageReadResult{}, vErr, nil
			}
		}
		mode := parser.Mode(0)
		if opts.parseCgoComments && cprep.SourceMayImportC(text) {
			mode = parser.ParseComments
		}
		file, err := parser.ParseFile(fset, name, src, mode)
		if err != nil {
			if opts.unparseableFailsClosed {
				res.hasUnparseable = true
				continue
			}
			return listedPackageReadResult{}, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err), nil
		}
		if mode == parser.ParseComments {
			res.cgoPreambles = append(res.cgoPreambles, cprep.ExtractFileCgoPreambles(file)...)
		}
		res.parsed = append(res.parsed, file)
	}
	return res, nil, nil
}

func verifyTrackedPackageDigestUnmoved(ctx context.Context, lp listedPackage, readCache map[string]trackedFileRead) error {
	if lp.digest == "" {
		return nil
	}
	curDigest, err := verifyReadPackageDigest(ctx, lp, readCache)
	if err != nil {
		return fmt.Errorf("%s: %w", lp.ImportPath, err)
	}
	if curDigest != lp.digest {
		return fmt.Errorf("%s: source moved during verification", lp.ImportPath)
	}
	return nil
}

func verifyOffSurfacePackageWithIO(ctx context.Context, lp listedPackage, pkgIncludeSalt string) (toolchain.OffSurfaceVerdict, error) {
	directRuntime := map[string]bool{}
	seedCrossMap := map[toolchain.OffSurfaceCrossEdge]bool{}
	var linkDirectives []toolchain.OffSurfaceLinkDirective

	readRes, _, ioErr := readListedPackageFiles(ctx, lp, listedPackageReadOptions{
		parseCgoComments:       true,
		unparseableFailsClosed: true,
		onNonGoFile: func(_, ext string, raw []byte) error {
			if ext == ".syso" {
				cprep.CollectRawBytesRuntimeSymbolRefs(raw, directRuntime)
			}
			return nil
		},
		onGoSource: func(_, text string) error {
			toolchain.ScanOffSurfaceGoDirectives(text, directRuntime, func(localSym, target string) {
				linkDirectives = append(linkDirectives, toolchain.OffSurfaceLinkDirective{LocalSym: localSym, Target: target})
			})
			return nil
		},
	})
	if ioErr != nil {
		return toolchain.OffSurfaceVerdict{}, ioErr
	}
	if readRes.hasUnparseable {
		directRuntime["runtime.*"] = true
	}
	nonGoTexts := append(readRes.nonGoTexts, readRes.cgoPreambles...)
	if len(nonGoTexts) > 0 {
		extAsm := map[string]bool{}
		incHdrs, vErr, iErr := loadPkgIncludeHeadersForPackage(ctx, lp, pkgIncludeSalt)
		if iErr != nil {
			return toolchain.OffSurfaceVerdict{}, iErr
		}
		if vErr != nil {
			directRuntime["runtime.*"] = true
		} else {
			if cprep.ScanPreprocessedNonGoSymbolRefs(lp.ImportPath, readRes.mergeIncludeHeaders(incHdrs), nonGoTexts, directRuntime, extAsm, nil) {
				directRuntime["runtime.*"] = true
			}
			for ext := range extAsm {
				if tPkg, tSym, ok := cprep.SplitLinknameTarget(ext); ok && tPkg != lp.ImportPath {
					seedCrossMap[toolchain.OffSurfaceCrossEdge{Pkg: tPkg, Sym: tSym}] = true
				}
			}
		}
	}
	if err := verifyTrackedPackageDigestUnmoved(ctx, lp, readRes.readCache); err != nil {
		return toolchain.OffSurfaceVerdict{}, err
	}
	return toolchain.BuildOffSurfaceGraph(lp.ImportPath, readRes.parsed, linkDirectives, directRuntime, seedCrossMap), nil
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
	if len(verdict.RequiredRuntimeLineWriters) > 0 {
		return fmt.Errorf("%s: requires cross-package runtime line-writer verification %v", lp.ImportPath, verdict.RequiredRuntimeLineWriters)
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
	hasAsm := false
	for _, name := range lp.Files {
		if strings.EqualFold(filepath.Ext(name), ".s") {
			hasAsm = true
			break
		}
	}
	runtimePullTargets := map[string]bool{}
	externalPullTargets := map[string]bool{}
	var selectedHeaders map[string]bool

	readRes, vErr, iErr := readListedPackageFiles(ctx, lp, listedPackageReadOptions{
		forbidNativeFiles: true,
		requireGoFiles:    true,
		onNonGoFile: func(name, ext string, raw []byte) error {
			if !hasAsm || (ext != ".s" && ext != ".h") {
				return nil
			}
			if selectedHeaders == nil {
				selectedHeaders = map[string]bool{}
				for _, f := range lp.Files {
					if strings.EqualFold(filepath.Ext(f), ".h") {
						selectedHeaders[f] = true
					}
				}
			}
			return toolchain.VerifyToolchainAssemblyFile(ctx, lp.ImportPath, name, string(raw), selectedHeaders)
		},
		onGoSource: func(name, text string) error {
			if err := toolchain.VerifyFileLinknameDirectives(lp.ImportPath, text); err != nil {
				return fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
			}
			if lp.ImportPath != "runtime" {
				toolchain.CollectGoLinknameTargets(lp.ImportPath, text, runtimePullTargets, externalPullTargets)
			}
			return nil
		},
	})
	if iErr != nil || vErr != nil {
		return verifiedPackageVerdict{}, vErr, iErr
	}
	if len(readRes.nonGoTexts) > 0 && lp.ImportPath != "runtime" {
		incHdrs, hdrVErr, hdrIErr := loadPkgIncludeHeadersForPackage(ctx, lp, pkgIncludeSalt)
		if hdrIErr != nil {
			return verifiedPackageVerdict{}, nil, hdrIErr
		}
		if hdrVErr != nil {
			return verifiedPackageVerdict{}, hdrVErr, nil
		}
		if cprep.ScanPreprocessedNonGoSymbolRefs(lp.ImportPath, readRes.mergeIncludeHeaders(incHdrs), readRes.nonGoTexts, runtimePullTargets, externalPullTargets, nil) {
			return verifiedPackageVerdict{}, fmt.Errorf("%s: non-Go macro expansion budget exceeded", lp.ImportPath), nil
		}
	}
	if err := verifyTrackedPackageDigestUnmoved(ctx, lp, readRes.readCache); err != nil {
		return verifiedPackageVerdict{}, nil, err
	}
	if err := toolchain.VerifyPurePackageAST(lp.ImportPath, readRes.parsed); err != nil {
		return verifiedPackageVerdict{}, err, nil
	}
	if lp.ImportPath == "bufio" {
		if err := toolchain.VerifyBufioWriterAST(readRes.parsed); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
	}
	delegateSet := map[string]bool{}
	for _, f := range readRes.parsed {
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

func listedSurfaceMustHaveGoFiles(importPath string) bool {
	switch importPath {
	case "os", "internal/testlog", "testing", "testing/internal/testdeps",
		"runtime", "runtime/debug", "sync", "reflect", "time", "math", "math/rand",
		"context", "crypto/fips140", "path/filepath",
		"text/tabwriter", "go/token", "go/scanner", "go/ast", "go/parser":
		return true
	}
	return false
}

func isGoOnlyVerifiedSurfacePkg(importPath string) bool {
	switch importPath {
	case "text/tabwriter", "go/token", "go/scanner", "go/ast", "go/parser":
		return true
	}
	return false
}

func verifyListedPackageWithIO(ctx context.Context, lp listedPackage) (verdict verifiedPackageVerdict, verdictErr error, ioErr error) {
	return verifyListedPackageWithIOAndSalt(ctx, lp, "")
}

func verifyListedPackageWithIOAndSalt(ctx context.Context, lp listedPackage, pkgIncludeSalt string) (verdict verifiedPackageVerdict, verdictErr error, ioErr error) {
	if auditset.PurePackage(lp.ImportPath) {
		return verifyPureCandidateWithIOAndSalt(ctx, lp, pkgIncludeSalt)
	}
	isHarnessPkg := lp.ImportPath == "os" || lp.ImportPath == "internal/testlog" || lp.ImportPath == "testing/internal/testdeps" || lp.ImportPath == "testing"
	isGoOnlyPkg := isGoOnlyVerifiedSurfacePkg(lp.ImportPath)

	runtimePullTargets := map[string]bool{}
	externalPullTargets := map[string]bool{}
	runtimeNonGoIdents := map[string]bool{}
	var runtimeIncludeHdrs []string

	runtimePullLinknames := map[string]bool{}
	harnessRuntimePullMap := map[string]string{}
	harnessAnyLinknameLocals := map[string]bool{}
	selfPushLinknames := map[string]bool{}

	readRes, vErr, iErr := readListedPackageFiles(ctx, lp, listedPackageReadOptions{
		forbidAnyNonGoFiles: isHarnessPkg || isGoOnlyPkg,
		forbidNativeFiles:   lp.ImportPath == "math" || lp.ImportPath == "runtime/debug",
		requireGoFiles:      listedSurfaceMustHaveGoFiles(lp.ImportPath),
		parseCgoComments:    true,
		onNonGoFile: func(_, ext string, raw []byte) error {
			if lp.ImportPath == "runtime" {
				if ext == ".syso" {
					cprep.CollectRuntimeIdentsAndMachO(raw, runtimeNonGoIdents)
				} else {
					text := string(raw)
					toolchain.CollectStrippedAsmRuntimeIdents(text, runtimeNonGoIdents)
					if ext == ".h" {
						runtimeIncludeHdrs = append(runtimeIncludeHdrs, text)
					}
				}
			} else if ext == ".syso" {
				cprep.CollectRawBytesRuntimeSymbolRefs(raw, runtimePullTargets)
			}
			return nil
		},
		onGoSource: func(name, text string) error {
			if lp.ImportPath == "runtime" {
				toolchain.CollectGoLinknameTargets(lp.ImportPath, text, nil, externalPullTargets)
			} else {
				toolchain.CollectGoLinknameTargets(lp.ImportPath, text, runtimePullTargets, externalPullTargets)
			}
			if isHarnessPkg {
				if err := toolchain.VerifyHarnessFileDirectives(lp.ImportPath, text, runtimePullLinknames, selfPushLinknames, harnessRuntimePullMap, harnessAnyLinknameLocals); err != nil {
					return fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
				}
			}
			if isGoOnlyPkg {
				if err := toolchain.VerifyNoForeignDirectives(lp.ImportPath, text); err != nil {
					return fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
				}
			}
			return nil
		},
	})
	if iErr != nil || vErr != nil {
		return verifiedPackageVerdict{}, vErr, iErr
	}

	if len(readRes.parsed) == 0 && len(readRes.goSrcs) == 0 {
		if len(readRes.nonGoTexts) > 0 && lp.ImportPath != "runtime" {
			incHdrs, hdrVErr, hdrIErr := loadPkgIncludeHeadersForPackage(ctx, lp, pkgIncludeSalt)
			if hdrIErr != nil {
				return verifiedPackageVerdict{}, nil, hdrIErr
			}
			if hdrVErr != nil {
				return verifiedPackageVerdict{}, hdrVErr, nil
			}
			if cprep.ScanPreprocessedNonGoSymbolRefs(lp.ImportPath, readRes.mergeIncludeHeaders(incHdrs), readRes.nonGoTexts, runtimePullTargets, externalPullTargets, nil) {
				return verifiedPackageVerdict{}, fmt.Errorf("%s: non-Go macro expansion budget exceeded", lp.ImportPath), nil
			}
		}
		if len(lp.Files) > 0 {
			if err := verifyTrackedPackageDigestUnmoved(ctx, lp, readRes.readCache); err != nil {
				return verifiedPackageVerdict{}, nil, err
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

	for _, name := range readRes.runtimeAsmHeaders {
		if err := ctx.Err(); err != nil {
			return verifiedPackageVerdict{}, nil, err
		}
		src, err := readPackageFileTracked(lp.Dir, name, readRes.readCache)
		if err != nil {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		text := string(src)
		if err := toolchain.VerifyToolchainAssemblyFile(ctx, "", lp.ImportPath+"/"+name, text, nil); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
		toolchain.CollectStrippedAsmRuntimeIdents(text, runtimeNonGoIdents)
		runtimeIncludeHdrs = append(runtimeIncludeHdrs, text)
	}

	if lp.ImportPath == "runtime" {
		rels, hdrTexts, hdrVErr, hdrIErr := loadPkgIncludeHeaders(ctx, lp, "", readRes.readCache)
		if hdrIErr != nil || hdrVErr != nil {
			return verifiedPackageVerdict{}, hdrVErr, hdrIErr
		}
		for i, rel := range rels {
			text := hdrTexts[i]
			if err := toolchain.VerifyToolchainAssemblyFile(ctx, "", "pkg/include/"+rel, text, nil); err != nil {
				return verifiedPackageVerdict{}, err, nil
			}
			toolchain.CollectStrippedAsmRuntimeIdents(text, runtimeNonGoIdents)
			runtimeIncludeHdrs = append(runtimeIncludeHdrs, text)
		}
	}

	allNonGoTexts := append(readRes.nonGoTexts, readRes.cgoPreambles...)
	if lp.ImportPath == "runtime" && len(allNonGoTexts) > 0 {
		if cprep.ScanPreprocessedNonGoSymbolRefs(lp.ImportPath, readRes.mergeIncludeHeaders(runtimeIncludeHdrs), allNonGoTexts, nil, externalPullTargets, runtimeNonGoIdents) {
			return verifiedPackageVerdict{}, fmt.Errorf("%s: non-Go macro expansion budget exceeded", lp.ImportPath), nil
		}
	} else if len(allNonGoTexts) > 0 && lp.ImportPath != "runtime" {
		incHdrs, hdrVErr, hdrIErr := loadPkgIncludeHeadersForPackage(ctx, lp, pkgIncludeSalt)
		if hdrIErr != nil {
			return verifiedPackageVerdict{}, nil, hdrIErr
		}
		if hdrVErr != nil {
			return verifiedPackageVerdict{}, hdrVErr, nil
		}
		if cprep.ScanPreprocessedNonGoSymbolRefs(lp.ImportPath, readRes.mergeIncludeHeaders(incHdrs), allNonGoTexts, runtimePullTargets, externalPullTargets, nil) {
			return verifiedPackageVerdict{}, fmt.Errorf("%s: non-Go macro expansion budget exceeded", lp.ImportPath), nil
		}
	}

	if err := verifyTrackedPackageDigestUnmoved(ctx, lp, readRes.readCache); err != nil {
		return verifiedPackageVerdict{}, nil, err
	}

	switch lp.ImportPath {
	case "runtime":
		verdict.InactiveRuntimeGates = toolchain.DiscoverRuntimeInactiveGates(readRes.parsed, readRes.goSrcs, runtimeNonGoIdents)
		verdict.VerifiedRuntimeLineWriters = toolchain.DiscoverVerifiedRuntimeLineWriters(readRes.parsed, readRes.goSrcs)
		verdict.ModinfoVerified = toolchain.VerifyRuntimeModinfoAST(readRes.parsed, readRes.goSrcs, runtimeNonGoIdents) == nil
	case "runtime/debug":
		if err := toolchain.VerifyRuntimeDebugPackage(ctx, readRes.parsed, readRes.goSrcs, readRes.asmSources, readRes.selectedHeaders); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
	case "text/tabwriter":
		if err := toolchain.VerifyTabwriterPackageAST(readRes.parsed); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
	case "go/token":
		if err := toolchain.VerifyGoTokenPackageAST(readRes.parsed); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
	case "go/scanner":
		if err := toolchain.VerifyGoScannerPackageAST(readRes.parsed); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
	case "go/ast":
		if err := toolchain.VerifyGoASTPackageAST(readRes.parsed); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
	case "go/parser":
		if err := toolchain.VerifyGoParserPackageAST(readRes.parsed); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
	case "os":
		reqGates, err := toolchain.VerifyOSPackageAST(readRes.parsed, harnessRuntimePullMap, harnessAnyLinknameLocals)
		if err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
		verdict.RequiredInactiveRuntimeGates = reqGates
	case "internal/testlog":
		if err := toolchain.VerifyInternalTestlogPackageAST(readRes.parsed); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
	case "testing/internal/testdeps":
		reqGates, reqWriters, err := toolchain.VerifyTestdepsPackageASTWithPulls(readRes.parsed, harnessRuntimePullMap, harnessAnyLinknameLocals)
		if err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
		verdict.RequiredInactiveRuntimeGates = reqGates
		verdict.RequiredRuntimeLineWriters = reqWriters
	case "testing":
		reqGates, err := toolchain.VerifyTestingPackageASTWithPulls(readRes.parsed, runtimePullLinknames, selfPushLinknames, harnessRuntimePullMap, harnessAnyLinknameLocals)
		if err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
		verdict.RequiredInactiveRuntimeGates = reqGates
	case "math":
		pureFuncs, err := toolchain.VerifyMathPackage(ctx, readRes.parsed, readRes.goSrcs, readRes.asmSources, readRes.selectedHeaders)
		if err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
		verdict.PureMathFuncs = pureFuncs
	case "path/filepath":
		delegateSet := map[string]bool{}
		for _, f := range readRes.parsed {
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
