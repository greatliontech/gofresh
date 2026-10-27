package closure

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/greatliontech/gofresh/closure/internal/cachefile"
	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/auditset"
)

// toolchainVerifierVersion versions the structural stdlib boundary verifier.
// Bumping this invalidates cached package verification verdicts and moves
// AdmissionPolicy.
const toolchainVerifierVersion = "gofresh/toolchain-verifier@5"

// verifiedPackageMemo caches structural verification verdicts per
// verifiedPackageMemoKey in memory.
var verifiedPackageMemo sync.Map

func verifiedPackageMemoKey(importPath, digest string) string {
	return verifiedPackageMemoKeyWithPolicy("", importPath, digest)
}

func verifiedPackageMemoKeyWithPolicy(policy, importPath, digest string) string {
	if policy == "" {
		policy = admissionPolicy()
	}
	return toolchainVerifierVersion + "|" + policy + "|" + importPath + "|" + digest
}

// pureDelegatePackages lists internal and delegate standard-library packages
// imported by auditset.PurePackages() whose selected Go files must satisfy the
// same closed-import, selector, and directive discipline as pure packages.
var pureDelegatePackages = map[string]bool{
	"crypto":                                true,
	"crypto/cipher":                         true,
	"crypto/internal/boring":                true,
	"crypto/internal/boring/sig":            true,
	"crypto/internal/constanttime":          true,
	"crypto/internal/fips140/alias":         true,
	"crypto/internal/fips140/hmac":          true,
	"crypto/internal/fips140/sha256":        true,
	"crypto/internal/fips140/sha3":          true,
	"crypto/internal/fips140/sha512":        true,
	"crypto/internal/fips140/subtle":        true,
	"crypto/internal/fips140deps/byteorder": true,
	"crypto/internal/fips140deps/cpu":       true,
	"crypto/internal/fips140hash":           true,
	"crypto/internal/fips140only":           true,
	"crypto/internal/impl":                  true,
	"crypto/sha3":                           true,
	"encoding/json/internal":                true,
	"encoding/json/internal/jsonflags":      true,
	"encoding/json/internal/jsonopts":       true,
	"encoding/json/internal/jsonwire":       true,
	"encoding/json/jsontext":                true,
	"encoding/json/v2":                      true,
	"internal/abi":                          true,
	"internal/bytealg":                      true,
	"internal/byteorder":                    true,
	"internal/cpu":                          true,
	"internal/filepathlite":                 true,
	"internal/fmtsort":                      true,
	"internal/goarch":                       true,
	"internal/goos":                         true,
	"internal/oserror":                      true,
	"internal/race":                         true,
	"internal/reflectlite":                  true,
	"internal/runtime/sys":                  true,
	"internal/saferio":                      true,
	"internal/strconv":                      true,
	"internal/stringslite":                  true,
	"internal/unsafeheader":                 true,
}

// allowedPureSupportImports lists the non-pure standard-library packages that a
// package in auditset.PurePackages() or pureDelegatePackages may import under a
// closed allowlist. Any import outside auditset.PurePackages(),
// pureDelegatePackages, allowedPureSupportImports, "unsafe", or an explicit
// package-scoped exception is rejected.
var allowedPureSupportImports = map[string]bool{
	"bufio":                           true,
	"crypto/fips140":                  true,
	"crypto/internal/fips140":         true,
	"crypto/internal/fips140/aes":     true,
	"crypto/internal/fips140/aes/gcm": true,
	"crypto/internal/fips140/drbg":    true,
	"fmt":                             true,
	"internal/godebug":                true,
	"io":                              true,
	"io/fs":                           true,
	"math":                            true,
	"net/netip":                       true,
	"reflect":                         true,
	"runtime":                         true,
	"sync":                            true,
	"sync/atomic":                     true,
	"time":                            true,
}

// forbiddenPureFmtSelectors lists ambient stdio selectors on "fmt" that a pure
// or pure-delegate package may never reference.
var forbiddenPureFmtSelectors = map[string]bool{
	"Print":   true,
	"Printf":  true,
	"Println": true,
	"Scan":    true,
	"Scanf":   true,
	"Scanln":  true,
}

// allowedPureFilepathliteSyscallSelectors lists the selectors on "syscall"
// permitted in internal/filepathlite.
var allowedPureFilepathliteSyscallSelectors = map[string]bool{
	"UTF16PtrFromString": true,
}

// allowedPureFilepathliteWindowsSelectors lists the selectors on
// "internal/syscall/windows" permitted in internal/filepathlite.
var allowedPureFilepathliteWindowsSelectors = map[string]bool{
	"RtlIsDosDeviceName_U": true,
}

// allowedPureMathRandSelectors lists the selectors on "math/rand" permitted in
// math/big (type Rand and deterministic local PRNG constructors New/NewSource).
var allowedPureMathRandSelectors = map[string]bool{
	"New":       true,
	"NewSource": true,
	"Rand":      true,
}

// allowedPureRuntimeSelectors lists the selectors on "runtime" permitted when a
// pure or pure-delegate package imports "runtime".
var allowedPureRuntimeSelectors = map[string]bool{
	"Caller":    true,
	"FuncForPC": true,
	"GOARCH":    true,
	"GOOS":      true,
	"Goexit":    true,
	"KeepAlive": true,
}

// forbiddenPureTimeSelectors lists ambient-clock, timer, and host-timezone
// selectors on package time that a pure or pure-delegate package may never
// reference even when importing "time" for pure value types/marshaling.
var forbiddenPureTimeSelectors = map[string]bool{
	"After":                   true,
	"AfterFunc":               true,
	"ForceUSPacificForTesting": true,
	"LoadLocation":            true,
	"LoadLocationFromTZData":  true,
	"Local":                   true,
	"NewTicker":               true,
	"NewTimer":                true,
	"Now":                     true,
	"ResetLocalOnceForTest":   true,
	"ResetZoneinfoForTesting": true,
	"Since":                   true,
	"Sleep":                   true,
	"Tick":                    true,
	"Unix":                    true,
	"UnixMicro":               true,
	"UnixMilli":               true,
	"Until":                   true,
}

// allowedPureLinknameTargets lists the two-argument //go:linkname and
// //go:linknamestd targets permitted inside auditset.PurePackages() and
// pureDelegatePackages beyond a package's own self-links.
var allowedPureLinknameTargets = map[string]bool{
	"runtime.cmpstring":                      true,
	"runtime.coroswitch":                     true,
	"runtime.divideError":                    true,
	"runtime.memequal":                       true,
	"runtime.memequal_varlen":                true,
	"runtime.newcoro":                        true,
	"runtime.overflowError":                  true,
	"crypto/internal/fips140hash.sha3Unwrap": true,
}

// allowedPureSingleArgLinknames lists the one-argument //go:linkname and
// //go:linknamestd directives permitted inside auditset.PurePackages() and
// pureDelegatePackages.
var allowedPureSingleArgLinknames = map[string]bool{
	"bytes.Compare":                            true,
	"bytes.Equal":                              true,
	"bytes.IndexByte":                          true,
	"bytes.Repeat":                             true,
	"bytes.explode":                            true,
	"crypto/internal/fips140hash.sha3Unwrap":   true,
	"crypto/subtle.setDITDisabled":             true,
	"crypto/subtle.setDITEnabled":              true,
	"internal/cpu.ARM":                         true,
	"internal/cpu.ARM64":                       true,
	"internal/cpu.HWCap":                       true,
	"internal/cpu.Loong64":                     true,
	"internal/cpu.MIPS64X":                     true,
	"internal/cpu.PPC64":                       true,
	"internal/cpu.RISCV64":                     true,
	"internal/cpu.S390X":                       true,
	"internal/cpu.X86":                         true,
	"internal/cpu.isProcessorFeaturePresent":   true,
	"internal/cpu.riscvHWProbe":                true,
	"internal/cpu.sysctlEnabled":               true,
	"internal/race.Acquire":                    true,
	"internal/race.Disable":                    true,
	"internal/race.Enable":                     true,
	"internal/race.Errors":                     true,
	"internal/race.Read":                       true,
	"internal/race.ReadObjectPC":               true,
	"internal/race.ReadPC":                     true,
	"internal/race.ReadRange":                  true,
	"internal/race.Release":                    true,
	"internal/race.ReleaseMerge":               true,
	"internal/race.Write":                      true,
	"internal/race.WriteObjectPC":              true,
	"internal/race.WritePC":                    true,
	"internal/race.WriteRange":                 true,
	"math/big.addMulVVW":                       true,
	"math/big.addVV":                           true,
	"math/big.addVW":                           true,
	"math/big.mulAddVWW":                       true,
	"math/big.shlVU":                           true,
	"math/big.subVV":                           true,
	"math/big.subVW":                           true,
	"net/url.newError":                         true,
	"strconv.bsearch":                          true,
	"strings.IndexByte":                        true,
	"strings.clone":                            true,
	"strings.explode":                          true,
}

func allowedPurePackageImport(pkgPath, importPath string) bool {
	if importPath == "unsafe" || auditset.PurePackage(importPath) || pureDelegatePackages[importPath] || allowedPureSupportImports[importPath] {
		return true
	}
	if pkgPath == "text/scanner" && importPath == "os" {
		return true
	}
	if pkgPath == "math/big" && importPath == "math/rand" {
		return true
	}
	if pkgPath == "internal/filepathlite" && (importPath == "internal/syscall/windows" || importPath == "syscall") {
		return true
	}
	return false
}

// verifyToolchainSurface checks every audited standard-library package in d
// against gofresh's structural boundary contracts. It returns the sorted list
// of package paths that failed verification (empty when the entire surface is
// verified).
func verifyToolchainSurface(d sourceDigests) []string {
	failed, ioErr, _ := verifyToolchainSurfaceWithIO(context.Background(), d)
	if ioErr != nil {
		return sortedKeys(boolKeys(d.Packages))
	}
	return failed
}

func verifyToolchainSurfaceContext(ctx context.Context, d sourceDigests) ([]string, error) {
	failed, ioErr, ctxErr := verifyToolchainSurfaceWithIO(ctx, d)
	if ctxErr != nil {
		return nil, ctxErr
	}
	if ioErr != nil {
		return nil, ioErr
	}
	return failed, nil
}

func verifyToolchainSurfaceWithIO(ctx context.Context, d sourceDigests) (failed []string, ioErr error, ctxErr error) {
	if len(d.Packages) == 0 {
		var missing []string
		for _, root := range auditedSurfaceTables() {
			first, _, _ := strings.Cut(root, "/")
			if !strings.Contains(first, ".") {
				missing = append(missing, root)
			}
		}
		return missing, nil, nil
	}
	keys := sortedKeys(boolKeys(d.Packages))
	if len(d.inventory) == 0 {
		return keys, nil, nil
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
	for _, pkg := range keys {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		wantDigest := d.Packages[pkg]
		lp, ok := d.inventory[pkg]
		if !ok || wantDigest == "" || lp.digest == "" || lp.digest != wantDigest {
			failedSet[pkg] = true
			continue
		}
		verified, err := verifyListedPackageMemoized(lp, policy)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, nil, ctxErr
			}
			return nil, err, nil
		}
		if !verified {
			failedSet[pkg] = true
		}
	}
	if len(failedSet) == 0 {
		return nil, nil, nil
	}
	return sortedKeys(failedSet), nil, nil
}

func verifyListedPackageMemoized(lp listedPackage, policy string) (bool, error) {
	if policy == "" {
		policy = admissionPolicy()
	}
	memoKey := verifiedPackageMemoKeyWithPolicy(policy, lp.ImportPath, lp.digest)
	if v, ok := verifiedPackageMemo.Load(memoKey); ok {
		return v.(bool), nil
	}
	var cached bool
	scope := "verified-package|" + toolchainVerifierVersion + "|" + policy
	if cachefile.Load(sourceDigestsDirName, scope, lp.ImportPath+"|"+lp.digest, &cached) {
		verifiedPackageMemo.Store(memoKey, cached)
		return cached, nil
	}
	verdictErr, ioErr := verifyListedPackageWithIO(lp)
	if ioErr != nil {
		return false, ioErr
	}
	ok := verdictErr == nil
	verifiedPackageMemo.Store(memoKey, ok)
	if lp.digest != "" {
		cachefile.Store(sourceDigestsDirName, scope, lp.ImportPath+"|"+lp.digest, ok)
	}
	return ok, nil
}

// verifyListedPackage checks the structural AST and directive contracts for one
// standard-library package's selected files.
func verifyListedPackage(lp listedPackage) error {
	verdictErr, ioErr := verifyListedPackageWithIO(lp)
	if ioErr != nil {
		return ioErr
	}
	return verdictErr
}

func verifyListedPackageWithIO(lp listedPackage) (verdictErr error, ioErr error) {
	if lp.Dir == "" {
		return nil, fmt.Errorf("%s: empty directory", lp.ImportPath)
	}
	pure := auditset.PurePackage(lp.ImportPath)
	delegate := pureDelegatePackages[lp.ImportPath]
	pureOrDelegate := pure || delegate
	var goFiles []string
	for _, name := range lp.Files {
		ext := strings.ToLower(filepath.Ext(name))
		if pureOrDelegate {
			switch ext {
			case ".c", ".cc", ".cpp", ".cxx", ".f", ".m", ".swig", ".swigcxx", ".syso":
				return fmt.Errorf("%s: pure package selects native file %s", lp.ImportPath, name), nil
			}
		}
		if ext == ".go" {
			goFiles = append(goFiles, name)
		}
	}
	if len(goFiles) == 0 {
		if pureOrDelegate || lp.ImportPath == "os" || lp.ImportPath == "testing" || lp.ImportPath == "testing/internal/testdeps" || lp.ImportPath == "runtime" || lp.ImportPath == "sync" || lp.ImportPath == "reflect" || lp.ImportPath == "time" || lp.ImportPath == "math/rand" || lp.ImportPath == "context" {
			return fmt.Errorf("%s: no selected Go files", lp.ImportPath), nil
		}
		return nil, nil
	}

	fset := token.NewFileSet()
	parsed := make([]*ast.File, 0, len(goFiles))
	for _, name := range goFiles {
		src, err := os.ReadFile(filepath.Join(lp.Dir, name))
		if err != nil {
			return nil, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		if pureOrDelegate {
			if err := verifyFileLinknameDirectives(lp.ImportPath, string(src)); err != nil {
				return fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err), nil
			}
		}
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			return fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err), nil
		}
		parsed = append(parsed, file)
	}
	if lp.digest != "" {
		curDigest, err := digestFiles(context.Background(), lp.Dir, lp.Files)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", lp.ImportPath, err)
		}
		if curDigest != lp.digest {
			return nil, fmt.Errorf("%s: source moved during verification", lp.ImportPath)
		}
	}

	if pureOrDelegate {
		if err := verifyPurePackageAST(lp.ImportPath, parsed); err != nil {
			return err, nil
		}
	}
	switch lp.ImportPath {
	case "net":
		if slices.Contains(lp.Files, "netgo_on.go") || slices.Contains(lp.Files, "netcgo_on.go") {
			return fmt.Errorf("net: tag-selected resolver override file"), nil
		}
	case "os":
		if err := verifyOSPackageAST(parsed); err != nil {
			return err, nil
		}
	case "testing/internal/testdeps":
		if err := verifyTestdepsPackageAST(parsed); err != nil {
			return err, nil
		}
	case "testing":
		if err := verifyTestingPackageAST(lp.Files, parsed); err != nil {
			return err, nil
		}
	}
	return nil, nil
}

func verifyFileLinknameDirectives(pkgPath string, text string) error {
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSuffix(rawLine, "\r")
		if !strings.HasPrefix(line, "//go:") {
			continue
		}
		if strings.HasPrefix(line, "//go:wasmimport") {
			return fmt.Errorf("forbidden wasmimport directive %q", line)
		}
		if strings.HasPrefix(line, "//go:cgo_") {
			return fmt.Errorf("forbidden cgo directive %q", line)
		}
		if !strings.HasPrefix(line, "//go:linkname") {
			continue
		}
		_, plain := auditset.BoundedToken(line, "//go:linkname", " \t")
		_, std := auditset.BoundedToken(line, "//go:linknamestd", " \t")
		if !plain && !std {
			return fmt.Errorf("malformed linkname directive %q", line)
		}
		fields := strings.Fields(line)
		if len(fields) != 2 && len(fields) != 3 {
			return fmt.Errorf("invalid linkname directive arity %q", line)
		}
		if len(fields) == 2 {
			if !allowedPureSingleArgLinknames[pkgPath+"."+fields[1]] {
				return fmt.Errorf("unapproved single-argument linkname %q in %s", line, pkgPath)
			}
			continue
		}
		target := fields[2]
		if !strings.HasPrefix(target, pkgPath+".") && !allowedPureLinknameTargets[target] {
			return fmt.Errorf("unapproved pure-package linkname target %q", target)
		}
	}
	return nil
}

func isOSStderrSelector(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Stderr" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "os"
}

func verifyPurePackageAST(pkgPath string, files []*ast.File) error {
	for _, f := range files {
		var importsTime, importsMathRand, importsOS, importsRuntime, importsFmt, importsSyscall, importsWindows bool
		for _, imp := range f.Imports {
			importPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			if !allowedPurePackageImport(pkgPath, importPath) {
				return fmt.Errorf("%s: forbidden import %q in pure package", pkgPath, importPath)
			}
			switch importPath {
			case "time":
				if imp.Name != nil {
					return fmt.Errorf("%s: aliased import \"time\" (%s) forbidden in pure package", pkgPath, imp.Name.Name)
				}
				importsTime = true
			case "math/rand":
				if imp.Name != nil {
					return fmt.Errorf("%s: aliased import \"math/rand\" (%s) forbidden in pure package", pkgPath, imp.Name.Name)
				}
				importsMathRand = true
			case "os":
				if imp.Name != nil {
					return fmt.Errorf("%s: aliased import \"os\" (%s) forbidden in pure package", pkgPath, imp.Name.Name)
				}
				importsOS = true
			case "runtime":
				if imp.Name != nil {
					return fmt.Errorf("%s: aliased import \"runtime\" (%s) forbidden in pure package", pkgPath, imp.Name.Name)
				}
				importsRuntime = true
			case "fmt":
				if imp.Name != nil {
					return fmt.Errorf("%s: aliased import \"fmt\" (%s) forbidden in pure package", pkgPath, imp.Name.Name)
				}
				importsFmt = true
			case "syscall":
				if imp.Name != nil {
					return fmt.Errorf("%s: aliased import \"syscall\" (%s) forbidden in pure package", pkgPath, imp.Name.Name)
				}
				importsSyscall = true
			case "internal/syscall/windows":
				if imp.Name != nil {
					return fmt.Errorf("%s: aliased import \"internal/syscall/windows\" (%s) forbidden in pure package", pkgPath, imp.Name.Name)
				}
				importsWindows = true
			}
		}
		if importsTime || importsMathRand || importsOS || importsRuntime || importsFmt || importsSyscall || importsWindows {
			paramRandAllowed := map[*ast.SelectorExpr]bool{}
			allowedTimeUnixUTC := map[*ast.SelectorExpr]bool{}
			if importsMathRand {
				for _, decl := range f.Decls {
					fn, ok := decl.(*ast.FuncDecl)
					if !ok || fn.Type.Params == nil || fn.Body == nil {
						continue
					}
					var shadowsRand bool
					for _, field := range fn.Type.Params.List {
						for _, name := range field.Names {
							if name.Name == "rand" {
								shadowsRand = true
							}
						}
					}
					if shadowsRand {
						ast.Inspect(fn.Body, func(n ast.Node) bool {
							if sel, ok := n.(*ast.SelectorExpr); ok {
								if id, ok := sel.X.(*ast.Ident); ok && id.Name == "rand" {
									paramRandAllowed[sel] = true
								}
							}
							return true
						})
					}
				}
			}
			var violation error
			ast.Inspect(f, func(n ast.Node) bool {
				if violation != nil || n == nil {
					return false
				}
				switch node := n.(type) {
				case *ast.CallExpr:
					if importsTime && pkgPath == "encoding/json/v2" {
						if outerSel, ok := node.Fun.(*ast.SelectorExpr); ok && outerSel.Sel.Name == "UTC" && len(node.Args) == 0 {
							if innerCall, ok := outerSel.X.(*ast.CallExpr); ok {
								if innerSel, ok := innerCall.Fun.(*ast.SelectorExpr); ok && innerSel.Sel.Name == "Unix" {
									if id, ok := innerSel.X.(*ast.Ident); ok && id.Name == "time" {
										allowedTimeUnixUTC[innerSel] = true
									}
								}
							}
						}
					}
				case *ast.SelectorExpr:
					if id, ok := node.X.(*ast.Ident); ok {
						if importsTime && id.Name == "time" && forbiddenPureTimeSelectors[node.Sel.Name] && !allowedTimeUnixUTC[node] {
							violation = fmt.Errorf("%s: forbidden ambient time.%s reference", pkgPath, node.Sel.Name)
							return false
						}
						if importsMathRand && id.Name == "rand" && !allowedPureMathRandSelectors[node.Sel.Name] && !paramRandAllowed[node] {
							violation = fmt.Errorf("%s: forbidden global rand.%s reference", pkgPath, node.Sel.Name)
							return false
						}
						if importsRuntime && id.Name == "runtime" && !allowedPureRuntimeSelectors[node.Sel.Name] {
							violation = fmt.Errorf("%s: forbidden runtime.%s reference", pkgPath, node.Sel.Name)
							return false
						}
						if importsFmt && id.Name == "fmt" && forbiddenPureFmtSelectors[node.Sel.Name] {
							violation = fmt.Errorf("%s: forbidden ambient fmt.%s reference", pkgPath, node.Sel.Name)
							return false
						}
						if importsSyscall && id.Name == "syscall" && !allowedPureFilepathliteSyscallSelectors[node.Sel.Name] {
							violation = fmt.Errorf("%s: forbidden syscall.%s reference", pkgPath, node.Sel.Name)
							return false
						}
						if importsWindows && id.Name == "windows" && !allowedPureFilepathliteWindowsSelectors[node.Sel.Name] {
							violation = fmt.Errorf("%s: forbidden windows.%s reference", pkgPath, node.Sel.Name)
							return false
						}
						if importsOS && id.Name == "os" && node.Sel.Name != "Stderr" {
							violation = fmt.Errorf("%s: forbidden os.%s reference", pkgPath, node.Sel.Name)
							return false
						}
					}
					if importsOS && isOSStderrSelector(node.X) {
						violation = fmt.Errorf("%s: forbidden method or field access os.Stderr.%s", pkgPath, node.Sel.Name)
						return false
					}
				case *ast.AssignStmt:
					if importsOS {
						for _, lhs := range node.Lhs {
							if isOSStderrSelector(lhs) {
								violation = fmt.Errorf("%s: forbidden assignment to os.Stderr", pkgPath)
								return false
							}
						}
					}
				case *ast.UnaryExpr:
					if importsOS && node.Op == token.AND && isOSStderrSelector(node.X) {
						violation = fmt.Errorf("%s: forbidden address-of os.Stderr", pkgPath)
						return false
					}
				}
				return true
			})
			if violation != nil {
				return violation
			}
		}
	}
	return nil
}

func verifyOSPackageAST(files []*ast.File) error {
	var importsTestlog bool
	seenTestlog := map[string]bool{}
	var seenChdir bool
	requiredFuncHook := map[string]string{
		"Getenv":    "Getenv",
		"LookupEnv": "Getenv",
		"OpenFile":  "Open",
		"openDir":   "Open",
		"Stat":      "Stat",
		"Lstat":     "Stat",
		"Chdir":     "Chdir",
	}
	seenFunc := make(map[string]bool, len(requiredFuncHook))
	for _, f := range files {
		for _, imp := range f.Imports {
			if path, err := strconv.Unquote(imp.Path.Value); err == nil && path == "internal/testlog" {
				importsTestlog = true
			}
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			wantHook, tracked := requiredFuncHook[fn.Name.Name]
			if !tracked {
				continue
			}
			var foundHook, foundLogger, foundOpen bool
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "testlog" {
					if sel.Sel.Name == wantHook {
						foundHook = true
					}
					if sel.Sel.Name == "Logger" {
						foundLogger = true
					}
					if sel.Sel.Name == "Open" {
						foundOpen = true
					}
				}
				if wantHook == "Chdir" && sel.Sel.Name == "Chdir" {
					if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "syscall" {
						foundHook = true
					}
				}
				return true
			})
			if !foundHook || (wantHook == "Chdir" && (!foundLogger || !foundOpen)) {
				return fmt.Errorf("os: function %s missing required testlog.%s hook", fn.Name.Name, wantHook)
			}
			seenFunc[fn.Name.Name] = true
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "testlog" {
				seenTestlog[sel.Sel.Name] = true
			}
			if sel.Sel.Name == "Chdir" {
				if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "syscall" {
					seenChdir = true
				}
			}
			return true
		})
	}
	if !importsTestlog {
		return fmt.Errorf("os: missing internal/testlog import")
	}
	for _, fnName := range []string{"Getenv", "LookupEnv", "OpenFile", "openDir", "Stat", "Lstat", "Chdir"} {
		if !seenFunc[fnName] {
			return fmt.Errorf("os: missing boundary function %s", fnName)
		}
	}
	for _, required := range []string{"Open", "Stat", "Getenv", "Logger"} {
		if !seenTestlog[required] {
			return fmt.Errorf("os: missing testlog.%s hook", required)
		}
	}
	if !seenChdir {
		return fmt.Errorf("os: missing Chdir testlog hook")
	}
	return nil
}

func verifyTestdepsPackageAST(files []*ast.File) error {
	var importsTestlog, hasStart, hasStop, hasSetLogger, hasFlush bool
	for _, f := range files {
		for _, imp := range f.Imports {
			if path, err := strconv.Unquote(imp.Path.Value); err == nil && path == "internal/testlog" {
				importsTestlog = true
			}
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			switch fn.Name.Name {
			case "StartTestLog":
				hasStart = true
			case "StopTestLog":
				if fn.Type.Results != nil && len(fn.Type.Results.List) > 0 {
					hasStop = true
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "testlog" && sel.Sel.Name == "SetLogger" {
				hasSetLogger = true
			}
			if sel.Sel.Name == "Flush" {
				hasFlush = true
			}
			return true
		})
	}
	if !importsTestlog || !hasStart || !hasStop || !hasSetLogger || !hasFlush {
		return fmt.Errorf("testing/internal/testdeps: incomplete testlog harness wiring")
	}
	return nil
}

func isMethodCallNamed(expr ast.Expr, name string) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == name
}

func isDirectCallNamed(expr ast.Expr, name string) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	return ok && id.Name == name
}

func verifyTestingPackageAST(selectedFiles []string, files []*ast.File) error {
	var hasStartCall, hasWrappedStartCall, hasCheckedStopCall, hasDiscardedStopCall bool
	var hasDstStreamWrite, dstStreamWriteReturnsError, hasWriteFromBubble, writeFromBubbleChecksErr bool
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			switch fn.Name.Name {
			case "dstHostStreamWrite":
				hasDstStreamWrite = true
				if fn.Type.Results != nil && fn.Type.Results.NumFields() >= 2 {
					dstStreamWriteReturnsError = true
				}
			case "writeFromBubble":
				if fn.Body == nil {
					continue
				}
				hasWriteFromBubble = true
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					switch stmt := n.(type) {
					case *ast.AssignStmt:
						if len(stmt.Rhs) == 1 && isDirectCallNamed(stmt.Rhs[0], "dstHostStreamWrite") && len(stmt.Lhs) >= 2 {
							if id, ok := stmt.Lhs[1].(*ast.Ident); ok && id.Name != "_" {
								writeFromBubbleChecksErr = true
							}
						}
					case *ast.ReturnStmt:
						if len(stmt.Results) == 1 && isDirectCallNamed(stmt.Results[0], "dstHostStreamWrite") {
							writeFromBubbleChecksErr = true
						}
					}
					return true
				})
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch stmt := n.(type) {
			case *ast.ExprStmt:
				if isMethodCallNamed(stmt.X, "StartTestLog") {
					hasStartCall = true
					if call, ok := stmt.X.(*ast.CallExpr); ok && len(call.Args) == 1 && isDirectCallNamed(call.Args[0], "dstWrapTestlogWriter") {
						hasWrappedStartCall = true
					}
				}
				if isMethodCallNamed(stmt.X, "StopTestLog") {
					hasDiscardedStopCall = true
				}
			case *ast.AssignStmt:
				for i, rhs := range stmt.Rhs {
					if isMethodCallNamed(rhs, "StopTestLog") {
						if i < len(stmt.Lhs) {
							if id, ok := stmt.Lhs[i].(*ast.Ident); ok && id.Name != "_" {
								hasCheckedStopCall = true
							} else {
								hasDiscardedStopCall = true
							}
						}
					}
				}
			}
			return true
		})
	}
	if !hasStartCall || !hasCheckedStopCall || hasDiscardedStopCall {
		return fmt.Errorf("testing: missing or unchecked StartTestLog/StopTestLog calls")
	}
	if slices.Contains(selectedFiles, "dst_hostio.go") {
		if !hasDstStreamWrite {
			return fmt.Errorf("testing: dst_hostio.go missing dstHostStreamWrite")
		}
		if !hasWrappedStartCall || !hasWriteFromBubble || !writeFromBubbleChecksErr {
			return fmt.Errorf("testing: dst_hostio.go missing dstWrapTestlogWriter/writeFromBubble testlog wiring")
		}
	}
	if hasDstStreamWrite && !dstStreamWriteReturnsError {
		return fmt.Errorf("testing: dstHostStreamWrite drops test-log write errors")
	}
	return nil
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
	if listErr != nil {
		return selectionDegradation{
			fmt.Sprintf("the audited surface of %s could not be read: %v", version, listErr),
			"; the admission needs the toolchain's standard-library source listed and readable",
		}, nil
	}
	failed, ioErr, ctxErr := verifyToolchainSurfaceWithIO(ctx, d)
	if ctxErr != nil {
		return selectionDegradation{}, ctxErr
	}
	if ioErr != nil {
		return selectionDegradation{
			fmt.Sprintf("the audited surface of %s could not be read: %v", version, ioErr),
			"; the admission needs the toolchain's standard-library source listed and readable",
		}, nil
	}
	if len(failed) == 0 {
		return selectionDegradation{}, nil
	}
	return selectionDegradation{
		fmt.Sprintf("the audited surface of %s moved in %d keys: %s", version, len(failed), namedMoved(failed)),
		"; the admission needs every audited standard-library package to satisfy the structural source contracts",
	}, nil
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
	deg, err := toolchainSourceDegradationContext(ctx, snapshot.Value("GOVERSION"), d, listErr)
	if err != nil {
		return selectionDegradation{}, sourceDigests{}, err
	}
	return deg, d, nil
}

// ToolchainSelectionNoticeResolved answers the toolchain-source audit
// notice for a pass's selection — the explicit build flags under the
// environment the reader resolves, the surface read from its GOROOT —
// so a consumer can state the verdict at the tier where the selection
// was authored without re-deriving the key; empty exactly when the
// selection is admitted.
func ToolchainSelectionNoticeResolved(ctx context.Context, reader *gotool.EnvReader, buildFlags []string) (string, error) {
	if reader == nil {
		return "", fmt.Errorf("closure: nil environment reader")
	}
	verdict, _, err := resolveSelection(ctx, reader, buildFlags)
	if err != nil {
		return "", err
	}
	return verdict.notice(), nil
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
