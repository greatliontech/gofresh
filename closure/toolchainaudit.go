package closure

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/greatliontech/gofresh/closure/internal/cachefile"
	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/auditset"
)

// toolchainVerifierVersion versions the structural stdlib boundary verifier.
// Bumping this invalidates cached package verification verdicts and moves
// AdmissionPolicy.
const toolchainVerifierVersion = "gofresh/toolchain-verifier@17"

type verifiedPackageVerdict struct {
	OK                           bool                `json:"ok"`
	Delegates                    []string            `json:"delegates,omitempty"`
	InactiveRuntimeGates         map[string][]string `json:"inactiveRuntimeGates,omitempty"`
	RuntimeLinknamePulls         []string            `json:"runtimeLinknamePulls,omitempty"`
	ExternalLinknamePulls        []string            `json:"externalLinknamePulls,omitempty"`
	RequiredInactiveRuntimeGates []string            `json:"requiredInactiveRuntimeGates,omitempty"`
}

type offSurfaceCrossEdge struct {
	Pkg string `json:"pkg"`
	Sym string `json:"sym"`
}

type offSurfaceUnaliasedSel struct {
	Ident      string   `json:"ident"`
	Sel        string   `json:"sel"`
	Candidates []string `json:"candidates"`
}

type offSurfaceVerdict struct {
	PackageName        string                              `json:"packageName,omitempty"`
	DirectRuntimePulls []string                            `json:"directRuntimePulls,omitempty"`
	RuntimePullByDecl  map[string]string                   `json:"runtimePullByDecl,omitempty"`
	LocalEdges         map[string][]string                 `json:"localEdges,omitempty"`
	LocalSels          map[string][]string                 `json:"localSels,omitempty"`
	MethodsByType      map[string][]string                 `json:"methodsByType,omitempty"`
	CrossEdges         map[string][]offSurfaceCrossEdge    `json:"crossEdges,omitempty"`
	UnaliasedSels      map[string][]offSurfaceUnaliasedSel `json:"unaliasedSels,omitempty"`
	DotImports         []string                            `json:"dotImports,omitempty"`
	DotImportIdents    map[string][]string                 `json:"dotImportIdents,omitempty"`
	SeedDecls          []string                            `json:"seedDecls,omitempty"`
	SeedSels           []string                            `json:"seedSels,omitempty"`
	SeedCrossEdges     []offSurfaceCrossEdge               `json:"seedCrossEdges,omitempty"`
	SeedUnaliasedSels  []offSurfaceUnaliasedSel            `json:"seedUnaliasedSels,omitempty"`
	SeedDotIdents      []string                            `json:"seedDotIdents,omitempty"`
	DeclaredNames      []string                            `json:"declaredNames,omitempty"`
}

// verifiedPackageMemo caches structural verification verdicts per
// verifiedPackageMemoKey in memory.
var verifiedPackageMemo sync.Map

// verifiedPureDelegateMemo caches pure-delegate verification verdicts per
// verifiedPureDelegateMemoKeyWithPolicy in memory.
var verifiedPureDelegateMemo sync.Map

// verifiedOffSurfaceMemo caches off-surface runtime-pull/startup graphs per
// verifiedOffSurfaceMemoKeyWithPolicy in memory.
var verifiedOffSurfaceMemo sync.Map

// pkgIncludeHeaderCache caches GOROOT/pkg/include header contents keyed by
// goroot+"|"+pkgIncludeSalt when pkgIncludeSalt is non-empty.
var pkgIncludeHeaderCache sync.Map

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

func loadVerifiedPackageMemo(m *sync.Map, memoKey string) (verifiedPackageVerdict, bool) {
	v, ok := m.Load(memoKey)
	if !ok {
		return verifiedPackageVerdict{}, false
	}
	val, ok := v.(verifiedPackageVerdict)
	return val, ok
}

// allowedPureSupportImports lists the non-pure standard-library packages that a
// package in auditset.PurePackages() or its transitive pure delegates may
// import globally under a closed selector allowlist without becoming pure
// delegates themselves. Package-specific support imports are gated in
// isPureSupportImport with dedicated closed selector allowlists. Any other
// standard-library import from a pure or pure-delegate package is either
// explicitly forbidden or must itself verify transitively as a pure delegate.
var allowedPureSupportImports = map[string]bool{
	"crypto/internal/fips140": true,
	"fmt":                     true,
	"math":                    true,
	"reflect":                 true,
	"runtime":                 true,
	"sync":                    true,
	"sync/atomic":             true,
	"time":                    true,
}

// allowedPureCryptoInternalFIPS140Selectors lists the selectors on
// "crypto/internal/fips140" permitted in pure and pure-delegate packages.
var allowedPureCryptoInternalFIPS140Selectors = map[string]bool{
	"CAST":              true,
	"Enabled":           true,
	"Name":              true,
	"RecordApproved":    true,
	"RecordNonApproved": true,
	"Version":           true,
}

// allowedPureBoringCipherSelectors lists the pure interface types on
// "crypto/cipher" permitted in crypto/internal/boring without pulling
// crypto/cipher's entropy-bearing constructors into pure delegates.
var allowedPureBoringCipherSelectors = map[string]bool{
	"AEAD":  true,
	"Block": true,
}

// allowedPureFIPS140OnlyFIPSSelectors lists the selectors on "crypto/fips140"
// permitted in crypto/internal/fips140only.
var allowedPureFIPS140OnlyFIPSSelectors = map[string]bool{
	"Enforced": true,
}

// allowedPureFIPS140OnlyDRBGSelectors lists the type/predicate selectors on
// "crypto/internal/fips140/drbg" permitted in crypto/internal/fips140only
// (excluding entropy-reading drbg.Read).
var allowedPureFIPS140OnlyDRBGSelectors = map[string]bool{
	"DefaultReader":   true,
	"IsDefaultReader": true,
}

// allowedPureSHAGodebugSettings lists the hardware-acceleration toggle literals
// permitted in crypto/internal/fips140/sha256 and sha512 via
// crypto/internal/fips140deps/godebug.Value.
var allowedPureSHAGodebugSettings = map[string]bool{
	`"#ppc64sha2"`:   true,
	`"#ppc64sha512"`: true,
}

// allowedPureFmtSelectors lists the closed set of value-formatting and
// interface/scanner selectors on "fmt" permitted in pure and pure-delegate
// packages (excluding ambient stdio Print*, Scan*).
var allowedPureFmtSelectors = map[string]bool{
	"Append":       true,
	"Appendf":      true,
	"Appendln":     true,
	"Errorf":       true,
	"FormatString": true,
	"Formatter":    true,
	"Fprint":       true,
	"Fprintf":      true,
	"Fprintln":     true,
	"GoStringer":   true,
	"ScanState":    true,
	"Scanner":      true,
	"Sprint":       true,
	"Sprintf":      true,
	"Sprintln":     true,
	"Sscan":        true,
	"Sscanf":       true,
	"Sscanln":      true,
	"State":        true,
	"Stringer":     true,
}

// allowedPureMathSelectors lists the closed IEEE-754 bit/rounding/elementary
// selectors on "math" permitted in pure and pure-delegate packages (excluding
// platform-libm-sensitive transcendental functions).
var allowedPureMathSelectors = map[string]bool{
	"Abs":                    true,
	"Ceil":                   true,
	"Copysign":               true,
	"Float32bits":            true,
	"Float32frombits":        true,
	"Float64bits":            true,
	"Float64frombits":        true,
	"Floor":                  true,
	"Frexp":                  true,
	"Inf":                    true,
	"IsInf":                  true,
	"IsNaN":                  true,
	"Ldexp":                  true,
	"Log10":                  true,
	"Log2":                   true,
	"Max":                    true,
	"MaxFloat32":             true,
	"MaxFloat64":             true,
	"MaxInt":                 true,
	"MaxInt8":                true,
	"MaxInt16":               true,
	"MaxInt32":               true,
	"MaxInt64":               true,
	"MaxUint":                true,
	"MaxUint8":               true,
	"MaxUint16":              true,
	"MaxUint32":              true,
	"MaxUint64":              true,
	"Min":                    true,
	"MinInt":                 true,
	"MinInt8":                true,
	"MinInt16":               true,
	"MinInt32":               true,
	"MinInt64":               true,
	"Modf":                   true,
	"NaN":                    true,
	"Round":                  true,
	"RoundToEven":            true,
	"Signbit":                true,
	"SmallestNonzeroFloat32": true,
	"SmallestNonzeroFloat64": true,
	"Sqrt":                   true,
	"Trunc":                  true,
}

// allowedPureReflectSelectors lists the closed set of selectors on "reflect"
// permitted in pure and pure-delegate packages (excluding MakeFunc, Select, and
// reflective call/method-by-name dispatch).
var allowedPureReflectSelectors = map[string]bool{
	"Append":          true,
	"Array":           true,
	"Bool":            true,
	"Bytes":           true,
	"Chan":            true,
	"Complex128":      true,
	"Complex64":       true,
	"Copy":            true,
	"DeepEqual":       true,
	"Float32":         true,
	"Float64":         true,
	"Func":            true,
	"Indirect":        true,
	"Int":             true,
	"Int16":           true,
	"Int32":           true,
	"Int64":           true,
	"Int8":            true,
	"Interface":       true,
	"Invalid":         true,
	"Kind":            true,
	"MakeMap":         true,
	"MakeMapWithSize": true,
	"MakeSlice":       true,
	"Map":             true,
	"MapOf":           true,
	"New":             true,
	"Pointer":         true,
	"PointerTo":       true,
	"Ptr":             true,
	"Slice":           true,
	"SliceOf":         true,
	"String":          true,
	"Struct":          true,
	"StructField":     true,
	"StructTag":       true,
	"Type":            true,
	"TypeAssert":      true,
	"TypeFor":         true,
	"TypeOf":          true,
	"Uint":            true,
	"Uint16":          true,
	"Uint32":          true,
	"Uint64":          true,
	"Uint8":           true,
	"Uintptr":         true,
	"UnsafePointer":   true,
	"Value":           true,
	"ValueOf":         true,
	"Zero":            true,
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

// allowedPureSyncSelectors lists the closed set of synchronization primitives
// on "sync" permitted in pure and pure-delegate packages for internal memos and
// pools.
var allowedPureSyncSelectors = map[string]bool{
	"Cond":       true,
	"Locker":     true,
	"Map":        true,
	"Mutex":      true,
	"NewCond":    true,
	"Once":       true,
	"OnceFunc":   true,
	"OnceValue":  true,
	"OnceValues": true,
	"Pool":       true,
	"RWMutex":    true,
	"WaitGroup":  true,
}

// allowedPureSyncAtomicSelectors lists the closed set of primitives on
// "sync/atomic" permitted in pure and pure-delegate packages (excluding
// arbitrary-value atomic.Value and generic atomic.Pointer).
var allowedPureSyncAtomicSelectors = map[string]bool{
	"AddInt32":              true,
	"AddInt64":              true,
	"AddUint32":             true,
	"AddUint64":             true,
	"AddUintptr":            true,
	"Bool":                  true,
	"CompareAndSwapInt32":   true,
	"CompareAndSwapInt64":   true,
	"CompareAndSwapPointer": true,
	"CompareAndSwapUint32":  true,
	"CompareAndSwapUint64":  true,
	"CompareAndSwapUintptr": true,
	"Int32":                 true,
	"Int64":                 true,
	"LoadInt32":             true,
	"LoadInt64":             true,
	"LoadPointer":           true,
	"LoadUint32":            true,
	"LoadUint64":            true,
	"LoadUintptr":           true,
	"Uint32":                true,
	"Uint64":                true,
	"Uintptr":               true,
}

// allowedPureTimeSelectors lists the closed set of pure value, layout, and
// deterministic parsing selectors on "time" permitted in pure and pure-delegate
// packages (excluding Now, Since, Until, Local, LoadLocation*, timers, Sleep,
// and unchained Unix* local-zone constructors).
var allowedPureTimeSelectors = map[string]bool{
	"ANSIC":         true,
	"Date":          true,
	"DateOnly":      true,
	"DateTime":      true,
	"Duration":      true,
	"FixedZone":     true,
	"Hour":          true,
	"Kitchen":       true,
	"Layout":        true,
	"Location":      true,
	"Microsecond":   true,
	"Millisecond":   true,
	"Minute":        true,
	"Month":         true,
	"Nanosecond":    true,
	"Parse":         true,
	"ParseDuration": true,
	"ParseError":    true,
	"RFC1123":       true,
	"RFC1123Z":      true,
	"RFC3339":       true,
	"RFC3339Nano":   true,
	"RFC822":        true,
	"RFC822Z":       true,
	"RFC850":        true,
	"RubyDate":      true,
	"Second":        true,
	"Stamp":         true,
	"StampMicro":    true,
	"StampMilli":    true,
	"StampNano":     true,
	"Time":          true,
	"TimeOnly":      true,
	"UTC":           true,
	"UnixDate":      true,
	"Weekday":       true,
}

// allowedPureAsmStandardHeaders lists the standard Go assembler headers
// provided by GOROOT/pkg/include (plus compiler-generated go_asm.h) that an
// assembly file in a pure or pure-delegate package may #include.
var allowedPureAsmStandardHeaders = map[string]bool{
	"asm_amd64.h":   true,
	"asm_ppc64x.h":  true,
	"asm_riscv64.h": true,
	"funcdata.h":    true,
	"go_asm.h":      true,
	"textflag.h":    true,
}

// allowedPureAsmCrossPkgSymbols lists cross-package middle-dot symbol
// references permitted inside pure and pure-delegate assembly files beyond
// allowedPureSingleArgLinknames.
var allowedPureAsmCrossPkgSymbols = map[string]bool{
	"runtime.cmpstring":       true,
	"runtime.memequal":        true,
	"runtime.memequal_varlen": true,
	"runtime.memmove":         true,
}

// allowedPureLinknameTargets lists the two-argument //go:linkname and
// //go:linknamestd targets permitted inside auditset.PurePackages() and its
// transitive pure delegates beyond a package's own self-links.
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
// //go:linknamestd directives permitted inside auditset.PurePackages() and its
// transitive pure delegates.
var allowedPureSingleArgLinknames = map[string]bool{
	"bytes.Compare":                          true,
	"bytes.Equal":                            true,
	"bytes.IndexByte":                        true,
	"bytes.Repeat":                           true,
	"bytes.explode":                          true,
	"crypto/internal/fips140hash.sha3Unwrap": true,
	"crypto/subtle.setDITDisabled":           true,
	"crypto/subtle.setDITEnabled":            true,
	"internal/cpu.ARM":                       true,
	"internal/cpu.ARM64":                     true,
	"internal/cpu.HWCap":                     true,
	"internal/cpu.Loong64":                   true,
	"internal/cpu.MIPS64X":                   true,
	"internal/cpu.PPC64":                     true,
	"internal/cpu.RISCV64":                   true,
	"internal/cpu.S390X":                     true,
	"internal/cpu.X86":                       true,
	"internal/cpu.isProcessorFeaturePresent": true,
	"internal/cpu.riscvHWProbe":              true,
	"internal/cpu.sysctlEnabled":             true,
	"internal/race.Acquire":                  true,
	"internal/race.Disable":                  true,
	"internal/race.Enable":                   true,
	"internal/race.Errors":                   true,
	"internal/race.Read":                     true,
	"internal/race.ReadObjectPC":             true,
	"internal/race.ReadPC":                   true,
	"internal/race.ReadRange":                true,
	"internal/race.Release":                  true,
	"internal/race.ReleaseMerge":             true,
	"internal/race.Write":                    true,
	"internal/race.WriteObjectPC":            true,
	"internal/race.WritePC":                  true,
	"internal/race.WriteRange":               true,
	"math/big.addMulVVW":                     true,
	"math/big.addVV":                         true,
	"math/big.addVW":                         true,
	"math/big.mulAddVWW":                     true,
	"math/big.shlVU":                         true,
	"math/big.subVV":                         true,
	"math/big.subVW":                         true,
	"net/url.newError":                       true,
	"strconv.bsearch":                        true,
	"strings.IndexByte":                      true,
	"strings.clone":                          true,
	"strings.explode":                        true,
}

func isPureSupportImport(pkgPath, importPath string) bool {
	if importPath == "unsafe" || allowedPureSupportImports[importPath] {
		return true
	}
	switch pkgPath {
	case "crypto/internal/boring":
		return importPath == "crypto/cipher"
	case "crypto/internal/fips140only":
		return importPath == "crypto/fips140" || importPath == "crypto/internal/fips140/drbg"
	case "crypto/internal/fips140/sha256", "crypto/internal/fips140/sha512":
		return importPath == "crypto/internal/fips140deps/godebug"
	case "text/scanner":
		return importPath == "os"
	case "math/big":
		return importPath == "math/rand"
	case "internal/filepathlite":
		return importPath == "internal/syscall/windows" || importPath == "syscall"
	}
	return false
}

func forbiddenPureImport(pkgPath, importPath string) bool {
	if importPath == "" || importPath == "C" || strings.HasPrefix(importPath, ".") {
		return true
	}
	if first, _, _ := strings.Cut(importPath, "/"); strings.Contains(first, ".") {
		return true
	}
	if isPureSupportImport(pkgPath, importPath) || auditset.PurePackage(importPath) {
		return false
	}
	if isAlwaysExternalPackage(importPath) || classBPackages[importPath] {
		return true
	}
	if strings.HasPrefix(importPath, "runtime/") ||
		strings.HasPrefix(importPath, "os/") ||
		strings.HasPrefix(importPath, "syscall/") ||
		strings.HasPrefix(importPath, "internal/syscall/") ||
		strings.HasPrefix(importPath, "internal/runtime/syscall") {
		return true
	}
	switch importPath {
	case "crypto/cipher", "crypto/fips140", "crypto/internal/fips140/drbg",
		"crypto/internal/fips140deps/godebug", "flag", "internal/godebug",
		"log", "log/slog", "math/rand", "math/rand/v2", "testing":
		return true
	}
	return false
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
	pkgIncludeSalt := ""
	if rtLP, ok := d.inventory["runtime"]; ok {
		pkgIncludeSalt = rtLP.digest
	}
	rootDelegates := map[string][]string{}
	surfaceVerdicts := map[string]verifiedPackageVerdict{}
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
	externalLinknameSeeds := []offSurfaceCrossEdge{}
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
			if tPkg, tSym, ok := splitLinknameTarget(ext); ok {
				externalLinknameSeeds = append(externalLinknameSeeds, offSurfaceCrossEdge{Pkg: tPkg, Sym: tSym})
			}
		}
	}
	for delPkg := range pureDelegates {
		for _, sym := range delegateVerdicts[delPkg].RuntimeLinknamePulls {
			pulledRuntimeTargets[sym] = true
		}
		for _, ext := range delegateVerdicts[delPkg].ExternalLinknamePulls {
			if tPkg, tSym, ok := splitLinknameTarget(ext); ok {
				externalLinknameSeeds = append(externalLinknameSeeds, offSurfaceCrossEdge{Pkg: tPkg, Sym: tSym})
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
		return nil, pureDelegates, nil, nil
	}
	return sortedKeys(failedSet), nil, nil, nil
}

func verifyListedPackageMemoized(ctx context.Context, lp listedPackage, policy, pkgIncludeSalt string) (verifiedPackageVerdict, error) {
	if err := ctx.Err(); err != nil {
		return verifiedPackageVerdict{}, err
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
	memoKey := verifiedPackageMemoKeyWithPolicy(policy, lp.ImportPath, lp.digest, salt)
	cacheKey := lp.ImportPath + "|" + lp.digest
	if salt != "" {
		cacheKey += "|inc:" + salt
	}
	scope := "verified-package|" + toolchainVerifierVersion + "|" + policy
	if canMemo {
		if verdict, ok := loadVerifiedPackageMemo(&verifiedPackageMemo, memoKey); ok {
			return verdict, nil
		}
		var cached verifiedPackageVerdict
		if cachefile.Load(sourceDigestsDirName, scope, cacheKey, &cached) {
			verifiedPackageMemo.Store(memoKey, cached)
			return cached, nil
		}
	}
	verdict, verdictErr, ioErr := verifyListedPackageWithIOAndSalt(ctx, lp, pkgIncludeSalt)
	if ioErr != nil {
		return verifiedPackageVerdict{}, ioErr
	}
	if verdictErr != nil {
		verdict = verifiedPackageVerdict{OK: false}
	} else {
		verdict.OK = true
	}
	if canMemo {
		verifiedPackageMemo.Store(memoKey, verdict)
		if lp.digest != "" {
			cachefile.Store(sourceDigestsDirName, scope, cacheKey, verdict)
		}
	}
	return verdict, nil
}

func verifyPureDelegateMemoized(ctx context.Context, lp listedPackage, policy, pkgIncludeSalt string) (verifiedPackageVerdict, error) {
	if err := ctx.Err(); err != nil {
		return verifiedPackageVerdict{}, err
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
	memoKey := verifiedPureDelegateMemoKeyWithPolicy(policy, lp.ImportPath, lp.digest, salt)
	cacheKey := lp.ImportPath + "|" + lp.digest
	if salt != "" {
		cacheKey += "|inc:" + salt
	}
	scope := "verified-pure-delegate|" + toolchainVerifierVersion + "|" + policy
	if canMemo {
		if verdict, ok := loadVerifiedPackageMemo(&verifiedPureDelegateMemo, memoKey); ok {
			return verdict, nil
		}
		var cached verifiedPackageVerdict
		if cachefile.Load(sourceDigestsDirName, scope, cacheKey, &cached) {
			verifiedPureDelegateMemo.Store(memoKey, cached)
			return cached, nil
		}
	}
	verdict, verdictErr, ioErr := verifyPureCandidateWithIOAndSalt(ctx, lp, pkgIncludeSalt)
	if ioErr != nil {
		return verifiedPackageVerdict{}, ioErr
	}
	if verdictErr != nil {
		verdict = verifiedPackageVerdict{OK: false}
	} else {
		verdict.OK = true
	}
	if canMemo {
		verifiedPureDelegateMemo.Store(memoKey, verdict)
		if lp.digest != "" {
			cachefile.Store(sourceDigestsDirName, scope, cacheKey, verdict)
		}
	}
	return verdict, nil
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
	runtimePullTargets := map[string]bool{}
	externalPullTargets := map[string]bool{}
	var nonGoTexts []string
	for _, name := range append(slices.Clone(asmFiles), headerFiles...) {
		if err := ctx.Err(); err != nil {
			return verifiedPackageVerdict{}, nil, err
		}
		src, err := os.ReadFile(filepath.Join(lp.Dir, name))
		if err != nil {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		if len(asmFiles) > 0 {
			if err := verifyAssemblyFile(lp.ImportPath, name, string(src), selectedHeaders); err != nil {
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
		if scanPreprocessedNonGoSymbolRefs(lp.ImportPath, incHdrs, nonGoTexts, runtimePullTargets, externalPullTargets, nil) {
			return verifiedPackageVerdict{}, fmt.Errorf("%s: non-Go macro expansion budget exceeded", lp.ImportPath), nil
		}
	}

	fset := token.NewFileSet()
	parsed := make([]*ast.File, 0, len(goFiles))
	for _, name := range goFiles {
		if err := ctx.Err(); err != nil {
			return verifiedPackageVerdict{}, nil, err
		}
		src, err := os.ReadFile(filepath.Join(lp.Dir, name))
		if err != nil {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		text := string(src)
		if err := verifyFileLinknameDirectives(lp.ImportPath, text); err != nil {
			return verifiedPackageVerdict{}, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err), nil
		}
		if lp.ImportPath != "runtime" {
			collectGoLinknameTargets(lp.ImportPath, text, runtimePullTargets, externalPullTargets)
		}
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			return verifiedPackageVerdict{}, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err), nil
		}
		parsed = append(parsed, file)
	}
	if lp.digest != "" {
		curDigest, err := digestListedPackageUntraced(ctx, lp)
		if err != nil {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: %w", lp.ImportPath, err)
		}
		if curDigest != lp.digest {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: source moved during verification", lp.ImportPath)
		}
	}
	if err := verifyPurePackageAST(lp.ImportPath, parsed); err != nil {
		return verifiedPackageVerdict{}, err, nil
	}
	if lp.ImportPath == "bufio" {
		if err := verifyBufioWriterAST(parsed); err != nil {
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
			if !isPureSupportImport(lp.ImportPath, importPath) && !auditset.PurePackage(importPath) {
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
		} else if lp.ImportPath == "runtime" && allowedPureAsmStandardHeaders[name] {
			runtimeAsmHeaders = append(runtimeAsmHeaders, name)
		} else if lp.ImportPath == "os" || lp.ImportPath == "internal/testlog" || lp.ImportPath == "testing/internal/testdeps" || lp.ImportPath == "testing" {
			return verifiedPackageVerdict{}, fmt.Errorf("%s: unexpected non-Go file %s", lp.ImportPath, name), nil
		} else {
			nonGoFiles = append(nonGoFiles, name)
		}
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
			raw, err := os.ReadFile(filepath.Join(lp.Dir, name))
			if err != nil {
				return verifiedPackageVerdict{}, nil, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
			}
			if lp.ImportPath == "runtime" {
				if ext == ".syso" {
					collectRuntimeIdentsAndMachO(raw, runtimeNonGoIdents)
				} else {
					for _, joinSpace := range []bool{false, true} {
						stripped := stripAssemblyComments(string(raw), true, joinSpace)
						collectRuntimeIdentsAndMachO([]byte(stripped), runtimeNonGoIdents)
						collectRuntimeIdentsAndMachO([]byte(collapseTokenPasteOps(normalizeCStringLiterals(stripped, true))), runtimeNonGoIdents)
					}
					if ext == ".h" {
						runtimeIncludeHdrs = append(runtimeIncludeHdrs, string(raw))
					}
					runtimeNonGoTexts = append(runtimeNonGoTexts, string(raw))
				}
			} else {
				if ext == ".syso" {
					collectRawBytesRuntimeSymbolRefs(raw, runtimePullTargets)
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
			if scanPreprocessedNonGoSymbolRefs(lp.ImportPath, incHdrs, nonGoTexts, runtimePullTargets, externalPullTargets, nil) {
				return verifiedPackageVerdict{}, fmt.Errorf("%s: non-Go macro expansion budget exceeded", lp.ImportPath), nil
			}
		}
		if lp.digest != "" && len(nonGoFiles) > 0 {
			curDigest, err := digestListedPackageUntraced(ctx, lp)
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
		src, err := os.ReadFile(filepath.Join(lp.Dir, name))
		if err != nil {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		if err := verifyAssemblyFile("", lp.ImportPath+"/"+name, string(src), nil); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
		for _, joinSpace := range []bool{false, true} {
			stripped := stripAssemblyComments(string(src), true, joinSpace)
			collectRuntimeIdentsAndMachO([]byte(stripped), runtimeNonGoIdents)
			collectRuntimeIdentsAndMachO([]byte(collapseTokenPasteOps(normalizeCStringLiterals(stripped, true))), runtimeNonGoIdents)
		}
		if lp.ImportPath == "runtime" {
			runtimeIncludeHdrs = append(runtimeIncludeHdrs, string(src))
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
					src, err := os.ReadFile(fullPath)
					if err != nil {
						return verifiedPackageVerdict{}, nil, fmt.Errorf("pkg/include/%s: %w", rel, err)
					}
					if err := verifyAssemblyFile("", "pkg/include/"+rel, string(src), nil); err != nil {
						return verifiedPackageVerdict{}, err, nil
					}
					for _, joinSpace := range []bool{false, true} {
						stripped := stripAssemblyComments(string(src), true, joinSpace)
						collectRuntimeIdentsAndMachO([]byte(stripped), runtimeNonGoIdents)
						collectRuntimeIdentsAndMachO([]byte(collapseTokenPasteOps(normalizeCStringLiterals(stripped, true))), runtimeNonGoIdents)
					}
					runtimeIncludeHdrs = append(runtimeIncludeHdrs, string(src))
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
		src, err := os.ReadFile(filepath.Join(lp.Dir, name))
		if err != nil {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		text := string(src)
		if lp.ImportPath == "runtime" {
			runtimeGoSrcs = append(runtimeGoSrcs, text)
			collectGoLinknameTargets(lp.ImportPath, text, nil, externalPullTargets)
		} else {
			collectGoLinknameTargets(lp.ImportPath, text, runtimePullTargets, externalPullTargets)
		}
		if isHarnessPkg {
			if err := verifyHarnessFileDirectives(lp.ImportPath, text, runtimePullLinknames, selfPushLinknames, osRuntimePullMap, osAnyLinknameLocals); err != nil {
				return verifiedPackageVerdict{}, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err), nil
			}
		}
		mode := parser.Mode(0)
		if strings.Contains(text, `"C"`) {
			mode = parser.ParseComments
		}
		file, err := parser.ParseFile(fset, name, src, mode)
		if err != nil {
			return verifiedPackageVerdict{}, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err), nil
		}
		if mode == parser.ParseComments {
			preambles := extractFileCgoPreambles(file)
			if lp.ImportPath == "runtime" {
				runtimeNonGoTexts = append(runtimeNonGoTexts, preambles...)
			} else {
				nonGoTexts = append(nonGoTexts, preambles...)
			}
		}
		parsed = append(parsed, file)
	}
	if lp.ImportPath == "runtime" && len(runtimeNonGoTexts) > 0 {
		if scanPreprocessedNonGoSymbolRefs(lp.ImportPath, runtimeIncludeHdrs, runtimeNonGoTexts, nil, externalPullTargets, runtimeNonGoIdents) {
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
		if scanPreprocessedNonGoSymbolRefs(lp.ImportPath, incHdrs, nonGoTexts, runtimePullTargets, externalPullTargets, nil) {
			return verifiedPackageVerdict{}, fmt.Errorf("%s: non-Go macro expansion budget exceeded", lp.ImportPath), nil
		}
	}
	if lp.digest != "" {
		curDigest, err := digestListedPackageUntraced(ctx, lp)
		if err != nil {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: %w", lp.ImportPath, err)
		}
		if curDigest != lp.digest {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: source moved during verification", lp.ImportPath)
		}
	}

	switch lp.ImportPath {
	case "runtime":
		verdict.InactiveRuntimeGates = discoverRuntimeInactiveGates(parsed, runtimeGoSrcs, runtimeNonGoIdents)
	case "os":
		reqGates, err := verifyOSPackageAST(parsed, osRuntimePullMap, osAnyLinknameLocals)
		if err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
		verdict.RequiredInactiveRuntimeGates = reqGates
	case "internal/testlog":
		if err := verifyInternalTestlogPackageAST(parsed); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
	case "testing/internal/testdeps":
		if err := verifyTestdepsPackageAST(parsed); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
	case "testing":
		if err := verifyTestingPackageAST(parsed, runtimePullLinknames, selfPushLinknames); err != nil {
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
				if strings.HasPrefix(importPath, "internal/") && !forbiddenPureImport(lp.ImportPath, importPath) && !isPureSupportImport(lp.ImportPath, importPath) && !auditset.PurePackage(importPath) {
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

func scanGoDirectiveComments(src string, visit func(lit string) error) error {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var scanErr error
	var s scanner.Scanner
	s.Init(file, []byte(src), func(_ token.Position, msg string) {
		if scanErr == nil {
			scanErr = fmt.Errorf("scanner error: %s", msg)
		}
	}, scanner.ScanComments)
	for {
		_, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok != token.COMMENT {
			continue
		}
		if strings.HasPrefix(lit, "/*go:") {
			return fmt.Errorf("forbidden block compiler directive %q", lit)
		}
		if !strings.HasPrefix(lit, "//go:") {
			continue
		}
		line := strings.TrimSuffix(lit, "\r")
		if strings.ContainsRune(line, '\r') {
			return fmt.Errorf("malformed carriage return in compiler directive %q", line)
		}
		if err := visit(line); err != nil {
			return err
		}
	}
	return scanErr
}

var forbiddenOSLinknameLocals = map[string]bool{
	"Getenv": true, "LookupEnv": true, "Open": true, "Create": true,
	"OpenFile": true, "openDir": true, "ReadFile": true, "ReadDir": true,
	"Stat": true, "Lstat": true, "Chdir": true, "Getwd": true,
	"Write": true, "WriteString": true, "Close": true, "close": true,
	"write": true, "checkValid": true, "wrapErr": true, "fixCount": true,
	"writeLock": true, "writeUnlock": true, "decref": true, "destroy": true,
	"statNolog": true, "lstatNolog": true, "openFileNolog": true, "openDirNolog": true,
	"ErrInvalid": true, "ErrClosed": true, "Args": true, "Stdin": true, "Stdout": true, "Stderr": true,
	"Exit": true, "epipecheck": true, "sigpipe": true, "Fd": true, "fd": true,
	"NewFile": true, "newFile": true, "newFileFromNewFile": true, "open": true,
	"ignoringEINTR": true, "ignoringEINTR2": true, "fixLongPath": true,
	"statOrZero": true, "fstatNolog": true, "readFileContents": true, "NewSyscallError": true,
	"SameFile": true, "sameFile": true,
}

func verifyHarnessFileDirectives(pkgPath, text string, runtimePullLinknames, selfPushLinknames map[string]bool, osRuntimePullMap map[string]string, osAnyLinknameLocals map[string]bool) error {
	return scanGoDirectiveComments(text, func(line string) error {
		if strings.HasPrefix(line, "//go:wasmimport") {
			return fmt.Errorf("forbidden wasmimport directive %q", line)
		}
		if strings.HasPrefix(line, "//go:wasmexport") {
			return fmt.Errorf("forbidden wasmexport directive %q", line)
		}
		if strings.HasPrefix(line, "//go:cgo_") {
			return fmt.Errorf("forbidden cgo directive %q", line)
		}
		if !strings.HasPrefix(line, "//go:linkname") {
			return nil
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
		switch pkgPath {
		case "testing/internal/testdeps":
			return fmt.Errorf("forbidden linkname directive %q in %s", line, pkgPath)
		case "internal/testlog":
			if len(fields) != 2 || fields[1] != "SetPanicOnExit0" {
				return fmt.Errorf("unapproved linkname directive %q in %s", line, pkgPath)
			}
		case "os":
			localSym := fields[1]
			if strings.Contains(localSym, ".") || forbiddenOSLinknameLocals[localSym] {
				return fmt.Errorf("forbidden linkname on os boundary/sink symbol %q", localSym)
			}
			if osAnyLinknameLocals != nil {
				osAnyLinknameLocals[localSym] = true
			}
			if len(fields) == 3 {
				target := fields[2]
				if target == "runtime.exit" || target == "syscall.Exit" || target == "syscall.ExitProcess" || strings.HasSuffix(target, ".Exit") || strings.HasSuffix(target, ".exit") {
					return fmt.Errorf("forbidden exit linkname target %q in os", target)
				}
				allowedTarget := target == "os."+localSym ||
					strings.HasPrefix(target, "os/") ||
					strings.HasPrefix(target, "runtime.") ||
					strings.HasPrefix(target, "syscall.") ||
					strings.HasPrefix(target, "net.") ||
					(strings.HasPrefix(target, "internal/") && !strings.HasPrefix(target, "internal/testlog."))
				if !allowedTarget {
					return fmt.Errorf("unapproved linkname target %q in os", target)
				}
				if strings.HasPrefix(target, "runtime.") {
					runtimePullLinknames[localSym] = true
					if osRuntimePullMap != nil {
						if prev, exists := osRuntimePullMap[localSym]; exists && prev != target {
							return fmt.Errorf("conflicting runtime linkname target for %s in os", localSym)
						}
						osRuntimePullMap[localSym] = target
					}
				}
			}
		case "testing":
			if len(fields) != 3 {
				return fmt.Errorf("unapproved single-argument linkname %q in %s", line, pkgPath)
			}
			localSym, target := fields[1], fields[2]
			switch localSym {
			case "MainStart", "Main", "Init", "tRunner", "runTests", "runBenchmarks", "runExamples", "runFuzzTests", "runFuzzing":
				return fmt.Errorf("forbidden linkname on harness symbol %s", localSym)
			}
			switch {
			case (target == "testing."+localSym || (strings.HasPrefix(target, "testing/") && !strings.HasPrefix(target, "testing/internal/"))) && strings.HasSuffix(target, "."+localSym):
				selfPushLinknames[localSym] = true
			case strings.HasPrefix(target, "runtime.") && target != "runtime.exit":
				runtimePullLinknames[localSym] = true
			default:
				return fmt.Errorf("unapproved linkname target %q in %s", target, pkgPath)
			}
		}
		return nil
	})
}

func isASCIIIdentByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func collectAllASCIIIdents(raw []byte, out map[string]bool) {
	i := 0
	for i < len(raw) {
		if !isASCIIIdentByte(raw[i]) {
			i++
			continue
		}
		start := i
		for i < len(raw) && isASCIIIdentByte(raw[i]) {
			i++
		}
		out[string(raw[start:i])] = true
	}
}

func collectRawBytesRuntimeSymbolRefs(raw []byte, out map[string]bool) {
	for _, prefix := range []string{"runtime.", "runtime\xc2\xb7"} {
		pb := []byte(prefix)
		idx := 0
		for idx < len(raw) {
			pos := strings.Index(string(raw[idx:]), prefix)
			if pos < 0 {
				break
			}
			start := idx + pos + len(pb)
			end := start
			for end < len(raw) && isASCIIIdentByte(raw[end]) {
				end++
			}
			if end > start {
				out["runtime."+string(raw[start:end])] = true
			}
			idx = max(start, idx+pos+1)
		}
	}
}

func collectTextRuntimeSymbolRefs(text string, out map[string]bool) {
	collectRawBytesRuntimeSymbolRefs([]byte(text), out)
}

func collectGoRuntimeLinknameTargets(src string, out map[string]bool) {
	collectGoLinknameTargets("", src, out, nil)
}

func splitLinknameTarget(target string) (pkgPath, sym string, ok bool) {
	slash := strings.LastIndexByte(target, '/')
	dotRel := strings.IndexByte(target[slash+1:], '.')
	if dotRel <= 0 {
		return "", "", false
	}
	dot := slash + 1 + dotRel
	pkgPath = target[:dot]
	sym = target[dot+1:]
	if sym == "" {
		return "", "", false
	}
	return pkgPath, sym, true
}

func collectGoLinknameTargets(selfPkg, src string, runtimeOut, externalOut map[string]bool) {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, []byte(src), func(_ token.Position, _ string) {}, scanner.ScanComments)
	for {
		_, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok != token.COMMENT {
			continue
		}
		if strings.HasPrefix(lit, "/*go:linkname") {
			if runtimeOut != nil {
				runtimeOut["runtime.*"] = true
			}
			continue
		}
		if strings.HasPrefix(lit, "//go:cgo_") && runtimeOut != nil && (strings.Contains(lit, "runtime.") || strings.Contains(lit, "runtime\xc2\xb7")) {
			runtimeOut["runtime.*"] = true
			continue
		}
		if !strings.HasPrefix(lit, "//go:linkname") {
			continue
		}
		line := strings.TrimSuffix(lit, "\r")
		if strings.ContainsRune(line, '\r') {
			if runtimeOut != nil {
				runtimeOut["runtime.*"] = true
			}
			continue
		}
		_, plain := auditset.BoundedToken(line, "//go:linkname", " \t")
		_, std := auditset.BoundedToken(line, "//go:linknamestd", " \t")
		fields := strings.Fields(line)
		if (!plain && !std) || (len(fields) != 2 && len(fields) != 3) {
			if runtimeOut != nil {
				runtimeOut["runtime.*"] = true
			}
			continue
		}
		if len(fields) == 3 {
			target := fields[2]
			if strings.HasPrefix(target, "runtime.") {
				if runtimeOut != nil {
					runtimeOut[target] = true
				}
			} else if externalOut != nil {
				if tPkg, _, ok := splitLinknameTarget(target); ok && tPkg != selfPkg {
					externalOut[target] = true
				}
			}
		}
	}
}

func extractCgoPreamble(doc *ast.CommentGroup) string {
	if doc == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range doc.List {
		if strings.HasPrefix(c.Text, "//") {
			b.WriteString(c.Text[2:])
			b.WriteByte('\n')
		} else if strings.HasPrefix(c.Text, "/*") && strings.HasSuffix(c.Text, "*/") && len(c.Text) >= 4 {
			b.WriteString(c.Text[2 : len(c.Text)-2])
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func extractFileCgoPreambles(file *ast.File) []string {
	if file == nil {
		return nil
	}
	var out []string
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.IMPORT {
			continue
		}
		for _, spec := range gd.Specs {
			imp, ok := spec.(*ast.ImportSpec)
			if !ok || imp.Path == nil || imp.Path.Value != `"C"` {
				continue
			}
			cg := imp.Doc
			if cg == nil && len(gd.Specs) == 1 {
				cg = gd.Doc
			}
			if cg != nil {
				if p := extractCgoPreamble(cg); p != "" {
					out = append(out, p)
				}
			}
		}
	}
	return out
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
			return v.([]string), nil, nil
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

type cppMacroDef struct {
	hasParams     bool
	params        []string
	variadic      bool
	namedVarParam string
	body          string
}

func collectCPPMacrosFromText(cleaned string, defs map[string][]cppMacroDef) {
	for _, rawLine := range strings.Split(cleaned, "\n") {
		trimmed := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(trimmed, "#") {
			continue
		}
		dRest := strings.TrimSpace(trimmed[1:])
		if !strings.HasPrefix(dRest, "define") || (len(dRest) > 6 && dRest[6] != ' ' && dRest[6] != '\t') {
			continue
		}
		afterDef := strings.TrimSpace(dRest[6:])
		mEnd := 0
		for mEnd < len(afterDef) && (isASCIIIdentByte(afterDef[mEnd]) && (mEnd > 0 || (afterDef[mEnd] < '0' || afterDef[mEnd] > '9'))) {
			mEnd++
		}
		if mEnd == 0 {
			continue
		}
		name := afterDef[:mEnd]
		afterName := afterDef[mEnd:]
		var def cppMacroDef
		if strings.HasPrefix(afterName, "(") {
			closeIdx := strings.IndexByte(afterName, ')')
			if closeIdx < 0 {
				continue
			}
			def.hasParams = true
			paramList := strings.TrimSpace(afterName[1:closeIdx])
			if paramList != "" {
				for _, p := range strings.Split(paramList, ",") {
					p = strings.TrimSpace(p)
					if p == "..." {
						def.variadic = true
						continue
					}
					if strings.HasSuffix(p, "...") {
						p = strings.TrimSpace(strings.TrimSuffix(p, "..."))
						def.variadic = true
						def.namedVarParam = p
						continue
					}
					if p != "" {
						def.params = append(def.params, p)
					}
				}
			}
			def.body = strings.TrimSpace(afterName[closeIdx+1:])
		} else {
			def.body = strings.TrimSpace(afterName)
		}
		dup := false
		for _, prev := range defs[name] {
			if prev.hasParams == def.hasParams && prev.variadic == def.variadic && prev.namedVarParam == def.namedVarParam && prev.body == def.body && slices.Equal(prev.params, def.params) {
				dup = true
				break
			}
		}
		if !dup {
			defs[name] = append(defs[name], def)
		}
	}
}

func collapseTokenPasteOps(s string) string {
	for {
		idx := strings.Index(s, "##")
		if idx < 0 {
			return s
		}
		left := idx
		for left > 0 && (s[left-1] == ' ' || s[left-1] == '\t') {
			left--
		}
		right := idx + 2
		for right < len(s) && (s[right] == ' ' || s[right] == '\t') {
			right++
		}
		s = s[:left] + s[right:]
	}
}

func parseCPPMacroCallArgs(s string, openParenIdx int) (args []string, nextIdx int, ok bool) {
	if openParenIdx >= len(s) || s[openParenIdx] != '(' {
		return nil, 0, false
	}
	depth := 1
	curStart := openParenIdx + 1
	for i := openParenIdx + 1; i < len(s); i++ {
		switch s[i] {
		case '"', '\'':
			q := s[i]
			i++
			for i < len(s) && s[i] != q {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				i++
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				tail := strings.TrimSpace(s[curStart:i])
				if len(args) > 0 || tail != "" {
					args = append(args, tail)
				}
				return args, i + 1, true
			}
		case ',':
			if depth == 1 {
				args = append(args, strings.TrimSpace(s[curStart:i]))
				curStart = i + 1
			}
		}
	}
	return nil, 0, false
}

func cppStringizeArg(arg string) string {
	trimmed := strings.TrimSpace(arg)
	var b strings.Builder
	b.WriteByte('"')
	inSpace := false
	for i := 0; i < len(trimmed); i++ {
		ch := trimmed[i]
		if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
			inSpace = true
			continue
		}
		if inSpace {
			b.WriteByte(' ')
			inSpace = false
		}
		if ch == '\\' || ch == '"' {
			b.WriteByte('\\')
		}
		b.WriteByte(ch)
	}
	b.WriteByte('"')
	return b.String()
}

func isHexDigitByte(c byte) (uint32, bool) {
	switch {
	case c >= '0' && c <= '9':
		return uint32(c - '0'), true
	case c >= 'a' && c <= 'f':
		return uint32(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return uint32(c-'A') + 10, true
	default:
		return 0, false
	}
}

func matchCStringPrefixAt(s string, idx int) (quoteIdx int, ok bool) {
	if idx >= len(s) {
		return 0, false
	}
	if s[idx] == '"' {
		return idx, true
	}
	if idx > 0 && isASCIIIdentByte(s[idx-1]) {
		return 0, false
	}
	if idx+1 < len(s) && (s[idx] == 'L' || s[idx] == 'u' || s[idx] == 'U') && s[idx+1] == '"' {
		return idx + 1, true
	}
	if idx+2 < len(s) && s[idx] == 'u' && s[idx+1] == '8' && s[idx+2] == '"' {
		return idx + 2, true
	}
	return 0, false
}

func writeNormalizedCStringByte(b *strings.Builder, ch byte) {
	switch ch {
	case '"':
		b.WriteString(`\"`)
	case '\\':
		b.WriteString(`\\`)
	default:
		b.WriteByte(ch)
	}
}

func normalizeCStringLiterals(s string, allowNewlineConcat bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '\'' {
			b.WriteByte(s[i])
			i++
			for i < len(s) {
				b.WriteByte(s[i])
				if s[i] == '\\' && i+1 < len(s) {
					i++
					b.WriteByte(s[i])
					i++
					continue
				}
				if s[i] == '\'' {
					i++
					break
				}
				i++
			}
			continue
		}
		if qIdx, ok := matchCStringPrefixAt(s, i); ok {
			b.WriteByte('"')
			i = qIdx + 1
			for {
				for i < len(s) && s[i] != '"' {
					if s[i] != '\\' || i+1 >= len(s) {
						b.WriteByte(s[i])
						i++
						continue
					}
					esc := s[i+1]
					switch {
					case esc == 'x':
						j := i + 2
						var val uint32
						digits := 0
						for j < len(s) {
							d, okD := isHexDigitByte(s[j])
							if !okD {
								break
							}
							val = (val << 4) | d
							digits++
							j++
						}
						if digits > 0 {
							writeNormalizedCStringByte(&b, byte(val))
							i = j
							continue
						}
					case esc >= '0' && esc <= '7':
						j := i + 1
						var val uint32
						for k := 0; k < 3 && j < len(s) && s[j] >= '0' && s[j] <= '7'; k++ {
							val = (val << 3) | uint32(s[j]-'0')
							j++
						}
						writeNormalizedCStringByte(&b, byte(val))
						i = j
						continue
					case esc == 'u' || esc == 'U':
						want := 4
						if esc == 'U' {
							want = 8
						}
						if i+2+want <= len(s) {
							var val uint32
							okU := true
							for k := 0; k < want; k++ {
								d, okD := isHexDigitByte(s[i+2+k])
								if !okD {
									okU = false
									break
								}
								val = (val << 4) | d
							}
							if okU && utf8.ValidRune(rune(val)) {
								r := rune(val)
								if r == '"' {
									b.WriteString(`\"`)
								} else if r == '\\' {
									b.WriteString(`\\`)
								} else {
									b.WriteRune(r)
								}
								i += 2 + want
								continue
							}
						}
					}
					switch esc {
					case '"':
						b.WriteString(`\"`)
					case '\\':
						b.WriteString(`\\`)
					case '\'':
						b.WriteByte('\'')
					case '?':
						b.WriteByte('?')
					case 'n':
						b.WriteByte('\n')
					case 'r':
						b.WriteByte('\r')
					case 't':
						b.WriteByte('\t')
					case 'v':
						b.WriteByte('\v')
					case 'b':
						b.WriteByte('\b')
					case 'f':
						b.WriteByte('\f')
					case 'a':
						b.WriteByte('\a')
					default:
						b.WriteByte(esc)
					}
					i += 2
				}
				if i < len(s) && s[i] == '"' {
					i++
				}
				k := i
				for k < len(s) {
					if s[k] == ' ' || s[k] == '\t' {
						k++
						continue
					}
					if allowNewlineConcat && (s[k] == '\r' || s[k] == '\n') {
						k++
						continue
					}
					break
				}
				if nextQ, okNext := matchCStringPrefixAt(s, k); okNext {
					i = nextQ + 1
					continue
				}
				b.WriteByte('"')
				break
			}
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

const (
	maxNonGoLogicalLineBytes    = 1 << 20
	maxCPPExpandedStatesPerLine = 256
	maxCPPExpansionDepth        = 32
)

type cppExpandBudget struct {
	statesLeft int
	overflow   bool
}

type cppStateKey struct {
	text    string
	blocked string
	chosen  string
}

type cppWorkItem struct {
	text    string
	blocked string
	chosen  string
	depth   int
}

func lookupChosenMacro(chosen, name string) (int, bool) {
	if chosen == "" {
		return 0, false
	}
	needle := "|" + name + "="
	idx := strings.Index(chosen, needle)
	if idx < 0 {
		return 0, false
	}
	rest := chosen[idx+len(needle):]
	end := strings.IndexByte(rest, '|')
	if end < 0 {
		return 0, false
	}
	val, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0, false
	}
	return val, true
}

func addChosenMacro(chosen, name string, defIdx int) string {
	if _, ok := lookupChosenMacro(chosen, name); ok {
		return chosen
	}
	entry := name + "=" + strconv.Itoa(defIdx) + "|"
	if chosen == "" {
		return "|" + entry
	}
	return chosen + entry
}

func isBlockedMacro(blocked, name string) bool {
	return blocked != "" && strings.Contains(blocked, "|"+name+"|")
}

func addBlockedMacro(blocked, name string) string {
	if isBlockedMacro(blocked, name) {
		return blocked
	}
	if blocked == "" {
		return "|" + name + "|"
	}
	return blocked + name + "|"
}

func mergeBlockedMacros(a, b string) string {
	if b == "" {
		return a
	}
	if a == "" {
		return b
	}
	out := a
	for _, part := range strings.Split(b, "|") {
		if part != "" {
			out = addBlockedMacro(out, part)
		}
	}
	return out
}

func isPasteAdjacentInBody(body string, start, end int) bool {
	l := start
	for l > 0 && (body[l-1] == ' ' || body[l-1] == '\t') {
		l--
	}
	if l >= 2 && body[l-1] == '#' && body[l-2] == '#' {
		return true
	}
	r := end
	for r < len(body) && (body[r] == ' ' || body[r] == '\t') {
		r++
	}
	return r+1 < len(body) && body[r] == '#' && body[r+1] == '#'
}

func macroNormalParams(def cppMacroDef) map[string]bool {
	normal := map[string]bool{}
	body := def.body
	for i := 0; i < len(body); {
		if body[i] == '"' || body[i] == '\'' {
			q := body[i]
			i++
			for i < len(body) {
				if body[i] == '\\' && i+1 < len(body) {
					i += 2
					continue
				}
				if body[i] == q {
					i++
					break
				}
				i++
			}
			continue
		}
		if body[i] == '#' && (i+1 >= len(body) || body[i+1] != '#') && (i == 0 || body[i-1] != '#') {
			k := i + 1
			for k < len(body) && (body[k] == ' ' || body[k] == '\t') {
				k++
			}
			if k < len(body) && isASCIIIdentByte(body[k]) && (body[k] < '0' || body[k] > '9') {
				for k < len(body) && isASCIIIdentByte(body[k]) {
					k++
				}
				i = k
				continue
			}
		}
		if isASCIIIdentByte(body[i]) && (body[i] < '0' || body[i] > '9') {
			start := i
			for i < len(body) && isASCIIIdentByte(body[i]) {
				i++
			}
			if !isPasteAdjacentInBody(body, start, i) {
				normal[body[start:i]] = true
			}
			continue
		}
		i++
	}
	return normal
}

func bodyMacroRefs(def cppMacroDef, defs map[string][]cppMacroDef) []string {
	paramSet := make(map[string]bool, len(def.params)+2)
	for _, p := range def.params {
		paramSet[p] = true
	}
	if def.variadic {
		paramSet["__VA_ARGS__"] = true
		if def.namedVarParam != "" {
			paramSet[def.namedVarParam] = true
		}
	}
	var refs []string
	for _, scanBody := range []string{def.body, collapseTokenPasteOps(def.body)} {
		for i := 0; i < len(scanBody); {
			if scanBody[i] == '"' || scanBody[i] == '\'' {
				q := scanBody[i]
				i++
				for i < len(scanBody) {
					if scanBody[i] == '\\' && i+1 < len(scanBody) {
						i += 2
						continue
					}
					if scanBody[i] == q {
						i++
						break
					}
					i++
				}
				continue
			}
			if isASCIIIdentByte(scanBody[i]) && (scanBody[i] < '0' || scanBody[i] > '9') {
				start := i
				for i < len(scanBody) && isASCIIIdentByte(scanBody[i]) {
					i++
				}
				tok := scanBody[start:i]
				if !paramSet[tok] && len(defs[tok]) > 0 && !slices.Contains(refs, tok) {
					refs = append(refs, tok)
				}
				continue
			}
			i++
		}
	}
	return refs
}

func defReachesMacro(target string, startDef cppMacroDef, defs map[string][]cppMacroDef) bool {
	queue := bodyMacroRefs(startDef, defs)
	visited := map[string]bool{}
	for len(queue) > 0 {
		m := queue[0]
		queue = queue[1:]
		if m == target {
			return true
		}
		if visited[m] {
			continue
		}
		visited[m] = true
		for _, d := range defs[m] {
			for _, next := range bodyMacroRefs(d, defs) {
				if next == target {
					return true
				}
				if !visited[next] {
					queue = append(queue, next)
				}
			}
		}
	}
	return false
}

func substituteCPPMacroBody(def cppMacroDef, rawArgs, expArgs []string) string {
	if !def.hasParams {
		return collapseTokenPasteOps(def.body)
	}
	rawMap := make(map[string]string, len(def.params)+2)
	expMap := make(map[string]string, len(def.params)+2)
	for idx, p := range def.params {
		if idx < len(rawArgs) {
			rawMap[p] = rawArgs[idx]
		} else {
			rawMap[p] = ""
		}
		if idx < len(expArgs) {
			expMap[p] = expArgs[idx]
		} else {
			expMap[p] = ""
		}
	}
	if def.variadic {
		varKey := "__VA_ARGS__"
		if def.namedVarParam != "" {
			varKey = def.namedVarParam
		}
		if len(rawArgs) > len(def.params) {
			rawMap[varKey] = strings.Join(rawArgs[len(def.params):], ", ")
		} else {
			rawMap[varKey] = ""
		}
		if len(expArgs) > len(def.params) {
			expMap[varKey] = strings.Join(expArgs[len(def.params):], ", ")
		} else {
			expMap[varKey] = ""
		}
	}
	var b strings.Builder
	body := def.body
	for i := 0; i < len(body); {
		if body[i] == '"' || body[i] == '\'' {
			q := body[i]
			b.WriteByte(body[i])
			i++
			for i < len(body) {
				b.WriteByte(body[i])
				if body[i] == '\\' && i+1 < len(body) {
					i++
					b.WriteByte(body[i])
					i++
					continue
				}
				if body[i] == q {
					i++
					break
				}
				i++
			}
			continue
		}
		if body[i] == '#' && (i+1 >= len(body) || body[i+1] != '#') && (i == 0 || body[i-1] != '#') {
			k := i + 1
			for k < len(body) && (body[k] == ' ' || body[k] == '\t') {
				k++
			}
			if k < len(body) && isASCIIIdentByte(body[k]) && (body[k] < '0' || body[k] > '9') {
				mEnd := k
				for mEnd < len(body) && isASCIIIdentByte(body[mEnd]) {
					mEnd++
				}
				if rep, ok := rawMap[body[k:mEnd]]; ok {
					b.WriteString(cppStringizeArg(rep))
					i = mEnd
					continue
				}
			}
		}
		if isASCIIIdentByte(body[i]) && (body[i] < '0' || body[i] > '9') {
			start := i
			for i < len(body) && isASCIIIdentByte(body[i]) {
				i++
			}
			tok := body[start:i]
			if rawRep, ok := rawMap[tok]; ok {
				if isPasteAdjacentInBody(body, start, i) {
					b.WriteString(rawRep)
				} else {
					b.WriteString(expMap[tok])
				}
			} else {
				b.WriteString(tok)
			}
			continue
		}
		b.WriteByte(body[i])
		i++
	}
	return collapseTokenPasteOps(b.String())
}

func stepCPPPass(cur cppWorkItem, defs map[string][]cppMacroDef, budget *cppExpandBudget) ([]cppWorkItem, bool) {
	s := cur.text
	var prefix strings.Builder
	expandedAny := false
	passAddedBlocks := ""
	type candChoice struct {
		rep        string
		nextEnd    int
		addBlock   bool
		bindChoice bool
		choiceIdx  int
	}

	for i := 0; i < len(s); {
		if budget.overflow {
			return nil, false
		}
		if s[i] == '"' || s[i] == '\'' {
			q := s[i]
			prefix.WriteByte(s[i])
			i++
			for i < len(s) {
				prefix.WriteByte(s[i])
				if s[i] == '\\' && i+1 < len(s) {
					i++
					prefix.WriteByte(s[i])
					i++
					continue
				}
				if s[i] == q {
					i++
					break
				}
				i++
			}
			continue
		}
		if isASCIIIdentByte(s[i]) && (s[i] < '0' || s[i] > '9') {
			start := i
			for i < len(s) && isASCIIIdentByte(s[i]) {
				i++
			}
			tok := s[start:i]
			dList := defs[tok]
			hasMultiDefs := len(dList) > 1
			if hasMultiDefs {
				if cIdx, okC := lookupChosenMacro(cur.chosen, tok); okC {
					if cIdx < 0 || cIdx >= len(dList) {
						dList = nil
					} else {
						dList = dList[cIdx : cIdx+1]
						hasMultiDefs = false
					}
				}
			}
			if len(dList) == 0 || isBlockedMacro(cur.blocked, tok) || (len(dList) == 1 && !dList[0].hasParams && dList[0].body == tok) {
				prefix.WriteString(tok)
				continue
			}
			j := i
			for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r' || s[j] == '\n') {
				j++
			}
			rawArgs, afterClose, hasCall := parseCPPMacroCallArgs(s, j)

			var choices []candChoice
			hasNonApplicableFuncDef := false
			for dIdx, d := range dList {
				if !d.hasParams {
					choices = append(choices, candChoice{
						rep:        collapseTokenPasteOps(d.body),
						nextEnd:    i,
						addBlock:   defReachesMacro(tok, d, defs),
						bindChoice: hasMultiDefs,
						choiceIdx:  dIdx,
					})
					continue
				}
				if !hasCall {
					hasNonApplicableFuncDef = true
					continue
				}
				normal := macroNormalParams(d)
				argChoices := make([][]string, len(rawArgs))
				for k, rawArg := range rawArgs {
					isNormal := false
					if k < len(d.params) {
						isNormal = normal[d.params[k]]
					} else if d.variadic {
						isNormal = normal["__VA_ARGS__"] || (d.namedVarParam != "" && normal[d.namedVarParam])
					}
					if isNormal && rawArg != "" {
						if cur.depth+1 > maxCPPExpansionDepth {
							budget.overflow = true
							return nil, false
						}
						_, terms := expandCPPStatesWithBudget(rawArg, defs, cur.blocked, cur.chosen, cur.depth+1, budget)
						if budget.overflow {
							return nil, false
						}
						argChoices[k] = terms
					} else {
						argChoices[k] = []string{rawArg}
					}
				}
				tuples := [][]string{{}}
				for _, ac := range argChoices {
					if len(tuples)*max(len(ac), 1) > maxCPPExpandedStatesPerLine {
						budget.overflow = true
						return nil, false
					}
					nextTuples := make([][]string, 0, len(tuples)*max(len(ac), 1))
					for _, prev := range tuples {
						for _, val := range ac {
							cp := make([]string, len(prev)+1)
							copy(cp, prev)
							cp[len(prev)] = val
							nextTuples = append(nextTuples, cp)
						}
					}
					tuples = nextTuples
				}
				addBlk := defReachesMacro(tok, d, defs)
				for _, expArgs := range tuples {
					choices = append(choices, candChoice{
						rep:        substituteCPPMacroBody(d, rawArgs, expArgs),
						nextEnd:    afterClose,
						addBlock:   addBlk,
						bindChoice: hasMultiDefs,
						choiceIdx:  dIdx,
					})
				}
			}
			if len(choices) == 0 {
				prefix.WriteString(tok)
				continue
			}
			if hasNonApplicableFuncDef {
				choices = append(choices, candChoice{
					rep:        tok,
					nextEnd:    i,
					addBlock:   true,
					bindChoice: hasMultiDefs,
					choiceIdx:  -1,
				})
			}
			if cur.depth+1 > maxCPPExpansionDepth {
				budget.overflow = true
				return nil, false
			}
			if len(choices) == 1 {
				expandedAny = true
				prefix.WriteString(choices[0].rep)
				if choices[0].addBlock {
					passAddedBlocks = addBlockedMacro(passAddedBlocks, tok)
				}
				i = choices[0].nextEnd
				if prefix.Len() > maxNonGoLogicalLineBytes {
					budget.overflow = true
					return nil, false
				}
				continue
			}
			pfx := prefix.String()
			baseBlk := mergeBlockedMacros(cur.blocked, passAddedBlocks)
			children := make([]cppWorkItem, 0, len(choices))
			for _, ch := range choices {
				if len(pfx)+len(ch.rep)+len(s[ch.nextEnd:]) > maxNonGoLogicalLineBytes {
					budget.overflow = true
					return nil, false
				}
				nextText := collapseTokenPasteOps(pfx + ch.rep + s[ch.nextEnd:])
				if len(nextText) > maxNonGoLogicalLineBytes {
					budget.overflow = true
					return nil, false
				}
				nextBlk := baseBlk
				if ch.addBlock {
					nextBlk = addBlockedMacro(nextBlk, tok)
				}
				nextChosen := cur.chosen
				if ch.bindChoice {
					nextChosen = addChosenMacro(nextChosen, tok, ch.choiceIdx)
				}
				children = append(children, cppWorkItem{
					text:    nextText,
					blocked: nextBlk,
					chosen:  nextChosen,
					depth:   cur.depth + 1,
				})
			}
			return children, true
		}
		prefix.WriteByte(s[i])
		i++
	}
	if !expandedAny {
		return nil, false
	}
	nextText := collapseTokenPasteOps(prefix.String())
	if len(nextText) > maxNonGoLogicalLineBytes {
		budget.overflow = true
		return nil, false
	}
	nextBlk := mergeBlockedMacros(cur.blocked, passAddedBlocks)
	if nextText == cur.text && nextBlk == cur.blocked {
		return nil, false
	}
	return []cppWorkItem{{
		text:    nextText,
		blocked: nextBlk,
		chosen:  cur.chosen,
		depth:   cur.depth + 1,
	}}, true
}

func expandCPPStatesWithBudget(line string, defs map[string][]cppMacroDef, blocked, chosen string, startDepth int, budget *cppExpandBudget) (allStates []string, terminals []string) {
	if len(line) > maxNonGoLogicalLineBytes {
		budget.overflow = true
		return nil, nil
	}
	initKey := cppStateKey{text: line, blocked: blocked, chosen: chosen}
	seen := map[cppStateKey]bool{initKey: true}
	queue := []cppWorkItem{{text: line, blocked: blocked, chosen: chosen, depth: startDepth}}
	allSet := map[string]bool{}
	termSet := map[string]bool{}

	for len(queue) > 0 && !budget.overflow {
		cur := queue[0]
		queue = queue[1:]
		if !allSet[cur.text] {
			allSet[cur.text] = true
			allStates = append(allStates, cur.text)
		}
		children, expanded := stepCPPPass(cur, defs, budget)
		if budget.overflow {
			return nil, nil
		}
		if !expanded {
			if !termSet[cur.text] {
				termSet[cur.text] = true
				terminals = append(terminals, cur.text)
			}
			continue
		}
		for _, ch := range children {
			key := cppStateKey{text: ch.text, blocked: ch.blocked, chosen: ch.chosen}
			if seen[key] {
				continue
			}
			budget.statesLeft--
			if budget.statesLeft < 0 {
				budget.overflow = true
				return nil, nil
			}
			seen[key] = true
			queue = append(queue, ch)
		}
	}
	if len(terminals) == 0 && !budget.overflow {
		terminals = []string{line}
	}
	return allStates, terminals
}

func expandCPPLineAllChoices(line string, defs map[string][]cppMacroDef) (allStates []string, primary string, overflow bool) {
	budget := &cppExpandBudget{statesLeft: maxCPPExpandedStatesPerLine}
	all, terms := expandCPPStatesWithBudget(line, defs, "", "", 0, budget)
	if budget.overflow {
		return nil, "", true
	}
	prim := line
	if len(terms) > 0 {
		prim = terms[0]
	}
	return all, prim, false
}

func collapseAsmMiddleDotAndSlashSpaces(s string) string {
	s = strings.ReplaceAll(s, "∕", "/")
	for _, sep := range []string{"·", "/"} {
		for {
			prev := s
			s = strings.ReplaceAll(s, " "+sep, sep)
			s = strings.ReplaceAll(s, "\t"+sep, sep)
			s = strings.ReplaceAll(s, sep+" ", sep)
			s = strings.ReplaceAll(s, sep+"\t", sep)
			if s == prev {
				break
			}
		}
	}
	// Normalize Plan 9 pointer-receiver method syntax pkg·(*Type)·Method to pkg·Type·Method.
	searchFrom := 0
	for searchFrom < len(s) {
		rel := strings.Index(s[searchFrom:], "·(*")
		if rel < 0 {
			break
		}
		idx := searchFrom + rel
		rest := s[idx+len("·(*"):]
		end := 0
		for end < len(rest) && isASCIIIdentByte(rest[end]) {
			end++
		}
		if end == 0 || !strings.HasPrefix(rest[end:], ")·") {
			searchFrom = idx + len("·(*")
			continue
		}
		s = s[:idx] + "·" + rest[:end] + "·" + rest[end+len(")·"):]
		searchFrom = idx + len("·")
	}
	return s
}

func leadingASCIIIdent(s string) string {
	end := 0
	for end < len(s) && isASCIIIdentByte(s[end]) {
		end++
	}
	if end == 0 || (s[0] >= '0' && s[0] <= '9') {
		return ""
	}
	return s[:end]
}

func unescapeObjabiToken(s string) string {
	if strings.IndexByte(s, '%') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) {
			hi, okHi := isHexDigitByte(s[i+1])
			lo, okLo := isHexDigitByte(s[i+2])
			if okHi && okLo {
				b.WriteByte(byte((hi << 4) | lo))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func collectRuntimeIdentsAndMachO(data []byte, identOut map[string]bool) {
	if identOut == nil || len(data) == 0 {
		return
	}
	tmp := map[string]bool{}
	collectAllASCIIIdents(data, tmp)
	for id := range tmp {
		identOut[id] = true
		if trimmed := strings.TrimLeft(id, "_"); trimmed != "" && (trimmed[0] < '0' || trimmed[0] > '9') {
			identOut[trimmed] = true
		}
	}
}

func collectCStringSymbolRefs(s, selfPkg string, runtimeOut, externalOut, identOut map[string]bool) {
	if runtimeOut == nil && externalOut == nil && identOut == nil {
		return
	}
	recordTarget := func(pkgPrefix, sym string) {
		if pkgPrefix == "" || sym == "" {
			return
		}
		if pkgPrefix == "runtime" {
			base := leadingASCIIIdent(sym)
			if base != "" && runtimeOut != nil {
				runtimeOut["runtime."+base] = true
			}
		} else if externalOut != nil && pkgPrefix != selfPkg {
			externalOut[pkgPrefix+"."+sym] = true
		}
	}
	isSymRunByte := func(c byte) bool {
		return isASCIIIdentByte(c) || c == '/' || c == '.' || c == '-' || c == '%'
	}
	for i := 0; i < len(s); {
		if s[i] == '\'' {
			i++
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				if s[i] == '\'' {
					i++
					break
				}
				i++
			}
			continue
		}
		if s[i] != '"' {
			i++
			continue
		}
		i++
		var lit strings.Builder
		for i < len(s) && s[i] != '"' {
			if s[i] == '\\' && i+1 < len(s) {
				lit.WriteByte(s[i+1])
				i += 2
				continue
			}
			lit.WriteByte(s[i])
			i++
		}
		if i < len(s) && s[i] == '"' {
			i++
		}
		body := lit.String()
		if identOut != nil {
			collectRuntimeIdentsAndMachO([]byte(body), identOut)
			if unescBody := unescapeObjabiToken(body); unescBody != body {
				collectRuntimeIdentsAndMachO([]byte(unescBody), identOut)
			}
		}
		for j := 0; j < len(body); {
			if !isSymRunByte(body[j]) {
				j++
				continue
			}
			start := j
			for j < len(body) {
				if isSymRunByte(body[j]) {
					j++
					continue
				}
				if j > start && body[j-1] == '.' && strings.HasPrefix(body[j:], "(*") {
					tIdent := leadingASCIIIdent(body[j+2:])
					afterType := j + 2 + len(tIdent)
					if tIdent != "" && strings.HasPrefix(body[afterType:], ").") {
						j = afterType + 2
						continue
					}
				}
				break
			}
			rawTok := body[start:j]
			tokCands := []string{rawTok}
			if unesc := unescapeObjabiToken(rawTok); unesc != rawTok {
				tokCands = append(tokCands, unesc)
			}
			for _, tok := range tokCands {
				pkgPrefix, symPart, ok := splitLinknameTarget(tok)
				if !ok {
					continue
				}
				pkgPrefix = unescapeObjabiToken(strings.TrimLeft(pkgPrefix, "./"))
				symPart = unescapeObjabiToken(symPart)
				var syms []string
				if strings.HasPrefix(symPart, "(*") {
					tIdent := leadingASCIIIdent(symPart[2:])
					afterType := 2 + len(tIdent)
					if tIdent != "" && strings.HasPrefix(symPart[afterType:], ").") {
						mIdent := leadingASCIIIdent(symPart[afterType+2:])
						if mIdent != "" {
							syms = append(syms, tIdent, tIdent+"."+mIdent)
						}
					}
				} else if first := leadingASCIIIdent(symPart); first != "" {
					syms = append(syms, first)
					if len(symPart) > len(first) && symPart[len(first)] == '.' {
						if second := leadingASCIIIdent(symPart[len(first)+1:]); second != "" {
							syms = append(syms, first+"."+second)
						}
					}
				}
				for _, sym := range syms {
					recordTarget(pkgPrefix, sym)
					if machOPrefix := strings.TrimPrefix(pkgPrefix, "_"); machOPrefix != pkgPrefix {
						recordTarget(machOPrefix, sym)
					}
				}
			}
		}
	}
}

func extractExpandedLineSymbols(text, selfPkg string, runtimeOut, externalOut, identOut map[string]bool) {
	candidates := []string{text}
	if cNorm := normalizeCStringLiterals(text, true); cNorm != text {
		candidates = append(candidates, cNorm)
	}
	for _, cand := range candidates {
		if identOut != nil {
			collectRuntimeIdentsAndMachO([]byte(cand), identOut)
		}
		if runtimeOut != nil {
			collectRawBytesRuntimeSymbolRefs([]byte(cand), runtimeOut)
		}
		collectCStringSymbolRefs(cand, selfPkg, runtimeOut, externalOut, identOut)
		norm := collapseAsmMiddleDotAndSlashSpaces(cand)
		if identOut != nil {
			collectRuntimeIdentsAndMachO([]byte(norm), identOut)
		}
		if runtimeOut != nil {
			collectRawBytesRuntimeSymbolRefs([]byte(norm), runtimeOut)
		}
		collectCStringSymbolRefs(norm, selfPkg, runtimeOut, externalOut, identOut)
		runes := []rune(norm)
		for i := 0; i < len(runes); {
			if !isAsmWordRune(runes[i]) {
				i++
				continue
			}
			start := i
			for i < len(runes) && isAsmWordRune(runes[i]) {
				i++
			}
			tok := string(runes[start:i])
			if !strings.ContainsRune(tok, '·') {
				continue
			}
			pkgPrefix, symPart, _ := strings.Cut(tok, "·")
			pkgPrefix = strings.TrimLeft(pkgPrefix, "./")
			basePart, _, _ := strings.Cut(symPart, "<")
			baseSym := leadingASCIIIdent(basePart)
			if pkgPrefix == "" || baseSym == "" {
				continue
			}
			if pkgPrefix == "runtime" {
				if runtimeOut != nil {
					runtimeOut["runtime."+baseSym] = true
				}
			} else if externalOut != nil && pkgPrefix != selfPkg {
				externalOut[pkgPrefix+"."+baseSym] = true
				if afterDot, okSecond := strings.CutPrefix(basePart[len(baseSym):], "·"); okSecond {
					if secondSym := leadingASCIIIdent(afterDot); secondSym != "" {
						externalOut[pkgPrefix+"."+baseSym+"."+secondSym] = true
					}
				}
			}
		}
	}
}

func unquotedParenBalance(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"', '\'':
			q := s[i]
			i++
			for i < len(s) && s[i] != q {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				i++
			}
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		}
	}
	return depth
}

func trailingFuncMacroIdent(s string, defs map[string][]cppMacroDef) bool {
	if len(defs) == 0 {
		return false
	}
	end := len(s)
	for end > 0 && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	start := end
	for start > 0 && isASCIIIdentByte(s[start-1]) {
		start--
	}
	if start == end || (s[start] >= '0' && s[start] <= '9') {
		return false
	}
	for _, d := range defs[s[start:end]] {
		if d.hasParams {
			return true
		}
	}
	return false
}

func buildLogicalNonGoScanLines(cleaned string, defs map[string][]cppMacroDef) ([]string, string, bool) {
	rawLines := strings.Split(cleaned, "\n")
	out := make([]string, 0, len(rawLines))
	var nonDirective strings.Builder
	var pending string
	for idx := 0; idx < len(rawLines); idx++ {
		line := strings.TrimSpace(rawLines[idx])
		if line == "" {
			continue
		}
		if len(line) > maxNonGoLogicalLineBytes {
			return nil, "", true
		}
		if strings.HasPrefix(line, "#") {
			if pending != "" {
				out = append(out, pending)
				pending = ""
			}
			dRest := strings.TrimSpace(line[1:])
			if strings.HasPrefix(dRest, "define") && (len(dRest) == 6 || dRest[6] == ' ' || dRest[6] == '\t') {
				afterDef := strings.TrimSpace(dRest[6:])
				mEnd := 0
				for mEnd < len(afterDef) && isASCIIIdentByte(afterDef[mEnd]) {
					mEnd++
				}
				afterName := afterDef[mEnd:]
				var body string
				if strings.HasPrefix(afterName, "(") {
					if closeIdx := strings.IndexByte(afterName, ')'); closeIdx >= 0 {
						body = strings.TrimSpace(afterName[closeIdx+1:])
					}
				} else {
					body = strings.TrimSpace(afterName)
				}
				if body != "" {
					out = append(out, body)
				}
			}
			continue
		}
		nonDirective.WriteString(line)
		nonDirective.WriteByte('\n')
		if pending == "" {
			pending = line
		} else if len(pending)+1+len(line) <= maxNonGoLogicalLineBytes {
			pending = pending + " " + line
		} else {
			return nil, "", true
		}
		if unquotedParenBalance(pending) > 0 {
			continue
		}
		if trailingFuncMacroIdent(pending, defs) {
			peek := idx + 1
			for peek < len(rawLines) && strings.TrimSpace(rawLines[peek]) == "" {
				peek++
			}
			if peek < len(rawLines) && strings.HasPrefix(strings.TrimSpace(rawLines[peek]), "(") {
				continue
			}
		}
		out = append(out, pending)
		pending = ""
	}
	if pending != "" {
		out = append(out, pending)
	}
	return out, nonDirective.String(), false
}

func scanPreprocessedNonGoSymbolRefs(selfPkg string, includeHeaders, pkgTexts []string, runtimeOut, externalOut, identOut map[string]bool) bool {
	for _, joinSpace := range []bool{false, true} {
		defs := map[string][]cppMacroDef{}
		for _, hdr := range includeHeaders {
			collectCPPMacrosFromText(stripAssemblyComments(hdr, true, joinSpace), defs)
		}
		cleanedTexts := make([]string, len(pkgTexts))
		for idx, txt := range pkgTexts {
			cleaned := stripAssemblyComments(txt, true, joinSpace)
			cleanedTexts[idx] = cleaned
			collectCPPMacrosFromText(cleaned, defs)
		}
		for _, cleaned := range cleanedTexts {
			logicalLines, nonDirText, overflow := buildLogicalNonGoScanLines(cleaned, defs)
			if overflow {
				return true
			}
			if nonDirText != "" {
				extractExpandedLineSymbols(nonDirText, selfPkg, runtimeOut, externalOut, identOut)
			}
			expandedLines := make([]string, 0, len(logicalLines))
			for _, line := range logicalLines {
				if line == "" {
					continue
				}
				extractExpandedLineSymbols(line, selfPkg, runtimeOut, externalOut, identOut)
				if len(defs) == 0 {
					expandedLines = append(expandedLines, line)
					continue
				}
				states, primary, expOverflow := expandCPPLineAllChoices(line, defs)
				if expOverflow {
					return true
				}
				expandedLines = append(expandedLines, primary)
				for _, st := range states {
					if st != line {
						extractExpandedLineSymbols(st, selfPkg, runtimeOut, externalOut, identOut)
					}
				}
			}
			if len(expandedLines) > 1 {
				extractExpandedLineSymbols(strings.Join(expandedLines, "\n"), selfPkg, runtimeOut, externalOut, identOut)
			}
		}
	}
	return false
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

func verifyOffSurfacePackageMemoized(ctx context.Context, lp listedPackage, policy, pkgIncludeSalt string) (offSurfaceVerdict, error) {
	if err := ctx.Err(); err != nil {
		return offSurfaceVerdict{}, err
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
	memoKey := verifiedOffSurfaceMemoKeyWithPolicy(policy, lp.ImportPath, lp.digest, salt)
	cacheKey := lp.ImportPath + "|" + lp.digest
	if salt != "" {
		cacheKey += "|inc:" + salt
	}
	scope := "verified-offsurface|" + toolchainVerifierVersion + "|" + policy
	if canMemo {
		if v, ok := verifiedOffSurfaceMemo.Load(memoKey); ok {
			return v.(offSurfaceVerdict), nil
		}
		var cached offSurfaceVerdict
		if cachefile.Load(sourceDigestsDirName, scope, cacheKey, &cached) {
			verifiedOffSurfaceMemo.Store(memoKey, cached)
			return cached, nil
		}
	}
	verdict, ioErr := verifyOffSurfacePackageWithIO(ctx, lp, pkgIncludeSalt)
	if ioErr != nil {
		return offSurfaceVerdict{}, ioErr
	}
	if canMemo {
		verifiedOffSurfaceMemo.Store(memoKey, verdict)
		if lp.digest != "" {
			cachefile.Store(sourceDigestsDirName, scope, cacheKey, verdict)
		}
	}
	return verdict, nil
}

func verifyOffSurfacePackageWithIO(ctx context.Context, lp listedPackage, pkgIncludeSalt string) (offSurfaceVerdict, error) {
	if err := ctx.Err(); err != nil {
		return offSurfaceVerdict{}, err
	}
	if lp.Dir == "" {
		return offSurfaceVerdict{}, fmt.Errorf("%s: empty directory", lp.ImportPath)
	}
	var goFiles, nonGoFiles []string
	for _, name := range lp.Files {
		if strings.EqualFold(filepath.Ext(name), ".go") {
			goFiles = append(goFiles, name)
		} else {
			nonGoFiles = append(nonGoFiles, name)
		}
	}
	directRuntime := map[string]bool{}
	seedCrossMap := map[offSurfaceCrossEdge]bool{}
	var nonGoTexts []string
	for _, name := range nonGoFiles {
		ext := strings.ToLower(filepath.Ext(name))
		switch ext {
		case ".s", ".h", ".c", ".cc", ".cpp", ".cxx", ".m", ".syso":
			if err := ctx.Err(); err != nil {
				return offSurfaceVerdict{}, err
			}
			raw, err := os.ReadFile(filepath.Join(lp.Dir, name))
			if err != nil {
				return offSurfaceVerdict{}, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
			}
			if ext == ".syso" {
				collectRawBytesRuntimeSymbolRefs(raw, directRuntime)
			} else {
				nonGoTexts = append(nonGoTexts, string(raw))
			}
		}
	}

	type twoArgLink struct {
		localSym string
		target   string
	}
	var linkDirectives []twoArgLink
	fset := token.NewFileSet()
	parsed := make([]*ast.File, 0, len(goFiles))
	for _, name := range goFiles {
		if err := ctx.Err(); err != nil {
			return offSurfaceVerdict{}, err
		}
		src, err := os.ReadFile(filepath.Join(lp.Dir, name))
		if err != nil {
			return offSurfaceVerdict{}, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		text := string(src)
		scanOffSurfaceGoDirectives(text, directRuntime, func(localSym, target string) {
			linkDirectives = append(linkDirectives, twoArgLink{localSym: localSym, target: target})
		})
		mode := parser.Mode(0)
		if strings.Contains(text, `"C"`) {
			mode = parser.ParseComments
		}
		file, err := parser.ParseFile(fset, name, src, mode)
		if err != nil {
			// Unparseable off-surface Go file fails closed on runtime.*
			directRuntime["runtime.*"] = true
			continue
		}
		if mode == parser.ParseComments {
			nonGoTexts = append(nonGoTexts, extractFileCgoPreambles(file)...)
		}
		parsed = append(parsed, file)
	}
	if len(nonGoTexts) > 0 {
		extAsm := map[string]bool{}
		incHdrs, vErr, iErr := loadPkgIncludeHeadersForPackage(ctx, lp, pkgIncludeSalt)
		if iErr != nil {
			return offSurfaceVerdict{}, iErr
		}
		if vErr != nil {
			directRuntime["runtime.*"] = true
		} else {
			if scanPreprocessedNonGoSymbolRefs(lp.ImportPath, incHdrs, nonGoTexts, directRuntime, extAsm, nil) {
				directRuntime["runtime.*"] = true
			}
			for ext := range extAsm {
				if tPkg, tSym, ok := splitLinknameTarget(ext); ok && tPkg != lp.ImportPath {
					seedCrossMap[offSurfaceCrossEdge{Pkg: tPkg, Sym: tSym}] = true
				}
			}
		}
	}
	if lp.digest != "" {
		curDigest, err := digestListedPackageUntraced(ctx, lp)
		if err != nil {
			return offSurfaceVerdict{}, fmt.Errorf("%s: %w", lp.ImportPath, err)
		}
		if curDigest != lp.digest {
			return offSurfaceVerdict{}, fmt.Errorf("%s: source moved during verification", lp.ImportPath)
		}
	}

	out := offSurfaceVerdict{
		RuntimePullByDecl: map[string]string{},
		LocalEdges:        map[string][]string{},
		LocalSels:         map[string][]string{},
		MethodsByType:     map[string][]string{},
		CrossEdges:        map[string][]offSurfaceCrossEdge{},
		UnaliasedSels:     map[string][]offSurfaceUnaliasedSel{},
		DotImportIdents:   map[string][]string{},
	}
	declaredSet := map[string]bool{}
	bodylessFuncs := map[string]bool{}
	concreteFuncs := map[string]bool{}
	varDecls := map[string]bool{}
	methodsSet := map[string]map[string]bool{}

	for _, f := range parsed {
		if out.PackageName == "" && f.Name != nil {
			out.PackageName = f.Name.Name
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.ValueSpec:
						for _, id := range sp.Names {
							if id.Name != "_" && id.Name != "" {
								declaredSet[id.Name] = true
								if d.Tok == token.VAR {
									varDecls[id.Name] = true
								}
							}
						}
					case *ast.TypeSpec:
						if sp.Name != nil && sp.Name.Name != "_" && sp.Name.Name != "" {
							declaredSet[sp.Name.Name] = true
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name != nil && d.Name.Name != "init" && d.Name.Name != "_" {
					declaredSet[d.Name.Name] = true
					if d.Body == nil {
						bodylessFuncs[d.Name.Name] = true
					} else {
						concreteFuncs[d.Name.Name] = true
					}
				} else if d.Recv != nil && len(d.Recv.List) == 1 && d.Name != nil && d.Name.Name != "_" {
					rBase := recvBaseTypeName(d.Recv.List[0].Type)
					if rBase != "" {
						if methodsSet[rBase] == nil {
							methodsSet[rBase] = map[string]bool{}
						}
						methodsSet[rBase][d.Name.Name] = true
					}
				}
			}
		}
	}
	for rBase, mSet := range methodsSet {
		out.MethodsByType[rBase] = sortedKeys(mSet)
	}
	out.DeclaredNames = sortedKeys(declaredSet)

	seedDeclSet := map[string]bool{}
	for _, ld := range linkDirectives {
		tPkg, tSym, ok := splitLinknameTarget(ld.target)
		if !ok {
			if strings.HasPrefix(ld.target, "runtime") {
				directRuntime["runtime.*"] = true
			}
			continue
		}
		isPureBodylessPull := bodylessFuncs[ld.localSym] && !concreteFuncs[ld.localSym] && !varDecls[ld.localSym]
		if tPkg == "runtime" {
			if isPureBodylessPull {
				if prev, exists := out.RuntimePullByDecl[ld.localSym]; exists && prev != "runtime."+tSym {
					directRuntime["runtime."+prev[len("runtime."):]] = true
					directRuntime["runtime."+tSym] = true
				} else {
					out.RuntimePullByDecl[ld.localSym] = "runtime." + tSym
				}
			} else {
				directRuntime["runtime."+tSym] = true
				if declaredSet[ld.localSym] {
					seedDeclSet[ld.localSym] = true
				}
			}
			continue
		}
		if tPkg != lp.ImportPath {
			if isPureBodylessPull {
				out.CrossEdges[ld.localSym] = append(out.CrossEdges[ld.localSym], offSurfaceCrossEdge{Pkg: tPkg, Sym: tSym})
			} else {
				if declaredSet[ld.localSym] {
					seedDeclSet[ld.localSym] = true
				}
				if varDecls[ld.localSym] {
					seedCrossMap[offSurfaceCrossEdge{Pkg: tPkg, Sym: tSym}] = true
				}
			}
		}
	}

	localEdgeMap := map[string]map[string]bool{}
	localSelMap := map[string]map[string]bool{}
	crossEdgeMap := map[string]map[offSurfaceCrossEdge]bool{}
	unaliasedMap := map[string][]offSurfaceUnaliasedSel{}
	dotIdentsMap := map[string]map[string]bool{}
	dotImportsSet := map[string]bool{}

	seedSelsSet := map[string]bool{}
	var seedUnaliased []offSurfaceUnaliasedSel
	seedDotIdents := map[string]bool{}

	for k, list := range out.CrossEdges {
		if crossEdgeMap[k] == nil {
			crossEdgeMap[k] = map[offSurfaceCrossEdge]bool{}
		}
		for _, e := range list {
			crossEdgeMap[k][e] = true
		}
	}

	for _, f := range parsed {
		explicitImports := map[string]string{}
		var unaliasedImports []string
		var fileDotImports []string
		for _, imp := range f.Imports {
			if imp.Path == nil {
				continue
			}
			impPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil || impPath == "C" || impPath == "unsafe" {
				continue
			}
			if imp.Name != nil {
				switch imp.Name.Name {
				case "_":
					continue
				case ".":
					fileDotImports = append(fileDotImports, impPath)
					dotImportsSet[impPath] = true
				default:
					explicitImports[imp.Name.Name] = impPath
				}
			} else {
				unaliasedImports = append(unaliasedImports, impPath)
			}
		}

		walkOwner := func(owner string, isSeed bool, initScope map[string]bool, nodes ...ast.Node) {
			recIdent := func(name string) {
				if name == "" || name == "_" {
					return
				}
				if pkgPath, okE := explicitImports[name]; okE {
					_ = pkgPath
					return
				}
				if declaredSet[name] {
					if isSeed {
						seedDeclSet[name] = true
					} else if owner != "" {
						if localEdgeMap[owner] == nil {
							localEdgeMap[owner] = map[string]bool{}
						}
						localEdgeMap[owner][name] = true
					}
				} else if len(fileDotImports) > 0 {
					if isSeed {
						seedDotIdents[name] = true
					} else if owner != "" {
						if dotIdentsMap[owner] == nil {
							dotIdentsMap[owner] = map[string]bool{}
						}
						dotIdentsMap[owner][name] = true
					}
				}
			}
			recSel := func(sel string) {
				if sel == "" || sel == "_" {
					return
				}
				if isSeed {
					seedSelsSet[sel] = true
				} else if owner != "" {
					if localSelMap[owner] == nil {
						localSelMap[owner] = map[string]bool{}
					}
					localSelMap[owner][sel] = true
				}
			}
			recQual := func(base, sel string) {
				if pkgPath, okE := explicitImports[base]; okE {
					ce := offSurfaceCrossEdge{Pkg: pkgPath, Sym: sel}
					if isSeed {
						seedCrossMap[ce] = true
					} else if owner != "" {
						if crossEdgeMap[owner] == nil {
							crossEdgeMap[owner] = map[offSurfaceCrossEdge]bool{}
						}
						crossEdgeMap[owner][ce] = true
					}
					return
				}
				recIdent(base)
				recSel(sel)
				if len(unaliasedImports) > 0 {
					u := offSurfaceUnaliasedSel{Ident: base, Sel: sel, Candidates: slices.Clone(unaliasedImports)}
					if isSeed {
						seedUnaliased = append(seedUnaliased, u)
					} else if owner != "" {
						unaliasedMap[owner] = append(unaliasedMap[owner], u)
					}
				}
			}
			scope := maps.Clone(initScope)
			if scope == nil {
				scope = map[string]bool{}
			}
			for _, nd := range nodes {
				if nd != nil {
					walkOffSurfaceAST(nd, scope, recIdent, recSel, recQual)
				}
			}
		}

		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.ValueSpec:
						if d.Tok == token.VAR && len(sp.Values) > 0 {
							for _, id := range sp.Names {
								if id.Name != "_" && id.Name != "" {
									seedDeclSet[id.Name] = true
								}
							}
							var nodes []ast.Node
							if sp.Type != nil {
								nodes = append(nodes, sp.Type)
							}
							for _, v := range sp.Values {
								nodes = append(nodes, v)
							}
							walkOwner("", true, nil, nodes...)
						}
						for idx, id := range sp.Names {
							if id.Name == "_" || id.Name == "" {
								continue
							}
							var nodes []ast.Node
							if sp.Type != nil {
								nodes = append(nodes, sp.Type)
							}
							if idx < len(sp.Values) {
								nodes = append(nodes, sp.Values[idx])
							} else if len(sp.Values) == 1 {
								nodes = append(nodes, sp.Values[0])
							}
							walkOwner(id.Name, false, nil, nodes...)
						}
					case *ast.TypeSpec:
						if sp.Name != nil && sp.Name.Name != "_" && sp.Name.Name != "" {
							tScope := map[string]bool{}
							if sp.TypeParams != nil {
								for _, fld := range sp.TypeParams.List {
									for _, id := range fld.Names {
										if id.Name != "_" && id.Name != "" {
											tScope[id.Name] = true
										}
									}
								}
							}
							walkOwner(sp.Name.Name, false, tScope, sp.Type)
						}
					}
				}
			case *ast.FuncDecl:
				if d.Name == nil {
					continue
				}
				fnScope := map[string]bool{}
				addFieldNames := func(fl *ast.FieldList) {
					if fl == nil {
						return
					}
					for _, fld := range fl.List {
						for _, id := range fld.Names {
							if id.Name != "_" && id.Name != "" {
								fnScope[id.Name] = true
							}
						}
					}
				}
				isInit := d.Recv == nil && d.Name.Name == "init"
				owner := ""
				if !isInit {
					if d.Recv == nil {
						if d.Name.Name == "_" {
							continue
						}
						owner = d.Name.Name
					} else if len(d.Recv.List) == 1 && d.Name.Name != "_" {
						rBase := recvBaseTypeName(d.Recv.List[0].Type)
						if rBase == "" {
							continue
						}
						owner = "method:" + rBase + "." + d.Name.Name
					} else {
						continue
					}
				}
				// Walk signature types before binding parameter/result names so type names resolve at package scope.
				typeScope := map[string]bool{}
				if d.Type != nil && d.Type.TypeParams != nil {
					for _, fld := range d.Type.TypeParams.List {
						for _, id := range fld.Names {
							if id.Name != "_" && id.Name != "" {
								typeScope[id.Name] = true
							}
						}
					}
				}
				var sigNodes []ast.Node
				for _, fl := range []*ast.FieldList{d.Recv, d.Type.Params, d.Type.Results} {
					if fl != nil {
						for _, fld := range fl.List {
							if fld.Type != nil {
								sigNodes = append(sigNodes, fld.Type)
							}
						}
					}
				}
				walkOwner(owner, isInit, typeScope, sigNodes...)
				maps.Copy(fnScope, typeScope)
				addFieldNames(d.Recv)
				addFieldNames(d.Type.Params)
				addFieldNames(d.Type.Results)
				if d.Body != nil {
					walkOwner(owner, isInit, fnScope, d.Body)
				}
			}
		}
	}

	if len(directRuntime) > 0 {
		out.DirectRuntimePulls = sortedKeys(directRuntime)
	}
	for k, m := range localEdgeMap {
		out.LocalEdges[k] = sortedKeys(m)
	}
	for k, m := range localSelMap {
		out.LocalSels[k] = sortedKeys(m)
	}
	out.CrossEdges = map[string][]offSurfaceCrossEdge{}
	for k, m := range crossEdgeMap {
		list := make([]offSurfaceCrossEdge, 0, len(m))
		for e := range m {
			list = append(list, e)
		}
		slices.SortFunc(list, func(a, b offSurfaceCrossEdge) int {
			if c := strings.Compare(a.Pkg, b.Pkg); c != 0 {
				return c
			}
			return strings.Compare(a.Sym, b.Sym)
		})
		out.CrossEdges[k] = list
	}
	out.UnaliasedSels = unaliasedMap
	if len(dotImportsSet) > 0 {
		out.DotImports = sortedKeys(dotImportsSet)
	}
	for k, m := range dotIdentsMap {
		out.DotImportIdents[k] = sortedKeys(m)
	}
	if len(seedDeclSet) > 0 {
		out.SeedDecls = sortedKeys(seedDeclSet)
	}
	if len(seedSelsSet) > 0 {
		out.SeedSels = sortedKeys(seedSelsSet)
	}
	if len(seedCrossMap) > 0 {
		list := make([]offSurfaceCrossEdge, 0, len(seedCrossMap))
		for e := range seedCrossMap {
			list = append(list, e)
		}
		slices.SortFunc(list, func(a, b offSurfaceCrossEdge) int {
			if c := strings.Compare(a.Pkg, b.Pkg); c != 0 {
				return c
			}
			return strings.Compare(a.Sym, b.Sym)
		})
		out.SeedCrossEdges = list
	}
	out.SeedUnaliasedSels = seedUnaliased
	if len(seedDotIdents) > 0 {
		out.SeedDotIdents = sortedKeys(seedDotIdents)
	}
	return out, nil
}

func scanOffSurfaceGoDirectives(src string, directRuntime map[string]bool, onTwoArgLink func(localSym, target string)) {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, []byte(src), func(_ token.Position, _ string) {}, scanner.ScanComments)
	for {
		_, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok != token.COMMENT {
			continue
		}
		if strings.HasPrefix(lit, "/*go:linkname") {
			directRuntime["runtime.*"] = true
			continue
		}
		if strings.HasPrefix(lit, "//go:cgo_") && (strings.Contains(lit, "runtime.") || strings.Contains(lit, "runtime\xc2\xb7")) {
			directRuntime["runtime.*"] = true
			continue
		}
		if !strings.HasPrefix(lit, "//go:linkname") {
			continue
		}
		line := strings.TrimSuffix(lit, "\r")
		if strings.ContainsRune(line, '\r') {
			directRuntime["runtime.*"] = true
			continue
		}
		_, plain := auditset.BoundedToken(line, "//go:linkname", " \t")
		_, std := auditset.BoundedToken(line, "//go:linknamestd", " \t")
		fields := strings.Fields(line)
		if (!plain && !std) || (len(fields) != 2 && len(fields) != 3) {
			directRuntime["runtime.*"] = true
			continue
		}
		if len(fields) == 3 {
			onTwoArgLink(fields[1], fields[2])
		}
	}
}

func walkOffSurfaceAST(node ast.Node, scope map[string]bool, recIdent, recSel func(string), recQual func(base, sel string)) {
	if node == nil {
		return
	}
	switch n := node.(type) {
	case *ast.BlockStmt:
		sub := maps.Clone(scope)
		for _, st := range n.List {
			walkOffSurfaceAST(st, sub, recIdent, recSel, recQual)
		}
	case *ast.IfStmt:
		sub := maps.Clone(scope)
		if n.Init != nil {
			walkOffSurfaceAST(n.Init, sub, recIdent, recSel, recQual)
		}
		walkOffSurfaceAST(n.Cond, sub, recIdent, recSel, recQual)
		walkOffSurfaceAST(n.Body, sub, recIdent, recSel, recQual)
		if n.Else != nil {
			walkOffSurfaceAST(n.Else, sub, recIdent, recSel, recQual)
		}
	case *ast.ForStmt:
		sub := maps.Clone(scope)
		if n.Init != nil {
			walkOffSurfaceAST(n.Init, sub, recIdent, recSel, recQual)
		}
		if n.Cond != nil {
			walkOffSurfaceAST(n.Cond, sub, recIdent, recSel, recQual)
		}
		if n.Post != nil {
			walkOffSurfaceAST(n.Post, sub, recIdent, recSel, recQual)
		}
		walkOffSurfaceAST(n.Body, sub, recIdent, recSel, recQual)
	case *ast.RangeStmt:
		walkOffSurfaceAST(n.X, scope, recIdent, recSel, recQual)
		sub := maps.Clone(scope)
		if n.Tok == token.DEFINE {
			for _, e := range []ast.Expr{n.Key, n.Value} {
				if id, ok := unwrapParens(e).(*ast.Ident); ok && id.Name != "_" && id.Name != "" {
					sub[id.Name] = true
				}
			}
		} else {
			if n.Key != nil {
				walkOffSurfaceAST(n.Key, sub, recIdent, recSel, recQual)
			}
			if n.Value != nil {
				walkOffSurfaceAST(n.Value, sub, recIdent, recSel, recQual)
			}
		}
		walkOffSurfaceAST(n.Body, sub, recIdent, recSel, recQual)
	case *ast.SwitchStmt:
		sub := maps.Clone(scope)
		if n.Init != nil {
			walkOffSurfaceAST(n.Init, sub, recIdent, recSel, recQual)
		}
		if n.Tag != nil {
			walkOffSurfaceAST(n.Tag, sub, recIdent, recSel, recQual)
		}
		if n.Body != nil {
			for _, st := range n.Body.List {
				walkOffSurfaceAST(st, maps.Clone(sub), recIdent, recSel, recQual)
			}
		}
	case *ast.TypeSwitchStmt:
		sub := maps.Clone(scope)
		if n.Init != nil {
			walkOffSurfaceAST(n.Init, sub, recIdent, recSel, recQual)
		}
		if as, ok := n.Assign.(*ast.AssignStmt); ok && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			walkOffSurfaceAST(as.Rhs[0], sub, recIdent, recSel, recQual)
			if id, okID := unwrapParens(as.Lhs[0]).(*ast.Ident); okID && id.Name != "_" && id.Name != "" {
				sub[id.Name] = true
			}
		} else if n.Assign != nil {
			walkOffSurfaceAST(n.Assign, sub, recIdent, recSel, recQual)
		}
		if n.Body != nil {
			for _, st := range n.Body.List {
				walkOffSurfaceAST(st, maps.Clone(sub), recIdent, recSel, recQual)
			}
		}
	case *ast.SelectStmt:
		if n.Body != nil {
			for _, st := range n.Body.List {
				walkOffSurfaceAST(st, maps.Clone(scope), recIdent, recSel, recQual)
			}
		}
	case *ast.CaseClause:
		for _, e := range n.List {
			walkOffSurfaceAST(e, scope, recIdent, recSel, recQual)
		}
		sub := maps.Clone(scope)
		for _, st := range n.Body {
			walkOffSurfaceAST(st, sub, recIdent, recSel, recQual)
		}
	case *ast.CommClause:
		sub := maps.Clone(scope)
		if n.Comm != nil {
			walkOffSurfaceAST(n.Comm, sub, recIdent, recSel, recQual)
		}
		for _, st := range n.Body {
			walkOffSurfaceAST(st, sub, recIdent, recSel, recQual)
		}
	case *ast.AssignStmt:
		for _, rhs := range n.Rhs {
			walkOffSurfaceAST(rhs, scope, recIdent, recSel, recQual)
		}
		if n.Tok == token.DEFINE {
			for _, lhs := range n.Lhs {
				if id, ok := unwrapParens(lhs).(*ast.Ident); ok {
					if id.Name != "_" && id.Name != "" {
						scope[id.Name] = true
					}
				} else {
					walkOffSurfaceAST(lhs, scope, recIdent, recSel, recQual)
				}
			}
		} else {
			for _, lhs := range n.Lhs {
				walkOffSurfaceAST(lhs, scope, recIdent, recSel, recQual)
			}
		}
	case *ast.DeclStmt:
		if gd, ok := n.Decl.(*ast.GenDecl); ok {
			for _, spec := range gd.Specs {
				switch sp := spec.(type) {
				case *ast.ValueSpec:
					if sp.Type != nil {
						walkOffSurfaceAST(sp.Type, scope, recIdent, recSel, recQual)
					}
					for _, v := range sp.Values {
						walkOffSurfaceAST(v, scope, recIdent, recSel, recQual)
					}
					for _, id := range sp.Names {
						if id.Name != "_" && id.Name != "" {
							scope[id.Name] = true
						}
					}
				case *ast.TypeSpec:
					if sp.Name != nil && sp.Name.Name != "_" && sp.Name.Name != "" {
						scope[sp.Name.Name] = true
					}
					sub := maps.Clone(scope)
					if sp.TypeParams != nil {
						for _, fld := range sp.TypeParams.List {
							for _, id := range fld.Names {
								if id.Name != "_" && id.Name != "" {
									sub[id.Name] = true
								}
							}
						}
					}
					walkOffSurfaceAST(sp.Type, sub, recIdent, recSel, recQual)
				}
			}
		}
	case *ast.FuncLit:
		sub := maps.Clone(scope)
		if n.Type != nil {
			for _, fl := range []*ast.FieldList{n.Type.Params, n.Type.Results} {
				if fl != nil {
					for _, fld := range fl.List {
						if fld.Type != nil {
							walkOffSurfaceAST(fld.Type, scope, recIdent, recSel, recQual)
						}
						for _, id := range fld.Names {
							if id.Name != "_" && id.Name != "" {
								sub[id.Name] = true
							}
						}
					}
				}
			}
		}
		if n.Body != nil {
			walkOffSurfaceAST(n.Body, sub, recIdent, recSel, recQual)
		}
	case *ast.Ident:
		if n.Name != "_" && !scope[n.Name] {
			recIdent(n.Name)
		}
	case *ast.SelectorExpr:
		if xID, ok := unwrapParens(n.X).(*ast.Ident); ok {
			if !scope[xID.Name] {
				if n.Sel != nil {
					recQual(xID.Name, n.Sel.Name)
				} else {
					recIdent(xID.Name)
				}
				return
			}
		} else {
			walkOffSurfaceAST(n.X, scope, recIdent, recSel, recQual)
		}
		if n.Sel != nil {
			recSel(n.Sel.Name)
		}
	case *ast.StructType:
		if n.Fields != nil {
			for _, fld := range n.Fields.List {
				if fld.Type != nil {
					walkOffSurfaceAST(fld.Type, scope, recIdent, recSel, recQual)
				}
			}
		}
	case *ast.InterfaceType:
		if n.Methods != nil {
			for _, m := range n.Methods.List {
				if m.Type != nil {
					walkOffSurfaceAST(m.Type, scope, recIdent, recSel, recQual)
				}
			}
		}
	case *ast.FuncType:
		for _, fl := range []*ast.FieldList{n.TypeParams, n.Params, n.Results} {
			if fl != nil {
				for _, fld := range fl.List {
					if fld.Type != nil {
						walkOffSurfaceAST(fld.Type, scope, recIdent, recSel, recQual)
					}
				}
			}
		}
	case *ast.LabeledStmt:
		walkOffSurfaceAST(n.Stmt, scope, recIdent, recSel, recQual)
	case *ast.BranchStmt:
		// Label ident is not a value/decl reference.
	default:
		ast.Inspect(node, func(ch ast.Node) bool {
			if ch == nil || ch == node {
				return true
			}
			walkOffSurfaceAST(ch, scope, recIdent, recSel, recQual)
			return false
		})
	}
}

func collectOffSurfaceStartupRuntimePulls(ctx context.Context, d sourceDigests, policy, pkgIncludeSalt string, pureDelegates map[string]bool, externalSeeds []offSurfaceCrossEdge, pulledRuntimeTargets map[string]bool) (ioErr error, ctxErr error) {
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

	offVerdicts := make(map[string]offSurfaceVerdict, len(invKeys))
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

	type workItem struct {
		pkg  string
		decl string
	}
	visited := map[workItem]bool{}
	var queue []workItem
	pkgReachedTypes := map[string]map[string]bool{}
	pkgReachedSels := map[string]map[string]bool{}
	globalExportedSels := map[string]bool{}

	enqueue := func(pkg, decl string) {
		if pkg == "" || decl == "" {
			return
		}
		if _, ok := offVerdicts[pkg]; !ok {
			return
		}
		wi := workItem{pkg: pkg, decl: decl}
		if visited[wi] {
			return
		}
		visited[wi] = true
		queue = append(queue, wi)
	}

	addSel := func(pkg, sel string) {
		if sel == "" {
			return
		}
		if pkg != "" {
			if pkgReachedSels[pkg] == nil {
				pkgReachedSels[pkg] = map[string]bool{}
			}
			if !pkgReachedSels[pkg][sel] {
				pkgReachedSels[pkg][sel] = true
				for tName := range pkgReachedTypes[pkg] {
					if slices.Contains(offVerdicts[pkg].MethodsByType[tName], sel) {
						enqueue(pkg, "method:"+tName+"."+sel)
					}
				}
			}
		}
		if ast.IsExported(sel) && !globalExportedSels[sel] {
			globalExportedSels[sel] = true
			for oPkg, tMap := range pkgReachedTypes {
				for tName := range tMap {
					if slices.Contains(offVerdicts[oPkg].MethodsByType[tName], sel) {
						enqueue(oPkg, "method:"+tName+"."+sel)
					}
				}
			}
		}
	}

	enqueueCross := func(rawPkg, sym string) {
		if rawPkg == "runtime" {
			if base := leadingASCIIIdent(sym); base != "" {
				pulledRuntimeTargets["runtime."+base] = true
			} else {
				pulledRuntimeTargets["runtime."+sym] = true
			}
			return
		}
		if resolved, ok := resolveStdInventoryImport(d.inventory, rawPkg); ok {
			enqueue(resolved, sym)
			if typePart, methodPart, hasDot := strings.Cut(sym, "."); hasDot {
				tBase := strings.TrimSuffix(strings.TrimPrefix(typePart, "(*"), ")")
				tBase = strings.TrimPrefix(tBase, "*")
				mBase := leadingASCIIIdent(methodPart)
				if tBase != "" && mBase != "" {
					enqueue(resolved, tBase)
					enqueue(resolved, "method:"+tBase+"."+mBase)
				}
			}
		}
	}

	enqueueUnaliased := func(u offSurfaceUnaliasedSel) {
		for _, cand := range u.Candidates {
			resolved, ok := resolveStdInventoryImport(d.inventory, cand)
			if !ok {
				continue
			}
			if ov, isOff := offVerdicts[resolved]; isOff {
				if ov.PackageName == "" || ov.PackageName == u.Ident {
					enqueue(resolved, u.Sel)
				}
			}
		}
	}

	enqueueDot := func(dotImports []string, ident string) {
		for _, cand := range dotImports {
			if resolved, ok := resolveStdInventoryImport(d.inventory, cand); ok {
				enqueue(resolved, ident)
			}
		}
	}

	for _, seed := range externalSeeds {
		enqueueCross(seed.Pkg, seed.Sym)
	}
	for _, pkg := range invKeys {
		ov := offVerdicts[pkg]
		for _, sd := range ov.SeedDecls {
			enqueue(pkg, sd)
		}
		for _, sel := range ov.SeedSels {
			addSel(pkg, sel)
		}
		for _, ce := range ov.SeedCrossEdges {
			enqueueCross(ce.Pkg, ce.Sym)
		}
		for _, u := range ov.SeedUnaliasedSels {
			enqueueUnaliased(u)
		}
		for _, di := range ov.SeedDotIdents {
			enqueueDot(ov.DotImports, di)
		}
	}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		ov := offVerdicts[item.pkg]
		if rt := ov.RuntimePullByDecl[item.decl]; rt != "" {
			pulledRuntimeTargets[rt] = true
			if pulledRuntimeTargets["runtime.*"] {
				return nil, nil
			}
		}
		if methods := ov.MethodsByType[item.decl]; len(methods) > 0 {
			if pkgReachedTypes[item.pkg] == nil {
				pkgReachedTypes[item.pkg] = map[string]bool{}
			}
			pkgReachedTypes[item.pkg][item.decl] = true
			for _, m := range methods {
				if pkgReachedSels[item.pkg][m] || (ast.IsExported(m) && globalExportedSels[m]) {
					enqueue(item.pkg, "method:"+item.decl+"."+m)
				}
			}
		}
		for _, sel := range ov.LocalSels[item.decl] {
			addSel(item.pkg, sel)
		}
		for _, loc := range ov.LocalEdges[item.decl] {
			enqueue(item.pkg, loc)
		}
		for _, ce := range ov.CrossEdges[item.decl] {
			enqueueCross(ce.Pkg, ce.Sym)
		}
		for _, u := range ov.UnaliasedSels[item.decl] {
			enqueueUnaliased(u)
		}
		for _, di := range ov.DotImportIdents[item.decl] {
			enqueueDot(ov.DotImports, di)
		}
	}
	return nil, nil
}

func allNonSelPropIdentsIn(files []*ast.File, name string, allowed map[*ast.Ident]bool) bool {
	ok := true
	var walk func(n ast.Node)
	walk = func(n ast.Node) {
		if !ok || n == nil {
			return
		}
		if sel, isSel := n.(*ast.SelectorExpr); isSel {
			walk(sel.X)
			return
		}
		if id, isID := n.(*ast.Ident); isID {
			if id.Name == name && !allowed[id] {
				ok = false
			}
			return
		}
		ast.Inspect(n, func(ch ast.Node) bool {
			if !ok {
				return false
			}
			if ch == n {
				return true
			}
			walk(ch)
			return false
		})
	}
	for _, f := range files {
		walk(f)
		if !ok {
			return false
		}
	}
	return true
}

func discoverRuntimeInactiveGates(files []*ast.File, goSrcs []string, nonGoIdents map[string]bool) map[string][]string {
	anyLinknameLocal := map[string]bool{}
	twoArgTargets := map[string][]string{}
	aliasedRuntimeSym := map[string]bool{}
	for _, src := range goSrcs {
		fset := token.NewFileSet()
		file := fset.AddFile("", fset.Base(), len(src))
		var scanBad bool
		var s scanner.Scanner
		s.Init(file, []byte(src), func(_ token.Position, _ string) { scanBad = true }, scanner.ScanComments)
		for {
			_, tok, lit := s.Scan()
			if tok == token.EOF {
				break
			}
			if tok != token.COMMENT {
				continue
			}
			if strings.HasPrefix(lit, "/*go:linkname") {
				return nil
			}
			if !strings.HasPrefix(lit, "//go:linkname") {
				continue
			}
			line := strings.TrimSuffix(lit, "\r")
			if strings.ContainsRune(line, '\r') {
				return nil
			}
			_, plain := auditset.BoundedToken(line, "//go:linkname", " \t")
			_, std := auditset.BoundedToken(line, "//go:linknamestd", " \t")
			fields := strings.Fields(line)
			if (!plain && !std) || (len(fields) != 2 && len(fields) != 3) {
				return nil
			}
			anyLinknameLocal[fields[1]] = true
			if len(fields) == 3 {
				twoArgTargets[fields[1]] = append(twoArgTargets[fields[1]], fields[2])
				if strings.HasPrefix(fields[2], "runtime.") {
					rem := strings.TrimPrefix(fields[2], "runtime.")
					if rem != fields[1] {
						aliasedRuntimeSym[rem] = true
					}
				}
			}
		}
		if scanBad {
			return nil
		}
	}

	fileImportsAtomic := map[*ast.File]bool{}
	pkgDeclCounts := map[string]int{}
	falseConstCand := map[string]bool{}
	trueConstCand := map[string]bool{}
	badBoolConst := map[string]bool{}
	type atomicStateCand struct {
		declIdent *ast.Ident
		isBool    bool
	}
	stateCands := map[string]atomicStateCand{}
	topFuncs := map[string]*ast.FuncDecl{}

	for _, f := range files {
		hasDotImport := false
		hasAtomic := false
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return nil
			}
			if imp.Name != nil && imp.Name.Name == "." {
				hasDotImport = true
			}
			if (p == "internal/runtime/atomic" || p == "sync/atomic") && imp.Name == nil {
				hasAtomic = true
			}
		}
		if hasAtomic && !hasDotImport {
			fileImportsAtomic[f] = true
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.ValueSpec:
						for idx, id := range sp.Names {
							if id.Name != "_" {
								pkgDeclCounts[id.Name]++
							}
							if d.Tok == token.CONST && id.Name != "_" {
								typeOK := sp.Type == nil
								if !typeOK {
									_, typeOK = isIdentNamed(sp.Type, "bool")
								}
								if typeOK && len(sp.Values) == len(sp.Names) {
									if _, okF := isIdentNamed(sp.Values[idx], "false"); okF {
										falseConstCand[id.Name] = true
									} else if _, okT := isIdentNamed(sp.Values[idx], "true"); okT {
										trueConstCand[id.Name] = true
									} else {
										badBoolConst[id.Name] = true
									}
								} else {
									badBoolConst[id.Name] = true
								}
							}
							if d.Tok == token.VAR && id.Name != "_" && !ast.IsExported(id.Name) && len(sp.Values) == 0 && fileImportsAtomic[f] && sp.Type != nil {
								if sel, okS := unwrapParens(sp.Type).(*ast.SelectorExpr); okS {
									if _, okA := isIdentNamed(sel.X, "atomic"); okA {
										switch sel.Sel.Name {
										case "Uint64", "Uint32", "Int64", "Int32":
											stateCands[id.Name] = atomicStateCand{declIdent: id, isBool: false}
										case "Bool":
											stateCands[id.Name] = atomicStateCand{declIdent: id, isBool: true}
										}
									}
								}
							}
						}
					case *ast.TypeSpec:
						if sp.Name != nil && sp.Name.Name != "_" {
							pkgDeclCounts[sp.Name.Name]++
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name != nil && d.Name.Name != "init" && d.Name.Name != "_" {
					pkgDeclCounts[d.Name.Name]++
					if d.Body != nil {
						topFuncs[d.Name.Name] = d
					}
				}
			}
		}
	}
	if pkgDeclCounts["false"] > 0 || pkgDeclCounts["true"] > 0 || pkgDeclCounts["bool"] > 0 || pkgDeclCounts["atomic"] > 0 {
		return nil
	}
	falseConsts := map[string]bool{}
	for name := range falseConstCand {
		if !badBoolConst[name] && !trueConstCand[name] && pkgDeclCounts[name] == 1 && !anyLinknameLocal[name] && !aliasedRuntimeSym[name] {
			falseConsts[name] = true
		}
	}
	trueConsts := map[string]bool{}
	for name := range trueConstCand {
		if !badBoolConst[name] && !falseConstCand[name] && pkgDeclCounts[name] == 1 && !anyLinknameLocal[name] && !aliasedRuntimeSym[name] {
			trueConsts[name] = true
		}
	}

	verifiedStateMutators := map[string][]string{}
	verifiedStateIsBool := map[string]bool{}
	for sName, cand := range stateCands {
		if pkgDeclCounts[sName] != 1 || anyLinknameLocal[sName] || aliasedRuntimeSym[sName] || nonGoIdents[sName] {
			continue
		}
		allowedIdents := map[*ast.Ident]bool{cand.declIdent: true}
		mutatorSet := map[string]bool{}
		for _, f := range files {
			if !fileImportsAtomic[f] {
				// S may still be accessed via methods in files without importing atomic directly!
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				if funcShadowsAnyIdent(fn, map[string]bool{sName: true, "false": true}) {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, isCall := n.(*ast.CallExpr)
					if !isCall || call.Ellipsis.IsValid() {
						return true
					}
					sel, okS := unwrapParens(call.Fun).(*ast.SelectorExpr)
					if !okS {
						return true
					}
					baseID, okID := unwrapParens(sel.X).(*ast.Ident)
					if !okID || baseID.Name != sName {
						return true
					}
					switch {
					case sel.Sel.Name == "Load" && len(call.Args) == 0:
						allowedIdents[baseID] = true
					case sel.Sel.Name == "Store" && len(call.Args) == 1:
						isZero := (!cand.isBool && isZeroIntLit(call.Args[0]))
						if cand.isBool {
							_, isZero = isIdentNamed(call.Args[0], "false")
						}
						if isZero {
							allowedIdents[baseID] = true
						} else if fn.Recv == nil && fn.Name != nil && !ast.IsExported(fn.Name.Name) && fn.Name.Name != "init" {
							allowedIdents[baseID] = true
							mutatorSet[fn.Name.Name] = true
						}
					}
					return true
				})
			}
		}
		if !allNonSelPropIdentsIn(files, sName, allowedIdents) {
			continue
		}
		mutatorsValid := true
		mutTargets := make([]string, 0, len(mutatorSet)+1)
		mutTargets = append(mutTargets, "runtime."+sName)
		for mName := range mutatorSet {
			mFn := topFuncs[mName]
			if mFn == nil || pkgDeclCounts[mName] != 1 || ast.IsExported(mName) || aliasedRuntimeSym[mName] || nonGoIdents[mName] {
				mutatorsValid = false
				break
			}
			for _, t := range twoArgTargets[mName] {
				if t != "runtime."+mName {
					mutatorsValid = false
					break
				}
			}
			if !mutatorsValid || !allNonSelPropIdentsIn(files, mName, map[*ast.Ident]bool{mFn.Name: true}) {
				mutatorsValid = false
				break
			}
			mutTargets = append(mutTargets, "runtime."+mName)
		}
		if !mutatorsValid {
			continue
		}
		slices.Sort(mutTargets)
		verifiedStateMutators[sName] = mutTargets
		verifiedStateIsBool[sName] = cand.isBool
	}

	provenGates := map[string][]string{}
	var evalFalseExpr func(expr ast.Expr, fn *ast.FuncDecl) ([]string, bool)
	evalFalseExpr = func(expr ast.Expr, fn *ast.FuncDecl) ([]string, bool) {
		expr = unwrapParens(expr)
		if id, ok := expr.(*ast.Ident); ok {
			if id.Name == "false" || (falseConsts[id.Name] && !funcShadowsAnyIdent(fn, map[string]bool{id.Name: true})) {
				return make([]string, 0), true
			}
			return nil, false
		}
		if call, ok := expr.(*ast.CallExpr); ok && !call.Ellipsis.IsValid() && len(call.Args) == 0 {
			if gID, okG := unwrapParens(call.Fun).(*ast.Ident); okG && !funcShadowsAnyIdent(fn, map[string]bool{gID.Name: true}) {
				if deps, okP := provenGates["runtime."+gID.Name]; okP {
					return slices.Clone(deps), true
				}
			}
			if sel, okS := unwrapParens(call.Fun).(*ast.SelectorExpr); okS && sel.Sel.Name == "Load" {
				if sID, okID := unwrapParens(sel.X).(*ast.Ident); okID && verifiedStateIsBool[sID.Name] && !funcShadowsAnyIdent(fn, map[string]bool{sID.Name: true}) {
					if deps, okM := verifiedStateMutators[sID.Name]; okM {
						return slices.Clone(deps), true
					}
				}
			}
		}
		if bin, ok := expr.(*ast.BinaryExpr); ok {
			switch bin.Op {
			case token.NEQ:
				checkLoadZero := func(loadExpr, zeroExpr ast.Expr) ([]string, bool) {
					if !isZeroIntLit(zeroExpr) {
						return nil, false
					}
					c, okC := unwrapParens(loadExpr).(*ast.CallExpr)
					if !okC || c.Ellipsis.IsValid() || len(c.Args) != 0 {
						return nil, false
					}
					sel, okS := unwrapParens(c.Fun).(*ast.SelectorExpr)
					if !okS || sel.Sel.Name != "Load" {
						return nil, false
					}
					sID, okID := unwrapParens(sel.X).(*ast.Ident)
					if !okID || verifiedStateIsBool[sID.Name] || funcShadowsAnyIdent(fn, map[string]bool{sID.Name: true}) {
						return nil, false
					}
					deps, okM := verifiedStateMutators[sID.Name]
					if !okM {
						return nil, false
					}
					return slices.Clone(deps), true
				}
				if deps, okL := checkLoadZero(bin.X, bin.Y); okL {
					return deps, true
				}
				if deps, okR := checkLoadZero(bin.Y, bin.X); okR {
					return deps, true
				}
			case token.LAND:
				if deps, okL := evalFalseExpr(bin.X, fn); okL {
					return deps, true
				}
				if id, okID := unwrapParens(bin.X).(*ast.Ident); okID && (id.Name == "true" || (trueConsts[id.Name] && !funcShadowsAnyIdent(fn, map[string]bool{id.Name: true}))) {
					return evalFalseExpr(bin.Y, fn)
				}
			case token.LOR:
				depsL, okL := evalFalseExpr(bin.X, fn)
				if !okL {
					return nil, false
				}
				depsR, okR := evalFalseExpr(bin.Y, fn)
				if !okR {
					return nil, false
				}
				merged := map[string]bool{}
				for _, d := range depsL {
					merged[d] = true
				}
				for _, d := range depsR {
					merged[d] = true
				}
				out := sortedKeys(merged)
				if out == nil {
					out = make([]string, 0)
				}
				return out, true
			}
		}
		return nil, false
	}

	gateReserved := map[string]bool{"false": true, "true": true, "bool": true}
	for {
		changed := false
		for gName, fn := range topFuncs {
			key := "runtime." + gName
			if _, already := provenGates[key]; already {
				continue
			}
			if ast.IsExported(gName) || pkgDeclCounts[gName] != 1 || aliasedRuntimeSym[gName] || fn.Type == nil {
				continue
			}
			badTarget := false
			for _, t := range twoArgTargets[gName] {
				if t != key {
					badTarget = true
					break
				}
			}
			if badTarget {
				continue
			}
			if fn.Type.Params != nil && fn.Type.Params.NumFields() != 0 {
				continue
			}
			if fn.Type.Results == nil || fn.Type.Results.NumFields() != 1 || len(fn.Type.Results.List) != 1 {
				continue
			}
			if _, okBool := isIdentNamed(fn.Type.Results.List[0].Type, "bool"); !okBool {
				continue
			}
			if len(fn.Body.List) == 0 || funcShadowsAnyIdent(fn, gateReserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
				continue
			}
			switch s0 := fn.Body.List[0].(type) {
			case *ast.ReturnStmt:
				if len(s0.Results) == 1 {
					if deps, ok := evalFalseExpr(s0.Results[0], fn); ok {
						provenGates[key] = deps
						changed = true
					}
				}
			case *ast.IfStmt:
				if s0.Init == nil && s0.Else == nil && len(s0.Body.List) == 1 {
					if ret, okR := s0.Body.List[0].(*ast.ReturnStmt); okR && len(ret.Results) == 1 {
						if _, okFalse := isIdentNamed(ret.Results[0], "false"); okFalse {
							if u, okU := unwrapParens(s0.Cond).(*ast.UnaryExpr); okU && u.Op == token.NOT {
								if deps, ok := evalFalseExpr(u.X, fn); ok {
									provenGates[key] = deps
									changed = true
								}
							}
						}
					}
				}
			}
		}
		if !changed {
			break
		}
	}
	if len(provenGates) == 0 {
		return nil
	}
	return provenGates
}

func matchLineContinuation(src string, idx int) (int, bool) {
	if idx >= len(src) || src[idx] != '\\' {
		return 0, false
	}
	j := idx + 1
	for j < len(src) && (src[j] == ' ' || src[j] == '\t' || src[j] == '\r') {
		j++
	}
	if j < len(src) && src[j] == '\n' {
		return j, true
	}
	return 0, false
}

func stripAssemblyComments(src string, keepLiterals, joinContinuationWithSpace bool) string {
	var b strings.Builder
	b.Grow(len(src))
	const (
		stateNormal = iota
		stateLineComment
		stateBlockComment
		stateString
		stateChar
	)
	state := stateNormal
	for i := 0; i < len(src); i++ {
		ch := src[i]
		switch state {
		case stateNormal:
			if nlIdx, ok := matchLineContinuation(src, i); ok {
				if joinContinuationWithSpace {
					b.WriteByte(' ')
				}
				i = nlIdx
				continue
			}
			if ch == '/' && i+1 < len(src) && src[i+1] == '/' {
				state = stateLineComment
				i++
				continue
			}
			if ch == '/' && i+1 < len(src) && src[i+1] == '*' {
				state = stateBlockComment
				b.WriteByte(' ')
				i++
				continue
			}
			if ch == '"' {
				state = stateString
				if keepLiterals {
					b.WriteByte(ch)
				} else {
					b.WriteByte(' ')
				}
				continue
			}
			if ch == '\'' {
				state = stateChar
				if keepLiterals {
					b.WriteByte(ch)
				} else {
					b.WriteByte(' ')
				}
				continue
			}
			b.WriteByte(ch)
		case stateLineComment:
			if ch == '\n' {
				state = stateNormal
				b.WriteByte('\n')
			}
		case stateBlockComment:
			if ch == '*' && i+1 < len(src) && src[i+1] == '/' {
				state = stateNormal
				i++
				continue
			}
		case stateString:
			if nlIdx, ok := matchLineContinuation(src, i); ok {
				i = nlIdx
				continue
			}
			if ch == '\\' && i+1 < len(src) {
				if keepLiterals {
					b.WriteByte(ch)
					b.WriteByte(src[i+1])
				}
				i++
				continue
			}
			if keepLiterals {
				b.WriteByte(ch)
			}
			if ch == '"' {
				state = stateNormal
			} else if ch == '\n' {
				state = stateNormal
				if !keepLiterals {
					b.WriteByte('\n')
				}
			}
		case stateChar:
			if nlIdx, ok := matchLineContinuation(src, i); ok {
				i = nlIdx
				continue
			}
			if ch == '\\' && i+1 < len(src) {
				if keepLiterals {
					b.WriteByte(ch)
					b.WriteByte(src[i+1])
				}
				i++
				continue
			}
			if keepLiterals {
				b.WriteByte(ch)
			}
			if ch == '\'' {
				state = stateNormal
			} else if ch == '\n' {
				state = stateNormal
				if !keepLiterals {
					b.WriteByte('\n')
				}
			}
		}
	}
	return foldAssemblyCommentContinuations(b.String(), joinContinuationWithSpace)
}

func foldAssemblyCommentContinuations(s string, joinWithSpace bool) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	lines := strings.Split(s, "\n")
	var out strings.Builder
	out.Grow(len(s))
	for idx, line := range lines {
		trimmedRight := strings.TrimRight(line, " \t\r")
		// Count trailing backslashes; an odd count escapes the newline even if a comment followed '\'.
		bs := 0
		for bs < len(trimmedRight) && trimmedRight[len(trimmedRight)-1-bs] == '\\' {
			bs++
		}
		if bs%2 == 1 && idx+1 < len(lines) {
			out.WriteString(trimmedRight[:len(trimmedRight)-1])
			if joinWithSpace {
				out.WriteByte(' ')
			}
			continue
		}
		out.WriteString(line)
		if idx+1 < len(lines) {
			out.WriteByte('\n')
		}
	}
	return out.String()
}

func isAsmWordRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
		r == '_' || r == '.' || r == '·' || r == '/' || r == '∕' || r == '<' || r == '>'
}

func verifyAssemblyNoSyscall(pkgPath, name, src string) error {
	return verifyAssemblyFile(pkgPath, name, src, nil)
}

var allowedAsmDirectiveKeywords = map[string]bool{
	"define":  true,
	"elif":    true,
	"else":    true,
	"endif":   true,
	"error":   true,
	"if":      true,
	"ifdef":   true,
	"ifndef":  true,
	"include": true,
	"line":    true,
	"pragma":  true,
	"undef":   true,
}

func verifyAssemblyFile(pkgPath, name, src string, selectedHeaders map[string]bool) error {
	if err := verifyAssemblyFileSinglePass(pkgPath, name, src, selectedHeaders, true); err != nil {
		return err
	}
	return verifyAssemblyFileSinglePass(pkgPath, name, src, selectedHeaders, false)
}

func verifyAssemblyFileSinglePass(pkgPath, name, src string, selectedHeaders map[string]bool, joinContinuationWithSpace bool) error {
	isHeader := pkgPath == "" || strings.EqualFold(filepath.Ext(name), ".h")
	noComments := stripAssemblyComments(src, true, joinContinuationWithSpace)
	definedMacros := map[string]bool{}
	for _, rawLine := range strings.Split(noComments, "\n") {
		trimmed := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(trimmed, "#") {
			continue
		}
		directive := strings.TrimSpace(trimmed[1:])
		kwEnd := 0
		for kwEnd < len(directive) && ((directive[kwEnd] >= 'a' && directive[kwEnd] <= 'z') || (directive[kwEnd] >= 'A' && directive[kwEnd] <= 'Z') || directive[kwEnd] == '_') {
			kwEnd++
		}
		kw := directive[:kwEnd]
		if !allowedAsmDirectiveKeywords[kw] {
			return fmt.Errorf("%s/%s: unsupported preprocessor directive in assembly", pkgPath, name)
		}
		if kw == "define" {
			defRest := strings.TrimSpace(directive[kwEnd:])
			mEnd := 0
			for mEnd < len(defRest) && ((defRest[mEnd] >= 'a' && defRest[mEnd] <= 'z') || (defRest[mEnd] >= 'A' && defRest[mEnd] <= 'Z') || (mEnd > 0 && defRest[mEnd] >= '0' && defRest[mEnd] <= '9') || defRest[mEnd] == '_') {
				mEnd++
			}
			macroName := defRest[:mEnd]
			if macroName == "" {
				return fmt.Errorf("%s/%s: malformed #define in assembly", pkgPath, name)
			}
			afterMacroName := defRest[mEnd:]
			hasMacroParams := strings.HasPrefix(afterMacroName, "(")
			macroBody := afterMacroName
			if hasMacroParams {
				if closeIdx := strings.IndexByte(afterMacroName, ')'); closeIdx >= 0 {
					macroBody = afterMacroName[closeIdx+1:]
				}
			}
			if pkgPath != "" && (macroName == pkgPath || slices.Contains(strings.Split(pkgPath, "/"), macroName)) {
				return fmt.Errorf("%s/%s: #define %s shadows package path", pkgPath, name, macroName)
			}
			if isHeader && !hasMacroParams && strings.TrimSpace(macroBody) != "" && macroName[0] >= 'a' && macroName[0] <= 'z' {
				return fmt.Errorf("%s/%s: header #define %s shadows lowercase package identifier", pkgPath, name, macroName)
			}
			definedMacros[macroName] = true
			continue
		}
		if kw != "include" {
			continue
		}
		incArg := strings.TrimSpace(directive[kwEnd:])
		if len(incArg) < 2 || incArg[0] != '"' {
			return fmt.Errorf("%s/%s: unapproved #include %s in assembly", pkgPath, name, incArg)
		}
		hdr, err := strconv.Unquote(incArg)
		if err != nil {
			return fmt.Errorf("%s/%s: unapproved #include %s in assembly", pkgPath, name, incArg)
		}
		if hdr == "" || strings.ContainsAny(hdr, `/\`) || strings.Contains(hdr, "..") {
			return fmt.Errorf("%s/%s: forbidden path in #include %q", pkgPath, name, hdr)
		}
		if !allowedPureAsmStandardHeaders[hdr] && !selectedHeaders[hdr] {
			return fmt.Errorf("%s/%s: unapproved #include %q in assembly", pkgPath, name, hdr)
		}
	}

	cleaned := stripAssemblyComments(src, false, joinContinuationWithSpace)
	for _, line := range strings.Split(cleaned, "\n") {
		trimmedClean := strings.TrimSpace(line)
		isDirectiveLine := strings.HasPrefix(trimmedClean, "#")
		if strings.Contains(trimmedClean, "#") && (!isDirectiveLine || strings.Contains(trimmedClean[1:], "#")) {
			return fmt.Errorf("%s/%s: unexpected '#' in assembly", pkgPath, name)
		}
		scanLine := line
		var macroParams map[string]bool
		isObjectDefine := false
		if isDirectiveLine {
			dRest := strings.TrimSpace(trimmedClean[1:])
			if strings.HasPrefix(dRest, "define") && (len(dRest) == 6 || dRest[6] == ' ' || dRest[6] == '\t') {
				afterDef := strings.TrimSpace(dRest[6:])
				mEnd := 0
				for mEnd < len(afterDef) && ((afterDef[mEnd] >= 'a' && afterDef[mEnd] <= 'z') || (afterDef[mEnd] >= 'A' && afterDef[mEnd] <= 'Z') || (mEnd > 0 && afterDef[mEnd] >= '0' && afterDef[mEnd] <= '9') || afterDef[mEnd] == '_') {
					mEnd++
				}
				afterName := afterDef[mEnd:]
				if strings.HasPrefix(afterName, "(") {
					closeIdx := strings.IndexByte(afterName, ')')
					if closeIdx < 0 {
						return fmt.Errorf("%s/%s: malformed function-like #define in assembly", pkgPath, name)
					}
					macroParams = map[string]bool{}
					for _, p := range strings.Split(afterName[1:closeIdx], ",") {
						p = strings.TrimSpace(p)
						if p != "" {
							macroParams[p] = true
						}
					}
					scanLine = afterName[closeIdx+1:]
				} else {
					isObjectDefine = true
					scanLine = afterName
				}
			}
		}
		if isObjectDefine {
			// Forbid `#define M CALL time` where an object-like macro expands to
			// an instruction plus a trailing Go package identifier before `·sym`.
			trimmedBody := strings.TrimSpace(scanLine)
			lastSpace := strings.LastIndexAny(trimmedBody, " \t")
			if lastSpace > 0 {
				beforeLast := strings.TrimRight(trimmedBody[:lastSpace], " \t")
				lastTok := trimmedBody[lastSpace+1:]
				if len(beforeLast) > 0 && isAsmWordRune(rune(beforeLast[len(beforeLast)-1])) &&
					len(lastTok) > 0 && lastTok[0] >= 'a' && lastTok[0] <= 'z' {
					allPkgChars := true
					for _, r := range lastTok {
						if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '/' || r == '∕') {
							allPkgChars = false
							break
						}
					}
					if allPkgChars {
						return fmt.Errorf("%s/%s: forbidden trailing package token %s in #define", pkgPath, name, lastTok)
					}
				}
			}
		}
		runes := []rune(scanLine)
		stmtWordIdx := 0
		prevWord := ""
		for i := 0; i < len(runes); {
			if runes[i] == ';' {
				stmtWordIdx = 0
				prevWord = ""
				i++
				continue
			}
			if !isAsmWordRune(runes[i]) {
				i++
				continue
			}
			start := i
			for i < len(runes) && isAsmWordRune(runes[i]) {
				i++
			}
			rawTok := string(runes[start:i])
			prevNonSpace := rune(0)
			for back := start - 1; back >= 0; back-- {
				if runes[back] != ' ' && runes[back] != '\t' && runes[back] != '\r' {
					prevNonSpace = runes[back]
					break
				}
			}
			if strings.ContainsRune(rawTok, '·') {
				if strings.HasSuffix(rawTok, "·") || strings.HasPrefix(rawTok, "/") || strings.HasPrefix(rawTok, "∕") ||
					prevNonSpace == '/' || prevNonSpace == '∕' || prevNonSpace == ')' ||
					strings.HasSuffix(prevWord, "/") || strings.HasSuffix(prevWord, "∕") {
					return fmt.Errorf("%s/%s: split middle-dot symbol %s in assembly", pkgPath, name, rawTok)
				}
				if (isObjectDefine || macroParams != nil) && strings.HasPrefix(rawTok, "·") && prevNonSpace == 0 {
					return fmt.Errorf("%s/%s: macro body starts with middle-dot symbol %s in assembly", pkgPath, name, rawTok)
				}
				if strings.HasPrefix(rawTok, "·") && isAsmWordRune(prevNonSpace) {
					prevHasLowerOrSlash := strings.ContainsAny(prevWord, "abcdefghijklmnopqrstuvwxyz/∕·")
					if stmtWordIdx != 1 || prevHasLowerOrSlash || definedMacros[prevWord] || macroParams[prevWord] {
						return fmt.Errorf("%s/%s: split package-qualified symbol %s %s in assembly", pkgPath, name, prevWord, rawTok)
					}
				}
				pkgPrefix, symPart, _ := strings.Cut(rawTok, "·")
				pkgPrefix = strings.ReplaceAll(pkgPrefix, "∕", "/")
				if pkgPrefix != "" {
					baseSym, _, _ := strings.Cut(symPart, "<")
					hasMacroSeg := definedMacros[pkgPrefix] || macroParams[pkgPrefix] || definedMacros[baseSym] || macroParams[baseSym] ||
						slices.ContainsFunc(strings.Split(pkgPrefix, "/"), func(seg string) bool {
							return definedMacros[seg] || macroParams[seg]
						})
					if hasMacroSeg {
						return fmt.Errorf("%s/%s: macro-qualified assembly symbol %s", pkgPath, name, rawTok)
					}
					if pkgPrefix != pkgPath {
						target := pkgPrefix + "." + baseSym
						if !allowedPureAsmCrossPkgSymbols[target] && !allowedPureSingleArgLinknames[target] {
							return fmt.Errorf("%s/%s: unapproved cross-package assembly symbol %s", pkgPath, name, rawTok)
						}
					}
				}
				stmtWordIdx++
				prevWord = rawTok
				continue
			}
			if isObjectDefine || macroParams != nil {
				switch rawTok {
				case "runtime", "syscall", "os", "internal":
					if !macroParams[rawTok] {
						return fmt.Errorf("%s/%s: forbidden package token %s in #define", pkgPath, name, rawTok)
					}
				}
			}
			tok := strings.ToUpper(rawTok)
			switch tok {
			case "SYSCALL", "SYSENTER", "SVC", "ECALL", "SCALL", "SWI",
				"RDTSC", "RDTSCP", "RDRAND", "RDSEED", "RDTIME", "RDCYCLE", "RDINSTRET",
				"CNTVCT_EL0", "CNTPCT_EL0", "CNTVCTSS_EL0", "CNTPCTSS_EL0", "RNDR", "RNDRRS":
				return fmt.Errorf("%s/%s: assembly file contains forbidden instruction %s", pkgPath, name, tok)
			case "TA":
				if prevNonSpace != ',' {
					return fmt.Errorf("%s/%s: assembly file contains raw trap instruction TA", pkgPath, name)
				}
			case "INT":
				rest := strings.TrimSpace(string(runes[i:]))
				if rawTok == "INT" || strings.HasPrefix(rest, "$") {
					return fmt.Errorf("%s/%s: assembly file contains software interrupt instruction", pkgPath, name)
				}
			}
			stmtWordIdx++
			prevWord = rawTok
		}
	}
	return nil
}

func verifyFileLinknameDirectives(pkgPath string, text string) error {
	return scanGoDirectiveComments(text, func(line string) error {
		if strings.HasPrefix(line, "//go:wasmimport") {
			return fmt.Errorf("forbidden wasmimport directive %q", line)
		}
		if strings.HasPrefix(line, "//go:wasmexport") {
			return fmt.Errorf("forbidden wasmexport directive %q", line)
		}
		if strings.HasPrefix(line, "//go:cgo_") {
			return fmt.Errorf("forbidden cgo directive %q", line)
		}
		if !strings.HasPrefix(line, "//go:linkname") {
			return nil
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
			return nil
		}
		target := fields[2]
		if !strings.HasPrefix(target, pkgPath+".") && !allowedPureLinknameTargets[target] {
			return fmt.Errorf("unapproved pure-package linkname target %q", target)
		}
		return nil
	})
}

func isOSStderrSelector(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Stderr" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "os"
}

func exprReferencesPkgPrefix(expr ast.Expr, prefixes map[string]bool) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && prefixes[id.Name] {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func verifyPurePackageAST(pkgPath string, files []*ast.File) error {
	for _, f := range files {
		var (
			importsTime, importsMathRand, importsOS, importsRuntime          bool
			importsFmt, importsMath, importsReflect, importsSync             bool
			importsAtomic, importsCryptoFIPS, importsCipher, importsFIPSOnly bool
			importsDRBG, importsSHAGodebug, importsSyscall, importsWindows   bool
		)
		for _, imp := range f.Imports {
			importPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			if forbiddenPureImport(pkgPath, importPath) {
				return fmt.Errorf("%s: forbidden import %q in pure package", pkgPath, importPath)
			}
			if importPath == "unsafe" {
				if imp.Name != nil && imp.Name.Name != "_" {
					return fmt.Errorf("%s: aliased import \"unsafe\" (%s) forbidden in pure package", pkgPath, imp.Name.Name)
				}
				continue
			}
			if isPureSupportImport(pkgPath, importPath) && imp.Name != nil {
				return fmt.Errorf("%s: aliased import %q (%s) forbidden in pure package", pkgPath, importPath, imp.Name.Name)
			}
			switch importPath {
			case "time":
				importsTime = true
			case "math/rand":
				importsMathRand = true
			case "os":
				importsOS = true
			case "runtime":
				importsRuntime = true
			case "fmt":
				importsFmt = true
			case "math":
				importsMath = true
			case "reflect":
				importsReflect = true
			case "sync":
				importsSync = true
			case "sync/atomic":
				importsAtomic = true
			case "crypto/internal/fips140":
				importsCryptoFIPS = true
			case "crypto/cipher":
				importsCipher = true
			case "crypto/fips140":
				importsFIPSOnly = true
			case "crypto/internal/fips140/drbg":
				importsDRBG = true
			case "crypto/internal/fips140deps/godebug":
				importsSHAGodebug = true
			case "syscall":
				importsSyscall = true
			case "internal/syscall/windows":
				importsWindows = true
			}
		}

		if importsSync || importsAtomic {
			syncPrefixes := map[string]bool{}
			if importsSync {
				syncPrefixes["sync"] = true
			}
			if importsAtomic {
				syncPrefixes["atomic"] = true
			}
			for _, decl := range f.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					hasExported := false
					for _, name := range vs.Names {
						if ast.IsExported(name.Name) {
							hasExported = true
							break
						}
					}
					if !hasExported {
						continue
					}
					if vs.Type != nil && exprReferencesPkgPrefix(vs.Type, syncPrefixes) {
						return fmt.Errorf("%s: exported sync/atomic package variable forbidden in pure package", pkgPath)
					}
					for _, val := range vs.Values {
						if exprReferencesPkgPrefix(val, syncPrefixes) {
							return fmt.Errorf("%s: exported sync/atomic package variable forbidden in pure package", pkgPath)
						}
					}
				}
			}
		}

		if importsTime || importsMathRand || importsOS || importsRuntime || importsFmt || importsMath ||
			importsReflect || importsSync || importsAtomic || importsCryptoFIPS || importsCipher ||
			importsFIPSOnly || importsDRBG || importsSHAGodebug || importsSyscall || importsWindows {
			paramRandAllowed := map[*ast.SelectorExpr]bool{}
			allowedTimeUnixUTC := map[*ast.SelectorExpr]bool{}
			allowedGodebugValue := map[*ast.SelectorExpr]bool{}
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
					if importsSHAGodebug && len(node.Args) == 1 {
						if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Value" {
							if id, ok := sel.X.(*ast.Ident); ok && id.Name == "godebug" {
								if lit, ok := node.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING && allowedPureSHAGodebugSettings[lit.Value] {
									allowedGodebugValue[sel] = true
								}
							}
						}
					}
				case *ast.SelectorExpr:
					if importsReflect {
						switch node.Sel.Name {
						case "Call", "CallSlice", "MethodByName":
							violation = fmt.Errorf("%s: forbidden reflective dispatch .%s in pure package", pkgPath, node.Sel.Name)
							return false
						}
					}
					if id, ok := node.X.(*ast.Ident); ok {
						if importsTime && id.Name == "time" && !allowedPureTimeSelectors[node.Sel.Name] && !allowedTimeUnixUTC[node] {
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
						if importsFmt && id.Name == "fmt" && !allowedPureFmtSelectors[node.Sel.Name] {
							violation = fmt.Errorf("%s: forbidden ambient fmt.%s reference", pkgPath, node.Sel.Name)
							return false
						}
						if importsMath && id.Name == "math" && !allowedPureMathSelectors[node.Sel.Name] {
							violation = fmt.Errorf("%s: forbidden math.%s reference", pkgPath, node.Sel.Name)
							return false
						}
						if importsReflect && id.Name == "reflect" && !allowedPureReflectSelectors[node.Sel.Name] {
							violation = fmt.Errorf("%s: forbidden reflect.%s reference", pkgPath, node.Sel.Name)
							return false
						}
						if importsSync && id.Name == "sync" && !allowedPureSyncSelectors[node.Sel.Name] {
							violation = fmt.Errorf("%s: forbidden sync.%s reference", pkgPath, node.Sel.Name)
							return false
						}
						if importsAtomic && id.Name == "atomic" && !allowedPureSyncAtomicSelectors[node.Sel.Name] {
							violation = fmt.Errorf("%s: forbidden atomic.%s reference", pkgPath, node.Sel.Name)
							return false
						}
						if importsCryptoFIPS && id.Name == "fips140" && !allowedPureCryptoInternalFIPS140Selectors[node.Sel.Name] {
							violation = fmt.Errorf("%s: forbidden fips140.%s reference", pkgPath, node.Sel.Name)
							return false
						}
						if importsCipher && id.Name == "cipher" && !allowedPureBoringCipherSelectors[node.Sel.Name] {
							violation = fmt.Errorf("%s: forbidden cipher.%s reference", pkgPath, node.Sel.Name)
							return false
						}
						if importsFIPSOnly && id.Name == "fips140" && !allowedPureFIPS140OnlyFIPSSelectors[node.Sel.Name] {
							violation = fmt.Errorf("%s: forbidden crypto/fips140.%s reference", pkgPath, node.Sel.Name)
							return false
						}
						if importsDRBG && id.Name == "drbg" && !allowedPureFIPS140OnlyDRBGSelectors[node.Sel.Name] {
							violation = fmt.Errorf("%s: forbidden drbg.%s reference", pkgPath, node.Sel.Name)
							return false
						}
						if importsSHAGodebug && id.Name == "godebug" && !allowedGodebugValue[node] {
							violation = fmt.Errorf("%s: forbidden godebug.%s reference", pkgPath, node.Sel.Name)
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

func declOrBodyShadowsIdent(f *ast.File, fn *ast.FuncDecl, ident string) bool {
	if f != nil {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.Name == ident {
					return true
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if n.Name == ident {
								return true
							}
						}
					case *ast.TypeSpec:
						if s.Name.Name == ident {
							return true
						}
					}
				}
			}
		}
	}
	if fn == nil {
		return false
	}
	for _, list := range []*ast.FieldList{fn.Recv, fn.Type.Params, fn.Type.Results} {
		if list == nil {
			continue
		}
		for _, field := range list.List {
			for _, n := range field.Names {
				if n.Name == ident {
					return true
				}
			}
		}
	}
	shadowed := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if shadowed || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.AssignStmt:
			if node.Tok == token.DEFINE {
				for _, lhs := range node.Lhs {
					if id, ok := unwrapParens(lhs).(*ast.Ident); ok && id.Name == ident {
						shadowed = true
						return false
					}
				}
			}
		case *ast.ValueSpec:
			for _, id := range node.Names {
				if id.Name == ident {
					shadowed = true
					return false
				}
			}
		case *ast.TypeSpec:
			if node.Name.Name == ident {
				shadowed = true
				return false
			}
		}
		return true
	})
	return shadowed
}

func verifyOSPackageAST(files []*ast.File, osRuntimePullMap map[string]string, osAnyLinknameLocals map[string]bool) ([]string, error) {
	osReserved := map[string]bool{
		"testlog": true, "io": true, "syscall": true, "unsafe": true, "fs": true, "errors": true, "runtime": true,
		"nil": true, "true": true, "false": true, "len": true, "panic": true,
		"error": true, "int": true, "uintptr": true, "string": true, "byte": true, "bool": true,
		"File": true, "file": true, "ErrInvalid": true, "ErrClosed": true, "PathError": true,
	}
	osNoFileReserved := map[string]bool{
		"testlog": true, "io": true, "syscall": true, "unsafe": true, "fs": true, "errors": true, "runtime": true,
		"nil": true, "true": true, "false": true, "len": true, "panic": true,
		"error": true, "int": true, "uintptr": true, "string": true, "byte": true, "bool": true,
		"File": true, "ErrInvalid": true, "ErrClosed": true, "PathError": true,
	}
	osPkgScopeReserved := map[string]bool{
		"testlog": true, "io": true, "syscall": true, "unsafe": true, "fs": true, "errors": true, "runtime": true,
		"nil": true, "true": true, "false": true, "len": true, "panic": true,
		"error": true, "int": true, "uintptr": true, "string": true, "byte": true, "bool": true,
	}
	rawFileMethodShadowsReserved := func(fn *ast.FuncDecl) bool {
		if fn == nil {
			return true
		}
		if recv := recvVarName(fn); recv != "" && osNoFileReserved[recv] {
			return true
		}
		if fn.Type != nil {
			for _, flist := range []*ast.FieldList{fn.Type.Params, fn.Type.Results} {
				if flist == nil {
					continue
				}
				for _, f := range flist.List {
					for _, id := range f.Names {
						if osNoFileReserved[id.Name] {
							return true
						}
					}
				}
			}
		}
		return bodyDeclaresAnyIdent(fn.Body, osNoFileReserved)
	}
	requiredBoundaryFuncs := map[string]bool{
		"Getenv": true, "LookupEnv": true, "Open": true, "Create": true,
		"OpenFile": true, "openFileNolog": true, "openDir": true, "ReadFile": true, "ReadDir": true,
		"Stat": true, "Lstat": true, "Chdir": true, "Getwd": true, "Exit": true, "fixCount": true,
	}
	requiredFileSinkMethods := map[string]bool{
		"Write": true, "WriteString": true, "Close": true,
		"write": true, "checkValid": true, "wrapErr": true,
		"Fd": true, "fd": true,
	}
	requiredRawFileMethods := map[string]bool{
		"close": true, "decref": true, "destroy": true,
	}

	var importsTestlog bool
	fileImportsTestlog := map[*ast.File]bool{}
	fileImportsIO := map[*ast.File]bool{}
	fileImportsSyscall := map[*ast.File]bool{}
	fileImportsUnsafe := map[*ast.File]bool{}
	fileImportsIOFS := map[*ast.File]bool{}
	fileImportsErrors := map[*ast.File]bool{}
	fileImportsRuntime := map[*ast.File]bool{}
	funcFile := map[*ast.FuncDecl]*ast.File{}
	pkgDeclCounts := map[string]int{}
	hasErrInvalidInit := false
	hasErrClosedInit := false
	osErrConstCand := map[string]bool{}
	osErrVarCand := map[string]bool{}
	nonAliasStructSpecs := map[string]*ast.TypeSpec{}

	topFuncs := map[string]*ast.FuncDecl{}
	allTopFuncs := map[string]*ast.FuncDecl{}
	fileMethods := map[string]*ast.FuncDecl{}
	allFileMethods := map[string]*ast.FuncDecl{}
	fileMethodCounts := map[string]int{}
	rawFileMethods := map[string]*ast.FuncDecl{}
	allRawFileMethods := map[string]*ast.FuncDecl{}
	rawFileMethodCounts := map[string]int{}
	allFileStatMethods := map[string]*ast.FuncDecl{}
	fileStatMethodCounts := map[string]int{}
	var dirInfoCloseFn *ast.FuncDecl
	var fileTypeSpec, rawFileTypeSpec *ast.TypeSpec

	isNonEmptyStringLit := func(expr ast.Expr) bool {
		lit, ok := unwrapParens(expr).(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return false
		}
		unq, err := strconv.Unquote(lit.Value)
		return err == nil && unq != ""
	}

	isVerifiedOSSentinelInit := func(f *ast.File, name string, expr ast.Expr) bool {
		if expr == nil {
			return false
		}
		if fileImportsIOFS[f] {
			if _, ok := isSelectorBaseField(expr, "fs", name); ok {
				return true
			}
		}
		if fileImportsErrors[f] {
			if call, ok := unwrapParens(expr).(*ast.CallExpr); ok && !call.Ellipsis.IsValid() && len(call.Args) == 1 {
				if _, okSel := isSelectorBaseField(call.Fun, "errors", "New"); okSel {
					if isNonEmptyStringLit(call.Args[0]) {
						return true
					}
				}
			}
		}
		return false
	}

	isVerifiedNonNilOSErrVarInit := func(f *ast.File, expr ast.Expr) bool {
		if expr == nil {
			return false
		}
		if fileImportsIOFS[f] {
			if sel, okS := unwrapParens(expr).(*ast.SelectorExpr); okS {
				if _, okFS := isIdentNamed(sel.X, "fs"); okFS && strings.HasPrefix(sel.Sel.Name, "Err") {
					return true
				}
			}
		}
		if fileImportsErrors[f] {
			if call, ok := unwrapParens(expr).(*ast.CallExpr); ok && !call.Ellipsis.IsValid() && len(call.Args) == 1 {
				if _, okSel := isSelectorBaseField(call.Fun, "errors", "New"); okSel && isNonEmptyStringLit(call.Args[0]) {
					return true
				}
			}
		}
		if fileImportsSyscall[f] {
			if call, ok := unwrapParens(expr).(*ast.CallExpr); ok && !call.Ellipsis.IsValid() && len(call.Args) == 1 {
				if _, okSel := isSelectorBaseField(call.Fun, "syscall", "NewError"); okSel && isNonEmptyStringLit(call.Args[0]) {
					return true
				}
			}
		}
		return false
	}

	for _, f := range files {
		for _, imp := range f.Imports {
			importPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return nil, err
			}
			if imp.Name != nil && (imp.Name.Name == "." || osReserved[imp.Name.Name]) {
				return nil, fmt.Errorf("os: forbidden or shadowing import alias %q", imp.Name.Name)
			}
			switch importPath {
			case "internal/testlog":
				if imp.Name != nil {
					return nil, fmt.Errorf("os: aliased import of internal/testlog forbidden")
				}
				importsTestlog = true
				fileImportsTestlog[f] = true
			case "io":
				if imp.Name != nil {
					return nil, fmt.Errorf("os: aliased import of io forbidden")
				}
				fileImportsIO[f] = true
			case "syscall":
				if imp.Name != nil {
					return nil, fmt.Errorf("os: aliased import of syscall forbidden")
				}
				fileImportsSyscall[f] = true
			case "unsafe":
				if imp.Name != nil && imp.Name.Name != "_" {
					return nil, fmt.Errorf("os: aliased import of unsafe forbidden")
				}
				if imp.Name == nil {
					fileImportsUnsafe[f] = true
				}
			case "io/fs":
				if imp.Name != nil {
					return nil, fmt.Errorf("os: aliased import of io/fs forbidden")
				}
				fileImportsIOFS[f] = true
			case "errors":
				if imp.Name != nil {
					return nil, fmt.Errorf("os: aliased import of errors forbidden")
				}
				fileImportsErrors[f] = true
			case "runtime":
				if imp.Name != nil {
					return nil, fmt.Errorf("os: aliased import of runtime forbidden")
				}
				fileImportsRuntime[f] = true
			}
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.ValueSpec:
						for idx, id := range sp.Names {
							if osPkgScopeReserved[id.Name] {
								return nil, fmt.Errorf("os: package declaration shadows %s", id.Name)
							}
							if id.Name != "_" {
								pkgDeclCounts[id.Name]++
							}
							if d.Tok == token.CONST && id.Name != "_" && sp.Type == nil && len(sp.Values) == len(sp.Names) && fileImportsSyscall[f] {
								if sel, okS := unwrapParens(sp.Values[idx]).(*ast.SelectorExpr); okS {
									if _, okSys := isIdentNamed(sel.X, "syscall"); okSys && strings.HasPrefix(sel.Sel.Name, "E") {
										osErrConstCand[id.Name] = true
									}
								}
							}
							if d.Tok == token.VAR && id.Name != "_" && len(sp.Values) == len(sp.Names) && isVerifiedNonNilOSErrVarInit(f, sp.Values[idx]) {
								osErrVarCand[id.Name] = true
							}
							if d.Tok == token.VAR && (id.Name == "ErrInvalid" || id.Name == "ErrClosed") {
								if len(sp.Values) != len(sp.Names) || !isVerifiedOSSentinelInit(f, id.Name, sp.Values[idx]) {
									return nil, fmt.Errorf("os: %s must have non-nil initializer", id.Name)
								}
								if id.Name == "ErrInvalid" {
									hasErrInvalidInit = true
								} else {
									hasErrClosedInit = true
								}
							}
						}
					case *ast.TypeSpec:
						if sp.Name != nil {
							if osPkgScopeReserved[sp.Name.Name] {
								return nil, fmt.Errorf("os: type declaration shadows %s", sp.Name.Name)
							}
							if sp.Name.Name != "_" {
								pkgDeclCounts[sp.Name.Name]++
								if !sp.Assign.IsValid() {
									if _, okST := unwrapParens(sp.Type).(*ast.StructType); okST {
										nonAliasStructSpecs[sp.Name.Name] = sp
									}
								}
							}
							switch sp.Name.Name {
							case "File":
								fileTypeSpec = sp
							case "file":
								rawFileTypeSpec = sp
							}
						}
					}
				}
			case *ast.FuncDecl:
				funcFile[d] = f
				if d.Recv == nil {
					if osReserved[d.Name.Name] {
						return nil, fmt.Errorf("os: function declaration shadows %s", d.Name.Name)
					}
					if d.Name.Name != "init" && d.Name.Name != "_" {
						pkgDeclCounts[d.Name.Name]++
						allTopFuncs[d.Name.Name] = d
					}
					if requiredBoundaryFuncs[d.Name.Name] {
						if d.Body == nil {
							return nil, fmt.Errorf("os: boundary function %s cannot be bodyless", d.Name.Name)
						}
						if _, dup := topFuncs[d.Name.Name]; dup {
							return nil, fmt.Errorf("os: duplicate boundary function %s", d.Name.Name)
						}
						topFuncs[d.Name.Name] = d
					}
				} else if len(d.Recv.List) == 1 {
					rType := recvTypeName(d.Recv.List[0].Type)
					_, isPtrRecv := unwrapParens(d.Recv.List[0].Type).(*ast.StarExpr)
					switch rType {
					case "File":
						fileMethodCounts[d.Name.Name]++
						allFileMethods[d.Name.Name] = d
						if requiredFileSinkMethods[d.Name.Name] {
							if !isPtrRecv || d.Body == nil {
								return nil, fmt.Errorf("os: File.%s must be a concrete pointer-receiver method", d.Name.Name)
							}
							if _, dup := fileMethods[d.Name.Name]; dup {
								return nil, fmt.Errorf("os: duplicate (*File).%s method", d.Name.Name)
							}
							fileMethods[d.Name.Name] = d
						}
					case "file":
						rawFileMethodCounts[d.Name.Name]++
						allRawFileMethods[d.Name.Name] = d
						if requiredRawFileMethods[d.Name.Name] {
							if !isPtrRecv || d.Body == nil {
								return nil, fmt.Errorf("os: file.%s must be a concrete pointer-receiver method", d.Name.Name)
							}
							if _, dup := rawFileMethods[d.Name.Name]; dup {
								return nil, fmt.Errorf("os: duplicate (*file).%s method", d.Name.Name)
							}
							rawFileMethods[d.Name.Name] = d
						}
					case "fileStat":
						fileStatMethodCounts[d.Name.Name]++
						allFileStatMethods[d.Name.Name] = d
					case "dirInfo":
						if d.Name.Name == "close" {
							if !isPtrRecv || d.Body == nil || dirInfoCloseFn != nil {
								return nil, fmt.Errorf("os: invalid or duplicate (*dirInfo).close")
							}
							dirInfoCloseFn = d
						}
					}
				}
			}
		}
	}
	if !importsTestlog {
		return nil, fmt.Errorf("os: missing internal/testlog import")
	}
	if !hasErrInvalidInit || pkgDeclCounts["ErrInvalid"] != 1 || !hasErrClosedInit || pkgDeclCounts["ErrClosed"] != 1 {
		return nil, fmt.Errorf("os: missing unique non-nil ErrInvalid/ErrClosed sentinel declarations")
	}
	if err := verifyOSFileStructTypes(fileTypeSpec, rawFileTypeSpec, pkgDeclCounts); err != nil {
		return nil, err
	}
	if err := verifyOSExitIntegrity(files, topFuncs["Exit"], funcFile, fileImportsTestlog, fileImportsSyscall, osReserved); err != nil {
		return nil, err
	}

	// Ensure ErrInvalid and ErrClosed are never reassigned or address-taken anywhere in os,
	// and collect unmutated non-nil package error identifiers.
	mutatedErrVarCands := map[string]bool{}
	for _, f := range files {
		sentinelMutated := false
		ast.Inspect(f, func(n ast.Node) bool {
			if sentinelMutated || n == nil {
				return false
			}
			markMut := func(expr ast.Expr) {
				id, ok := unwrapParens(expr).(*ast.Ident)
				if !ok {
					return
				}
				if id.Name == "ErrInvalid" || id.Name == "ErrClosed" {
					sentinelMutated = true
				}
				if osErrVarCand[id.Name] {
					mutatedErrVarCands[id.Name] = true
				}
			}
			switch node := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					markMut(lhs)
				}
			case *ast.RangeStmt:
				if node.Key != nil {
					markMut(node.Key)
				}
				if node.Value != nil {
					markMut(node.Value)
				}
			case *ast.IncDecStmt:
				markMut(node.X)
			case *ast.UnaryExpr:
				if node.Op == token.AND {
					markMut(node.X)
				}
			}
			return !sentinelMutated
		})
		if sentinelMutated {
			return nil, fmt.Errorf("os: ErrInvalid or ErrClosed mutated or address-taken")
		}
	}
	verifiedNonNilOSErrIdents := map[string]bool{
		"ErrInvalid": true,
		"ErrClosed":  true,
	}
	for name := range osErrConstCand {
		if pkgDeclCounts[name] == 1 && !osAnyLinknameLocals[name] {
			verifiedNonNilOSErrIdents[name] = true
		}
	}
	for name := range osErrVarCand {
		if pkgDeclCounts[name] == 1 && !osAnyLinknameLocals[name] && !mutatedErrVarCands[name] {
			verifiedNonNilOSErrIdents[name] = true
		}
	}

	osInactive := discoverOSInactiveState(files, osRuntimePullMap, osAnyLinknameLocals)
	usedRuntimeGates := map[string]bool{}
	skipInactiveHookIf := func(stmt ast.Stmt, fn *ast.FuncDecl) bool {
		gates, ok := osInactive.checkInactiveHookIf(stmt, fn)
		if !ok {
			return false
		}
		for _, g := range gates {
			if g != "" {
				usedRuntimeGates[g] = true
			}
		}
		return true
	}

	isDirectTestlogCall := func(stmt ast.Stmt, hookName, wantArg string) bool {
		es, ok := stmt.(*ast.ExprStmt)
		if !ok {
			return false
		}
		call, ok := unwrapParens(es.X).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) != 1 {
			return false
		}
		if _, okArg := isIdentNamed(call.Args[0], wantArg); !okArg {
			return false
		}
		_, okSel := isSelectorBaseField(call.Fun, "testlog", hookName)
		return okSel
	}

	firstParamChecked := func(fn *ast.FuncDecl, minParams int, needTestlogImport bool) (string, error) {
		if fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.Params == nil {
			return "", fmt.Errorf("missing function")
		}
		if needTestlogImport && !fileImportsTestlog[funcFile[fn]] {
			return "", fmt.Errorf("file defining %s missing internal/testlog import", fn.Name.Name)
		}
		if funcShadowsAnyIdent(fn, osReserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
			return "", fmt.Errorf("function %s shadows reserved identifier or has control-flow/recover bypass", fn.Name.Name)
		}
		pNames := paramNamesFlat(fn.Type.Params)
		if len(pNames) < minParams || pNames[0] == "" || pNames[0] == "_" {
			return "", fmt.Errorf("function %s invalid first parameter", fn.Name.Name)
		}
		return pNames[0], nil
	}

	// 1. Getenv(key) & LookupEnv(key): Body.List[0] must be testlog.Getenv(p0).
	for _, fnName := range []string{"Getenv", "LookupEnv"} {
		fn := topFuncs[fnName]
		p0, err := firstParamChecked(fn, 1, true)
		if err != nil {
			return nil, fmt.Errorf("os: %s: %w", fnName, err)
		}
		if len(fn.Body.List) < 2 || !isDirectTestlogCall(fn.Body.List[0], "Getenv", p0) {
			return nil, fmt.Errorf("os: %s must execute testlog.Getenv(%s) as its first statement", fnName, p0)
		}
	}

	// 2. Open(name) & Create(name): single return delegating to OpenFile(p0, ...).
	for _, fnName := range []string{"Open", "Create"} {
		fn := topFuncs[fnName]
		p0, err := firstParamChecked(fn, 1, false)
		if err != nil {
			return nil, fmt.Errorf("os: %s: %w", fnName, err)
		}
		if len(fn.Body.List) != 1 {
			return nil, fmt.Errorf("os: %s must be a single-statement delegation to OpenFile", fnName)
		}
		ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return nil, fmt.Errorf("os: %s must return OpenFile(%s, ...)", fnName, p0)
		}
		call, ok := unwrapParens(ret.Results[0]).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) != 3 {
			return nil, fmt.Errorf("os: %s invalid OpenFile call arity", fnName)
		}
		if _, okFun := isIdentNamed(call.Fun, "OpenFile"); !okFun {
			return nil, fmt.Errorf("os: %s does not call OpenFile", fnName)
		}
		if _, okArg := isIdentNamed(call.Args[0], p0); !okArg {
			return nil, fmt.Errorf("os: %s does not forward %s to OpenFile", fnName, p0)
		}
	}

	// 3. OpenFile(name, flag, perm), openFileNolog(name, flag, perm), & openDir(name).
	{
		ofFn := topFuncs["OpenFile"]
		p0, err := firstParamChecked(ofFn, 3, true)
		if err != nil {
			return nil, fmt.Errorf("os: OpenFile: %w", err)
		}
		ofParams := paramNamesFlat(ofFn.Type.Params)
		if len(ofParams) != 3 || ofParams[1] == "" || ofParams[1] == "_" || ofParams[2] == "" || ofParams[2] == "_" {
			return nil, fmt.Errorf("os: OpenFile invalid parameters")
		}
		if bodyMutatesOrTakesAddrOfAny(ofFn.Body, map[string]bool{p0: true, ofParams[1]: true, ofParams[2]: true}) || bodyDeclaresAnyIdent(ofFn.Body, map[string]bool{p0: true, ofParams[1]: true, ofParams[2]: true}) {
			return nil, fmt.Errorf("os: OpenFile mutates or shadows parameters")
		}
		if len(ofFn.Body.List) < 2 || !isDirectTestlogCall(ofFn.Body.List[0], "Open", p0) {
			return nil, fmt.Errorf("os: OpenFile must execute testlog.Open(%s) as its first statement", p0)
		}
		isOpenFileNologCall := func(expr ast.Expr) bool {
			c, okC := unwrapParens(expr).(*ast.CallExpr)
			if !okC || c.Ellipsis.IsValid() || len(c.Args) != 3 {
				return false
			}
			_, okF := isIdentNamed(c.Fun, "openFileNolog")
			_, ok0 := isIdentNamed(c.Args[0], p0)
			_, ok1 := isIdentNamed(c.Args[1], ofParams[1])
			_, ok2 := isIdentNamed(c.Args[2], ofParams[2])
			return okF && ok0 && ok1 && ok2
		}
		openFileOK := false
		if len(ofFn.Body.List) == 2 {
			if ret, okR := ofFn.Body.List[1].(*ast.ReturnStmt); okR && len(ret.Results) == 1 && isOpenFileNologCall(ret.Results[0]) {
				openFileOK = true
			}
		} else if len(ofFn.Body.List) >= 4 {
			as, okAs := ofFn.Body.List[1].(*ast.AssignStmt)
			ifs, okIf := ofFn.Body.List[2].(*ast.IfStmt)
			retLast, okRet := ofFn.Body.List[len(ofFn.Body.List)-1].(*ast.ReturnStmt)
			if okAs && as.Tok == token.DEFINE && len(as.Lhs) == 2 && len(as.Rhs) == 1 && isOpenFileNologCall(as.Rhs[0]) && okIf && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 && okRet && len(retLast.Results) == 2 {
				fID, okF := unwrapParens(as.Lhs[0]).(*ast.Ident)
				eID, okE := unwrapParens(as.Lhs[1]).(*ast.Ident)
				if okF && okE && fID.Name != "" && fID.Name != "_" && eID.Name != "" && eID.Name != "_" && fID.Name != eID.Name && condChecksNonZeroErr(ifs.Cond) == eID.Name {
					if errRet, okER := ifs.Body.List[0].(*ast.ReturnStmt); okER && len(errRet.Results) == 2 {
						_, okNil0 := isIdentNamed(errRet.Results[0], "nil")
						_, okErr1 := isIdentNamed(errRet.Results[1], eID.Name)
						_, okRetF := isIdentNamed(retLast.Results[0], fID.Name)
						_, okRetNil := isIdentNamed(retLast.Results[1], "nil")
						midOK := okNil0 && okErr1 && okRetF && okRetNil && !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: ofFn.Body.List[2:]}, map[string]bool{fID.Name: true})
						for _, mid := range ofFn.Body.List[3 : len(ofFn.Body.List)-1] {
							mAs, okM := mid.(*ast.AssignStmt)
							if !okM || mAs.Tok != token.ASSIGN || len(mAs.Lhs) != 1 || len(mAs.Rhs) != 1 {
								midOK = false
								break
							}
							sel, okS := unwrapParens(mAs.Lhs[0]).(*ast.SelectorExpr)
							if !okS {
								midOK = false
								break
							}
							_, okBase := isIdentNamed(sel.X, fID.Name)
							if !okBase || sel.Sel.Name == "file" || sel.Sel.Name == "pfd" || sel.Sel.Name == "sysfd" || sel.Sel.Name == "name" || exprContainsAnyCall(mAs.Rhs[0]) {
								midOK = false
								break
							}
						}
						openFileOK = midOK
					}
				}
			}
		}
		if !openFileOK {
			return nil, fmt.Errorf("os: OpenFile must delegate directly to openFileNolog")
		}
		if err := verifyOSOpenFileNolog(topFuncs["openFileNolog"], allTopFuncs, funcFile, fileImportsSyscall, osNoFileReserved, osAnyLinknameLocals, skipInactiveHookIf); err != nil {
			return nil, err
		}

		odFn := topFuncs["openDir"]
		odP0, err := firstParamChecked(odFn, 1, true)
		if err != nil {
			return nil, fmt.Errorf("os: openDir: %w", err)
		}
		if len(odFn.Body.List) < 2 || !isDirectTestlogCall(odFn.Body.List[0], "Open", odP0) {
			return nil, fmt.Errorf("os: openDir must execute testlog.Open(%s) as its first statement", odP0)
		}
	}

	// 4. ReadFile(name) & ReadDir(name).
	{
		rfFn := topFuncs["ReadFile"]
		rfP0, err := firstParamChecked(rfFn, 1, false)
		if err != nil {
			return nil, fmt.Errorf("os: ReadFile: %w", err)
		}
		if err := verifyOSReadFile(rfFn, rfP0, allTopFuncs, allFileMethods, allRawFileMethods, osNoFileReserved, osAnyLinknameLocals, skipInactiveHookIf); err != nil {
			return nil, err
		}

		rdFn := topFuncs["ReadDir"]
		rdP0, err := firstParamChecked(rdFn, 1, false)
		if err != nil {
			return nil, fmt.Errorf("os: ReadDir: %w", err)
		}
		if len(rdFn.Body.List) < 2 {
			return nil, fmt.Errorf("os: ReadDir missing body statements")
		}
		as, ok := rdFn.Body.List[0].(*ast.AssignStmt)
		if !ok || (as.Tok != token.DEFINE && as.Tok != token.ASSIGN) || len(as.Lhs) != 2 || len(as.Rhs) != 1 {
			return nil, fmt.Errorf("os: ReadDir first statement must bind logged open result")
		}
		call, ok := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) < 1 {
			return nil, fmt.Errorf("os: ReadDir invalid open call")
		}
		calleeID, ok := unwrapParens(call.Fun).(*ast.Ident)
		if !ok || (calleeID.Name != "openDir" && calleeID.Name != "Open" && calleeID.Name != "OpenFile") {
			return nil, fmt.Errorf("os: ReadDir first statement does not call logged open helper")
		}
		if _, okArg := isIdentNamed(call.Args[0], rdP0); !okArg {
			return nil, fmt.Errorf("os: ReadDir does not forward %s to %s", rdP0, calleeID.Name)
		}
	}

	// 5. Stat(name) & Lstat(name): optional verified inactive hook then testlog.Stat(p0).
	for _, fnName := range []string{"Stat", "Lstat"} {
		fn := topFuncs[fnName]
		p0, err := firstParamChecked(fn, 1, true)
		if err != nil {
			return nil, fmt.Errorf("os: %s: %w", fnName, err)
		}
		pos := 0
		for pos < len(fn.Body.List) && skipInactiveHookIf(fn.Body.List[pos], fn) {
			pos++
		}
		if len(fn.Body.List) < pos+2 || !isDirectTestlogCall(fn.Body.List[pos], "Stat", p0) {
			return nil, fmt.Errorf("os: %s must execute testlog.Stat(%s) before stat syscall", fnName, p0)
		}
	}

	// 6. Chdir(dir) & Getwd(): optional verified inactive hook, syscall.Chdir(p0) error-branch testlog.Open(p0),
	// verified mid-statements, testlog.Logger().Chdir(wd) on success, return nil; plus Getwd() integrity.
	{
		fn := topFuncs["Chdir"]
		p0, err := firstParamChecked(fn, 1, true)
		if err != nil {
			return nil, fmt.Errorf("os: Chdir: %w", err)
		}
		if !fileImportsSyscall[funcFile[fn]] {
			return nil, fmt.Errorf("os: file defining Chdir missing syscall import")
		}
		pos := 0
		for pos < len(fn.Body.List) && skipInactiveHookIf(fn.Body.List[pos], fn) {
			pos++
		}
		if len(fn.Body.List) < pos+3 {
			return nil, fmt.Errorf("os: Chdir body too short")
		}
		if bodyMutatesOrTakesAddrOfAny(fn.Body, map[string]bool{p0: true}) || bodyDeclaresAnyIdent(fn.Body, map[string]bool{p0: true}) {
			return nil, fmt.Errorf("os: Chdir mutates or shadows parameter %s", p0)
		}
		ifs0, ok := fn.Body.List[pos].(*ast.IfStmt)
		if !ok || ifs0.Init == nil || ifs0.Else != nil || len(ifs0.Body.List) != 2 {
			return nil, fmt.Errorf("os: Chdir missing syscall.Chdir error guard")
		}
		initAs, ok := ifs0.Init.(*ast.AssignStmt)
		if !ok || initAs.Tok != token.DEFINE || len(initAs.Lhs) != 1 || len(initAs.Rhs) != 1 {
			return nil, fmt.Errorf("os: Chdir invalid syscall.Chdir init assignment")
		}
		eID, ok := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
		sysCall, okC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
		if !ok || !okC || eID.Name == "" || eID.Name == "_" || condChecksNonZeroErr(ifs0.Cond) != eID.Name || sysCall.Ellipsis.IsValid() || len(sysCall.Args) != 1 {
			return nil, fmt.Errorf("os: Chdir invalid syscall.Chdir condition or call")
		}
		if _, okSel := isSelectorBaseField(sysCall.Fun, "syscall", "Chdir"); !okSel {
			return nil, fmt.Errorf("os: Chdir does not call syscall.Chdir")
		}
		if _, okArg := isIdentNamed(sysCall.Args[0], p0); !okArg {
			return nil, fmt.Errorf("os: Chdir does not pass %s to syscall.Chdir", p0)
		}
		if !isDirectTestlogCall(ifs0.Body.List[0], "Open", p0) {
			return nil, fmt.Errorf("os: Chdir failure branch missing testlog.Open(%s)", p0)
		}
		errRet, ok := ifs0.Body.List[1].(*ast.ReturnStmt)
		if !ok || len(errRet.Results) != 1 {
			return nil, fmt.Errorf("os: Chdir failure branch invalid return")
		}
		_, okDirectChdirErr := isIdentNamed(errRet.Results[0], eID.Name)
		uChdirErr, okUChdir := unwrapParens(errRet.Results[0]).(*ast.UnaryExpr)
		_, tChdirErr := compositeWriterLit(errRet.Results[0])
		if !okDirectChdirErr && (!okUChdir || uChdirErr.Op != token.AND || tChdirErr != "PathError") {
			return nil, fmt.Errorf("os: Chdir failure branch must return %s or &PathError", eID.Name)
		}
		for _, mid := range fn.Body.List[pos+1 : len(fn.Body.List)-2] {
			badMid := false
			ast.Inspect(mid, func(n ast.Node) bool {
				if badMid || n == nil {
					return false
				}
				switch call := n.(type) {
				case *ast.ReturnStmt, *ast.DeferStmt, *ast.GoStmt, *ast.FuncLit, *ast.BranchStmt, *ast.LabeledStmt:
					badMid = true
					return false
				case *ast.CallExpr:
					if call.Ellipsis.IsValid() {
						badMid = true
						return false
					}
					sel, okS := unwrapParens(call.Fun).(*ast.SelectorExpr)
					if !okS {
						badMid = true
						return false
					}
					if _, okBase := unwrapParens(sel.X).(*ast.Ident); !okBase {
						badMid = true
						return false
					}
					switch sel.Sel.Name {
					case "Lock", "Unlock":
						if len(call.Args) != 0 {
							badMid = true
							return false
						}
					case "IsAbs":
						if len(call.Args) != 1 {
							badMid = true
							return false
						}
						if _, okP0 := isIdentNamed(call.Args[0], p0); !okP0 {
							badMid = true
							return false
						}
					default:
						badMid = true
						return false
					}
				}
				return true
			})
			if badMid {
				return nil, fmt.Errorf("os: Chdir has forbidden control flow or call before testlog.Logger().Chdir")
			}
		}
		logIf, ok := fn.Body.List[len(fn.Body.List)-2].(*ast.IfStmt)
		if !ok || logIf.Init == nil || logIf.Else != nil || len(logIf.Body.List) != 2 {
			return nil, fmt.Errorf("os: Chdir missing testlog.Logger() block")
		}
		logInit, ok := logIf.Init.(*ast.AssignStmt)
		if !ok || logInit.Tok != token.DEFINE || len(logInit.Lhs) != 1 || len(logInit.Rhs) != 1 {
			return nil, fmt.Errorf("os: Chdir invalid testlog.Logger() assignment")
		}
		logID, ok1 := unwrapParens(logInit.Lhs[0]).(*ast.Ident)
		logCall, ok2 := unwrapParens(logInit.Rhs[0]).(*ast.CallExpr)
		if !ok1 || !ok2 || logID.Name == "" || logID.Name == "_" || condChecksNonZeroErr(logIf.Cond) != logID.Name || logCall.Ellipsis.IsValid() || len(logCall.Args) != 0 {
			return nil, fmt.Errorf("os: Chdir invalid testlog.Logger() guard")
		}
		if _, okSel := isSelectorBaseField(logCall.Fun, "testlog", "Logger"); !okSel {
			return nil, fmt.Errorf("os: Chdir does not call testlog.Logger()")
		}
		wdAs, ok := logIf.Body.List[0].(*ast.AssignStmt)
		if !ok || wdAs.Tok != token.DEFINE || len(wdAs.Lhs) != 2 || len(wdAs.Rhs) != 1 {
			return nil, fmt.Errorf("os: Chdir missing Getwd() assignment")
		}
		wdID, ok1 := unwrapParens(wdAs.Lhs[0]).(*ast.Ident)
		wdErrID, ok2 := unwrapParens(wdAs.Lhs[1]).(*ast.Ident)
		wdCall, ok3 := unwrapParens(wdAs.Rhs[0]).(*ast.CallExpr)
		if !ok1 || !ok2 || !ok3 || wdID.Name == "" || wdID.Name == "_" || wdErrID.Name == "" || wdErrID.Name == "_" || wdCall.Ellipsis.IsValid() || len(wdCall.Args) != 0 {
			return nil, fmt.Errorf("os: Chdir invalid Getwd() call")
		}
		if _, okFun := isIdentNamed(wdCall.Fun, "Getwd"); !okFun {
			return nil, fmt.Errorf("os: Chdir does not call Getwd()")
		}
		wdIf, ok := logIf.Body.List[1].(*ast.IfStmt)
		if !ok || wdIf.Init != nil || wdIf.Else != nil || !condChecksEqErr(wdIf.Cond, wdErrID.Name) || len(wdIf.Body.List) != 1 {
			return nil, fmt.Errorf("os: Chdir missing if err == nil guard around log.Chdir")
		}
		chES, ok := wdIf.Body.List[0].(*ast.ExprStmt)
		if !ok {
			return nil, fmt.Errorf("os: Chdir log.Chdir not an expression statement")
		}
		chCall, ok := unwrapParens(chES.X).(*ast.CallExpr)
		if !ok || chCall.Ellipsis.IsValid() || len(chCall.Args) != 1 {
			return nil, fmt.Errorf("os: Chdir invalid log.Chdir call")
		}
		if _, okSel := isSelectorBaseField(chCall.Fun, logID.Name, "Chdir"); !okSel {
			return nil, fmt.Errorf("os: Chdir does not call %s.Chdir", logID.Name)
		}
		if _, okArg := isIdentNamed(chCall.Args[0], wdID.Name); !okArg {
			return nil, fmt.Errorf("os: Chdir does not pass %s to %s.Chdir", wdID.Name, logID.Name)
		}
		retNil, ok := fn.Body.List[len(fn.Body.List)-1].(*ast.ReturnStmt)
		if !ok || len(retNil.Results) != 1 {
			return nil, fmt.Errorf("os: Chdir missing trailing return nil")
		}
		if _, okNil := isIdentNamed(retNil.Results[0], "nil"); !okNil {
			return nil, fmt.Errorf("os: Chdir trailing return is not nil")
		}
		if err := verifyOSGetwd(files, topFuncs["Getwd"], allTopFuncs, allFileMethods, allRawFileMethods, allFileStatMethods, nonAliasStructSpecs, pkgDeclCounts, fileMethodCounts, rawFileMethodCounts, fileStatMethodCounts, funcFile, fileImportsSyscall, verifiedNonNilOSErrIdents, osReserved, osNoFileReserved, osAnyLinknameLocals, osInactive, skipInactiveHookIf); err != nil {
			return nil, err
		}
	}

	// 7. Verify (*os.File) write/close/fd sink delivery: checkValid, wrapErr, Write, WriteString, write, Fd, fd, Close, (*file).close.
	{
		cvFn := fileMethods["checkValid"]
		if cvFn == nil || len(cvFn.Body.List) < 2 || funcShadowsAnyIdent(cvFn, osReserved) || bodyHasControlFlowOrRecoverBypass(cvFn.Body) {
			return nil, fmt.Errorf("os: missing or invalid (*File).checkValid")
		}
		cvRecv := recvVarName(cvFn)
		if cvRecv == "" || cvFn.Type.Params == nil || cvFn.Type.Params.NumFields() != 1 || !funcReturnsErrorLast(cvFn.Type) || cvFn.Type.Results.NumFields() != 1 {
			return nil, fmt.Errorf("os: (*File).checkValid invalid signature")
		}
		ifs, ok := cvFn.Body.List[0].(*ast.IfStmt)
		if !ok || ifs.Init != nil || ifs.Else != nil || !condChecksEqErr(ifs.Cond, cvRecv) || len(ifs.Body.List) != 1 {
			return nil, fmt.Errorf("os: (*File).checkValid missing nil receiver guard")
		}
		ret, ok := ifs.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return nil, fmt.Errorf("os: (*File).checkValid invalid nil return")
		}
		if _, okErr := isIdentNamed(ret.Results[0], "ErrInvalid"); !okErr {
			return nil, fmt.Errorf("os: (*File).checkValid does not return ErrInvalid")
		}
	}

	{
		weFn := fileMethods["wrapErr"]
		if weFn == nil || len(weFn.Body.List) < 2 || funcShadowsAnyIdent(weFn, osReserved) || bodyHasControlFlowOrRecoverBypass(weFn.Body) || !blockAlwaysReturns(weFn.Body.List) {
			return nil, fmt.Errorf("os: missing or invalid (*File).wrapErr")
		}
		weParams := paramNamesFlat(weFn.Type.Params)
		if recvVarName(weFn) == "" || len(weParams) != 2 || weParams[1] == "" || weParams[1] == "_" || !funcReturnsErrorLast(weFn.Type) || weFn.Type.Results.NumFields() != 1 {
			return nil, fmt.Errorf("os: (*File).wrapErr invalid signature")
		}
		errParam := weParams[1]
		if bodyDeclaresAnyIdent(weFn.Body, map[string]bool{errParam: true}) {
			return nil, fmt.Errorf("os: (*File).wrapErr shadows error parameter")
		}
		badWrapErr := false
		ast.Inspect(weFn.Body, func(n ast.Node) bool {
			if badWrapErr || n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.DeferStmt, *ast.FuncLit:
				badWrapErr = true
				return false
			case *ast.UnaryExpr:
				if node.Op == token.AND {
					if id, ok := unwrapParens(node.X).(*ast.Ident); ok && id.Name == errParam {
						badWrapErr = true
						return false
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range node.Lhs {
					if id, ok := unwrapParens(lhs).(*ast.Ident); ok && id.Name == errParam {
						if node.Tok != token.ASSIGN || i >= len(node.Rhs) {
							badWrapErr = true
							return false
						}
						if _, okEC := isIdentNamed(node.Rhs[i], "ErrClosed"); !okEC {
							badWrapErr = true
							return false
						}
					}
				}
			case *ast.ReturnStmt:
				if len(node.Results) != 1 {
					badWrapErr = true
					return false
				}
				if _, okID := isIdentNamed(node.Results[0], errParam); okID {
					return false
				}
				u, okU := unwrapParens(node.Results[0]).(*ast.UnaryExpr)
				_, tName := compositeWriterLit(node.Results[0])
				if !okU || u.Op != token.AND || tName != "PathError" {
					badWrapErr = true
					return false
				}
			}
			return true
		})
		if badWrapErr {
			return nil, fmt.Errorf("os: (*File).wrapErr may swallow non-nil error")
		}
	}

	{
		wFn := fileMethods["Write"]
		if wFn == nil || len(wFn.Body.List) < 5 || !fileImportsIO[funcFile[wFn]] || funcShadowsAnyIdent(wFn, osReserved) || bodyHasControlFlowOrRecoverBypass(wFn.Body) {
			return nil, fmt.Errorf("os: missing or invalid (*File).Write")
		}
		wRecv := recvVarName(wFn)
		wParams := paramNamesFlat(wFn.Type.Params)
		if wRecv == "" || len(wParams) != 1 || wParams[0] == "" || wParams[0] == "_" || wFn.Type.Results == nil || wFn.Type.Results.NumFields() != 2 || !firstResultIsInt(wFn.Type.Results) || !funcReturnsErrorLast(wFn.Type) {
			return nil, fmt.Errorf("os: (*File).Write invalid signature")
		}
		bParam := wParams[0]
		if bodyMutatesOrTakesAddrOfAny(wFn.Body, map[string]bool{wRecv: true, bParam: true}) || bodyDeclaresAnyIdent(wFn.Body, map[string]bool{wRecv: true, bParam: true}) {
			return nil, fmt.Errorf("os: (*File).Write mutates receiver or slice parameter")
		}
		// List[0]: if err := f.checkValid("write"); err != nil { return 0, err }
		s0, ok := wFn.Body.List[0].(*ast.IfStmt)
		if !ok || s0.Init == nil || s0.Else != nil || len(s0.Body.List) != 1 {
			return nil, fmt.Errorf("os: (*File).Write missing checkValid guard")
		}
		cvAs, ok := s0.Init.(*ast.AssignStmt)
		if !ok || (cvAs.Tok != token.DEFINE && cvAs.Tok != token.ASSIGN) || len(cvAs.Lhs) != 1 || len(cvAs.Rhs) != 1 {
			return nil, fmt.Errorf("os: (*File).Write invalid checkValid assignment")
		}
		cvErrID, ok1 := unwrapParens(cvAs.Lhs[0]).(*ast.Ident)
		cvCall, ok2 := unwrapParens(cvAs.Rhs[0]).(*ast.CallExpr)
		if !ok1 || !ok2 || cvErrID.Name == "" || cvErrID.Name == "_" || condChecksNonZeroErr(s0.Cond) != cvErrID.Name || cvCall.Ellipsis.IsValid() || len(cvCall.Args) != 1 {
			return nil, fmt.Errorf("os: (*File).Write invalid checkValid call")
		}
		if _, okSel := isSelectorBaseField(cvCall.Fun, wRecv, "checkValid"); !okSel {
			return nil, fmt.Errorf("os: (*File).Write does not call %s.checkValid", wRecv)
		}
		cvRet, ok := s0.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(cvRet.Results) != 2 || !isZeroIntLit(cvRet.Results[0]) {
			return nil, fmt.Errorf("os: (*File).Write invalid checkValid return")
		}
		if _, okErr := isIdentNamed(cvRet.Results[1], cvErrID.Name); !okErr {
			return nil, fmt.Errorf("os: (*File).Write checkValid does not propagate error")
		}

		// List[1]: n, e := f.write(b)
		s1, ok := wFn.Body.List[1].(*ast.AssignStmt)
		if !ok || (s1.Tok != token.DEFINE && s1.Tok != token.ASSIGN) || len(s1.Lhs) != 2 || len(s1.Rhs) != 1 {
			return nil, fmt.Errorf("os: (*File).Write missing %s.write(%s) assignment", wRecv, bParam)
		}
		nID, ok1 := unwrapParens(s1.Lhs[0]).(*ast.Ident)
		eID, ok2 := unwrapParens(s1.Lhs[1]).(*ast.Ident)
		wrCall, ok3 := unwrapParens(s1.Rhs[0]).(*ast.CallExpr)
		if !ok1 || !ok2 || !ok3 || nID.Name == "" || nID.Name == "_" || eID.Name == "" || eID.Name == "_" || nID.Name == eID.Name || wrCall.Ellipsis.IsValid() || len(wrCall.Args) != 1 {
			return nil, fmt.Errorf("os: (*File).Write invalid %s.write call", wRecv)
		}
		if _, okSel := isSelectorBaseField(wrCall.Fun, wRecv, "write"); !okSel {
			return nil, fmt.Errorf("os: (*File).Write does not call %s.write", wRecv)
		}
		if _, okArg := isIdentNamed(wrCall.Args[0], bParam); !okArg {
			return nil, fmt.Errorf("os: (*File).Write does not forward %s to %s.write", bParam, wRecv)
		}

		resNames := paramNamesFlat(wFn.Type.Results)
		var errVar string
		if len(resNames) == 2 && resNames[1] != "" && resNames[1] != "_" {
			errVar = resNames[1]
		}
		if errVar == eID.Name {
			return nil, fmt.Errorf("os: (*File).Write aliases raw error and returned error")
		}
		var sawShortWrite, sawWrapErr bool
		for idx := 2; idx < len(wFn.Body.List)-1; idx++ {
			st := wFn.Body.List[idx]
			if ifs, isIf := st.(*ast.IfStmt); isIf && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
				if bin, okB := unwrapParens(ifs.Cond).(*ast.BinaryExpr); okB {
					// Optional: if n < 0 { n = 0 }
					if bin.Op == token.LSS && isZeroIntLit(bin.Y) {
						if _, okN := isIdentNamed(bin.X, nID.Name); okN && !sawShortWrite {
							if as, okA := ifs.Body.List[0].(*ast.AssignStmt); okA && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 && isZeroIntLit(as.Rhs[0]) {
								if _, okNL := isIdentNamed(as.Lhs[0], nID.Name); okNL {
									continue
								}
							}
						}
					}
					// Required: if n != len(b) { err = io.ErrShortWrite }
					if bin.Op == token.NEQ && isLenOfIdentCall(bin.Y, bParam) {
						if _, okN := isIdentNamed(bin.X, nID.Name); okN && !sawShortWrite && !sawWrapErr {
							if as, okA := ifs.Body.List[0].(*ast.AssignStmt); okA && (as.Tok == token.ASSIGN || as.Tok == token.DEFINE) && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
								lhsErr, okL := unwrapParens(as.Lhs[0]).(*ast.Ident)
								_, okSW := isSelectorBaseField(as.Rhs[0], "io", "ErrShortWrite")
								if okL && okSW && lhsErr.Name != "" && lhsErr.Name != "_" && lhsErr.Name != nID.Name && lhsErr.Name != eID.Name && (errVar == "" || errVar == lhsErr.Name) {
									errVar = lhsErr.Name
									sawShortWrite = true
									continue
								}
							}
						}
					}
				}
				// Required: if e != nil { err = f.wrapErr("write", e) }
				if condChecksNonZeroErr(ifs.Cond) == eID.Name && sawShortWrite && !sawWrapErr && errVar != "" {
					if as, okA := ifs.Body.List[0].(*ast.AssignStmt); okA && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
						_, okL := isIdentNamed(as.Lhs[0], errVar)
						weCall, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
						if okL && okC && !weCall.Ellipsis.IsValid() && len(weCall.Args) == 2 {
							_, okSel := isSelectorBaseField(weCall.Fun, wRecv, "wrapErr")
							_, okArg := isIdentNamed(weCall.Args[1], eID.Name)
							if okSel && okArg {
								sawWrapErr = true
								continue
							}
						}
					}
				}
			}
			// Optional: epipecheck(f, e)
			if es, isES := st.(*ast.ExprStmt); isES {
				if c, okC := unwrapParens(es.X).(*ast.CallExpr); okC && !c.Ellipsis.IsValid() && len(c.Args) == 2 {
					_, ok0 := isIdentNamed(c.Args[0], wRecv)
					_, ok1 := isIdentNamed(c.Args[1], eID.Name)
					if cFun, okFun := unwrapParens(c.Fun).(*ast.Ident); okFun && cFun.Name == "epipecheck" && ok0 && ok1 {
						if err := verifyOSEpipecheck(allTopFuncs["epipecheck"], funcFile, fileImportsSyscall, osNoFileReserved, osAnyLinknameLocals); err != nil {
							return nil, err
						}
						continue
					}
				}
			}
			return nil, fmt.Errorf("os: (*File).Write unexpected statement at index %d", idx)
		}
		if !sawShortWrite || !sawWrapErr || errVar == "" {
			return nil, fmt.Errorf("os: (*File).Write missing ErrShortWrite or wrapErr propagation")
		}
		lastRet, ok := wFn.Body.List[len(wFn.Body.List)-1].(*ast.ReturnStmt)
		if !ok || len(lastRet.Results) != 2 {
			return nil, fmt.Errorf("os: (*File).Write invalid final return")
		}
		_, okRN := isIdentNamed(lastRet.Results[0], nID.Name)
		_, okRE := isIdentNamed(lastRet.Results[1], errVar)
		if !okRN || !okRE {
			return nil, fmt.Errorf("os: (*File).Write final return does not return (%s, %s)", nID.Name, errVar)
		}
	}

	{
		wsFn := fileMethods["WriteString"]
		if wsFn == nil || (len(wsFn.Body.List) != 1 && len(wsFn.Body.List) != 2) || funcShadowsAnyIdent(wsFn, osReserved) || bodyHasControlFlowOrRecoverBypass(wsFn.Body) {
			return nil, fmt.Errorf("os: missing or invalid (*File).WriteString")
		}
		wsRecv := recvVarName(wsFn)
		wsParams := paramNamesFlat(wsFn.Type.Params)
		if wsRecv == "" || len(wsParams) != 1 || wsParams[0] == "" || wsParams[0] == "_" || wsFn.Type.Results == nil || wsFn.Type.Results.NumFields() != 2 || !firstResultIsInt(wsFn.Type.Results) || !funcReturnsErrorLast(wsFn.Type) {
			return nil, fmt.Errorf("os: (*File).WriteString invalid signature")
		}
		sParam := wsParams[0]
		if len(wsFn.Body.List) == 1 {
			ret, ok := wsFn.Body.List[0].(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				return nil, fmt.Errorf("os: (*File).WriteString invalid 1-stmt return")
			}
			wCall, ok := unwrapParens(ret.Results[0]).(*ast.CallExpr)
			if !ok || wCall.Ellipsis.IsValid() || len(wCall.Args) != 1 {
				return nil, fmt.Errorf("os: (*File).WriteString invalid Write delegation")
			}
			if _, okSel := isSelectorBaseField(wCall.Fun, wsRecv, "Write"); !okSel {
				return nil, fmt.Errorf("os: (*File).WriteString does not call %s.Write", wsRecv)
			}
			conv, ok := unwrapParens(wCall.Args[0]).(*ast.CallExpr)
			if !ok || conv.Ellipsis.IsValid() || len(conv.Args) != 1 {
				return nil, fmt.Errorf("os: (*File).WriteString invalid []byte conversion")
			}
			at, okAT := unwrapParens(conv.Fun).(*ast.ArrayType)
			_, okByte := isIdentNamed(at.Elt, "byte")
			_, okS := isIdentNamed(conv.Args[0], sParam)
			if !okAT || at.Len != nil || !okByte || !okS {
				return nil, fmt.Errorf("os: (*File).WriteString does not convert %s to []byte", sParam)
			}
		} else {
			if !fileImportsUnsafe[funcFile[wsFn]] {
				return nil, fmt.Errorf("os: (*File).WriteString unsafe.Slice form missing unsafe import")
			}
			as, ok := wsFn.Body.List[0].(*ast.AssignStmt)
			if !ok || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return nil, fmt.Errorf("os: (*File).WriteString invalid unsafe.Slice assignment")
			}
			bID, ok1 := unwrapParens(as.Lhs[0]).(*ast.Ident)
			slCall, ok2 := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
			if !ok1 || !ok2 || bID.Name == "" || bID.Name == "_" || slCall.Ellipsis.IsValid() || len(slCall.Args) != 2 || !isLenOfIdentCall(slCall.Args[1], sParam) {
				return nil, fmt.Errorf("os: (*File).WriteString invalid unsafe.Slice call")
			}
			if _, okSel := isSelectorBaseField(slCall.Fun, "unsafe", "Slice"); !okSel {
				return nil, fmt.Errorf("os: (*File).WriteString does not call unsafe.Slice")
			}
			sdCall, ok := unwrapParens(slCall.Args[0]).(*ast.CallExpr)
			if !ok || sdCall.Ellipsis.IsValid() || len(sdCall.Args) != 1 {
				return nil, fmt.Errorf("os: (*File).WriteString invalid unsafe.StringData call")
			}
			_, okSDSel := isSelectorBaseField(sdCall.Fun, "unsafe", "StringData")
			_, okSArg := isIdentNamed(sdCall.Args[0], sParam)
			if !okSDSel || !okSArg {
				return nil, fmt.Errorf("os: (*File).WriteString does not pass %s to unsafe.StringData", sParam)
			}
			ret, ok := wsFn.Body.List[1].(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				return nil, fmt.Errorf("os: (*File).WriteString invalid return")
			}
			wCall, ok := unwrapParens(ret.Results[0]).(*ast.CallExpr)
			if !ok || wCall.Ellipsis.IsValid() || len(wCall.Args) != 1 {
				return nil, fmt.Errorf("os: (*File).WriteString invalid Write call")
			}
			_, okWSel := isSelectorBaseField(wCall.Fun, wsRecv, "Write")
			_, okBArg := isIdentNamed(wCall.Args[0], bID.Name)
			if !okWSel || !okBArg {
				return nil, fmt.Errorf("os: (*File).WriteString does not return %s.Write(%s)", wsRecv, bID.Name)
			}
		}
	}

	{
		wrFn := fileMethods["write"]
		if wrFn == nil || len(wrFn.Body.List) < 2 || funcShadowsAnyIdent(wrFn, osReserved) || bodyHasControlFlowOrRecoverBypass(wrFn.Body) {
			return nil, fmt.Errorf("os: missing or invalid (*File).write")
		}
		wrRecv := recvVarName(wrFn)
		wrParams := paramNamesFlat(wrFn.Type.Params)
		if wrRecv == "" || len(wrParams) != 1 || wrParams[0] == "" || wrParams[0] == "_" || wrFn.Type.Results == nil || wrFn.Type.Results.NumFields() != 2 || !firstResultIsInt(wrFn.Type.Results) || !funcReturnsErrorLast(wrFn.Type) {
			return nil, fmt.Errorf("os: (*File).write invalid signature")
		}
		bParam := wrParams[0]
		if bodyMutatesOrTakesAddrOfAny(wrFn.Body, map[string]bool{wrRecv: true, bParam: true}) || bodyDeclaresAnyIdent(wrFn.Body, map[string]bool{wrRecv: true, bParam: true}) {
			return nil, fmt.Errorf("os: (*File).write mutates receiver or slice parameter")
		}
		pos := 0
		for pos < len(wrFn.Body.List) && skipInactiveHookIf(wrFn.Body.List[pos], wrFn) {
			pos++
		}
		validPosixWrite := false
		if pos+1 < len(wrFn.Body.List) {
			if as, ok := wrFn.Body.List[pos].(*ast.AssignStmt); ok && (as.Tok == token.ASSIGN || as.Tok == token.DEFINE) && len(as.Lhs) == 2 && len(as.Rhs) == 1 {
				nID, ok1 := unwrapParens(as.Lhs[0]).(*ast.Ident)
				eID, ok2 := unwrapParens(as.Lhs[1]).(*ast.Ident)
				pfdCall, ok3 := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
				if ok1 && ok2 && ok3 && nID.Name != "" && nID.Name != "_" && eID.Name != "" && eID.Name != "_" && nID.Name != eID.Name && !pfdCall.Ellipsis.IsValid() && len(pfdCall.Args) == 1 {
					if _, okArg := isIdentNamed(pfdCall.Args[0], bParam); okArg {
						if wSel, okS := unwrapParens(pfdCall.Fun).(*ast.SelectorExpr); okS && wSel.Sel.Name == "Write" {
							if _, okPFD := isSelectorBaseField(wSel.X, wrRecv, "pfd"); okPFD {
								midOK := true
								for _, mid := range wrFn.Body.List[pos+1 : len(wrFn.Body.List)-1] {
									es, okES := mid.(*ast.ExprStmt)
									if !okES {
										midOK = false
										break
									}
									kc, okKC := unwrapParens(es.X).(*ast.CallExpr)
									if !okKC || kc.Ellipsis.IsValid() || len(kc.Args) != 1 {
										midOK = false
										break
									}
									_, okKA := isSelectorBaseField(kc.Fun, "runtime", "KeepAlive")
									_, okKArg := isIdentNamed(kc.Args[0], wrRecv)
									if !okKA || !okKArg {
										midOK = false
										break
									}
								}
								if ret, okR := wrFn.Body.List[len(wrFn.Body.List)-1].(*ast.ReturnStmt); midOK && okR && len(ret.Results) == 2 {
									_, okRN := isIdentNamed(ret.Results[0], nID.Name)
									_, okRE := isIdentNamed(ret.Results[1], eID.Name)
									if okRN && okRE {
										validPosixWrite = true
									}
								}
							}
						}
					}
				}
			}
		}
		validPlan9Write := false
		if !validPosixWrite && pos == 0 && len(wrFn.Body.List) == 4 && fileImportsSyscall[funcFile[wrFn]] {
			// Plan 9: writeLock guard, defer writeUnlock, len(b) == 0 guard, return fixCount(syscall.Write(f.sysfd, b)).
			s0, ok0 := wrFn.Body.List[0].(*ast.IfStmt)
			s1, ok1 := wrFn.Body.List[1].(*ast.DeferStmt)
			s2, ok2 := wrFn.Body.List[2].(*ast.IfStmt)
			s3, ok3 := wrFn.Body.List[3].(*ast.ReturnStmt)
			fcFn := topFuncs["fixCount"]
			if ok0 && ok1 && ok2 && ok3 && s0.Else == nil && s2.Init == nil && s2.Else == nil && len(s3.Results) == 1 && fcFn != nil && len(fcFn.Body.List) == 2 && !funcShadowsAnyIdent(fcFn, osReserved) && !bodyHasControlFlowOrRecoverBypass(fcFn.Body) {
				if _, okUnlock := isZeroArgMethodCallOnIdent(s1.Call, wrRecv, "writeUnlock"); okUnlock {
					if bin, okB := unwrapParens(s2.Cond).(*ast.BinaryExpr); okB && bin.Op == token.EQL && isLenOfIdentCall(bin.X, bParam) && isZeroIntLit(bin.Y) && len(s2.Body.List) == 1 {
						if zRet, okZR := s2.Body.List[0].(*ast.ReturnStmt); okZR && len(zRet.Results) == 2 && isZeroIntLit(zRet.Results[0]) {
							if _, okNil := isIdentNamed(zRet.Results[1], "nil"); okNil {
								if fcCall, okFC := unwrapParens(s3.Results[0]).(*ast.CallExpr); okFC && !fcCall.Ellipsis.IsValid() && len(fcCall.Args) == 1 {
									if _, okFCID := isIdentNamed(fcCall.Fun, "fixCount"); okFCID {
										if sc, okSC := unwrapParens(fcCall.Args[0]).(*ast.CallExpr); okSC && !sc.Ellipsis.IsValid() && len(sc.Args) == 2 {
											_, okSCSel := isSelectorBaseField(sc.Fun, "syscall", "Write")
											_, okSysfd := isSelectorBaseField(sc.Args[0], wrRecv, "sysfd")
											_, okBArg := isIdentNamed(sc.Args[1], bParam)
											fcParams := paramNamesFlat(fcFn.Type.Params)
											if okSCSel && okSysfd && okBArg && len(fcParams) == 2 {
												if fcRet, okFCR := fcFn.Body.List[1].(*ast.ReturnStmt); okFCR && len(fcRet.Results) == 2 {
													_, okFN := isIdentNamed(fcRet.Results[0], fcParams[0])
													_, okFE := isIdentNamed(fcRet.Results[1], fcParams[1])
													if okFN && okFE && !bodyMutatesOrTakesAddrOfAny(fcFn.Body, map[string]bool{fcParams[1]: true}) {
														validPlan9Write = true
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		if !validPosixWrite && !validPlan9Write {
			return nil, fmt.Errorf("os: (*File).write has unverified implementation")
		}
	}

	if err := verifyOSFileFdMethods(fileMethods["Fd"], fileMethods["fd"], osNoFileReserved, skipInactiveHookIf); err != nil {
		return nil, err
	}

	{
		clFn := fileMethods["Close"]
		if clFn == nil || len(clFn.Body.List) < 2 || funcShadowsAnyIdent(clFn, osReserved) || bodyHasControlFlowOrRecoverBypass(clFn.Body) {
			return nil, fmt.Errorf("os: missing or invalid (*File).Close")
		}
		clRecv := recvVarName(clFn)
		if clRecv == "" || (clFn.Type.Params != nil && clFn.Type.Params.NumFields() != 0) || !funcReturnsErrorLast(clFn.Type) || clFn.Type.Results.NumFields() != 1 {
			return nil, fmt.Errorf("os: (*File).Close invalid signature")
		}
		ifs0, ok := clFn.Body.List[0].(*ast.IfStmt)
		if !ok || ifs0.Init != nil || ifs0.Else != nil || !condChecksEqErr(ifs0.Cond, clRecv) || len(ifs0.Body.List) != 1 {
			return nil, fmt.Errorf("os: (*File).Close missing nil receiver guard")
		}
		if ret0, okR := ifs0.Body.List[0].(*ast.ReturnStmt); !okR || len(ret0.Results) != 1 {
			return nil, fmt.Errorf("os: (*File).Close invalid nil receiver return")
		} else if _, okEI := isIdentNamed(ret0.Results[0], "ErrInvalid"); !okEI {
			return nil, fmt.Errorf("os: (*File).Close nil receiver guard does not return ErrInvalid")
		}
		pos := 1
		for pos < len(clFn.Body.List) && skipInactiveHookIf(clFn.Body.List[pos], clFn) {
			pos++
		}
		if len(clFn.Body.List) != pos+1 {
			return nil, fmt.Errorf("os: (*File).Close unexpected statements before f.file.close()")
		}
		retClose, ok := clFn.Body.List[pos].(*ast.ReturnStmt)
		if !ok || len(retClose.Results) != 1 {
			return nil, fmt.Errorf("os: (*File).Close invalid final return")
		}
		cCall, ok := unwrapParens(retClose.Results[0]).(*ast.CallExpr)
		if !ok || cCall.Ellipsis.IsValid() || len(cCall.Args) != 0 {
			return nil, fmt.Errorf("os: (*File).Close invalid close() call")
		}
		cSel, ok := unwrapParens(cCall.Fun).(*ast.SelectorExpr)
		if !ok || cSel.Sel.Name != "close" {
			return nil, fmt.Errorf("os: (*File).Close does not call f.file.close()")
		}
		if _, okFile := isSelectorBaseField(cSel.X, clRecv, "file"); !okFile {
			return nil, fmt.Errorf("os: (*File).Close receiver is not %s.file", clRecv)
		}
	}

	{
		rcFn := rawFileMethods["close"]
		if rcFn == nil || len(rcFn.Body.List) < 3 || rawFileMethodShadowsReserved(rcFn) || bodyHasControlFlowOrRecoverBypass(rcFn.Body) {
			return nil, fmt.Errorf("os: missing or invalid (*file).close")
		}
		rcRecv := recvVarName(rcFn)
		if rcRecv == "" || (rcFn.Type.Params != nil && rcFn.Type.Params.NumFields() != 0) || !funcReturnsErrorLast(rcFn.Type) || rcFn.Type.Results.NumFields() != 1 {
			return nil, fmt.Errorf("os: (*file).close invalid signature")
		}
		if bodyMutatesOrTakesAddrOfAny(rcFn.Body, map[string]bool{rcRecv: true}) || bodyDeclaresAnyIdent(rcFn.Body, map[string]bool{rcRecv: true}) {
			return nil, fmt.Errorf("os: (*file).close mutates or shadows receiver")
		}
		isSetFinalizerNilStmt := func(st ast.Stmt) bool {
			if !fileImportsRuntime[funcFile[rcFn]] {
				return false
			}
			es, okES := st.(*ast.ExprStmt)
			if !okES {
				return false
			}
			c, okC := unwrapParens(es.X).(*ast.CallExpr)
			if !okC || c.Ellipsis.IsValid() || len(c.Args) != 2 {
				return false
			}
			_, okSF := isSelectorBaseField(c.Fun, "runtime", "SetFinalizer")
			_, okR := isIdentNamed(c.Args[0], rcRecv)
			_, okN := isIdentNamed(c.Args[1], "nil")
			return okSF && okR && okN
		}
		validPFDClose := false
		if ifs0, ok0 := rcFn.Body.List[0].(*ast.IfStmt); ok0 && ifs0.Init == nil && ifs0.Else == nil && condChecksEqErr(ifs0.Cond, rcRecv) && len(ifs0.Body.List) == 1 {
			if ret0, okR0 := ifs0.Body.List[0].(*ast.ReturnStmt); okR0 && len(ret0.Results) == 1 {
				_, okNilEI := isIdentNamed(ret0.Results[0], "ErrInvalid")
				_, okNilEINVAL := isSelectorBaseField(ret0.Results[0], "syscall", "EINVAL")
				if okNilEI || (fileImportsSyscall[funcFile[rcFn]] && okNilEINVAL) {
					var errVar string
					pfdCloseIdx := -1
					directReturnOnErr := false
					preOK := true
					for idx := 1; idx < len(rcFn.Body.List)-1; idx++ {
						st := rcFn.Body.List[idx]
						if pfdCloseIdx < 0 && skipInactiveHookIf(st, rcFn) {
							continue
						}
						if isDirinfoSwapCloseIf(st, rcRecv, dirInfoCloseFn, osNoFileReserved, osAnyLinknameLocals) {
							continue
						}
						if ds, isDS := st.(*ast.DeclStmt); isDS {
							if gd, okGD := ds.Decl.(*ast.GenDecl); okGD && gd.Tok == token.VAR && len(gd.Specs) == 1 {
								if vs, okVS := gd.Specs[0].(*ast.ValueSpec); okVS && len(vs.Names) == 1 && len(vs.Values) == 0 {
									if _, okErrT := isIdentNamed(vs.Type, "error"); okErrT && errVar == "" {
										errVar = vs.Names[0].Name
										continue
									}
								}
							}
						}
						if ifs, isIf := st.(*ast.IfStmt); isIf && ifs.Init != nil && ifs.Else == nil {
							if initAs, okA := ifs.Init.(*ast.AssignStmt); okA && initAs.Tok == token.DEFINE && len(initAs.Lhs) == 1 && len(initAs.Rhs) == 1 {
								eID, okE := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
								pcCall, okC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
								if okE && okC && eID.Name != "" && eID.Name != "_" && condChecksNonZeroErr(ifs.Cond) == eID.Name && !pcCall.Ellipsis.IsValid() && len(pcCall.Args) == 0 {
									if pcSel, okS := unwrapParens(pcCall.Fun).(*ast.SelectorExpr); okS && pcSel.Sel.Name == "Close" {
										if _, okPFD := isSelectorBaseField(pcSel.X, rcRecv, "pfd"); okPFD {
											if len(ifs.Body.List) == 1 {
												if rStmt, okRS := ifs.Body.List[0].(*ast.ReturnStmt); okRS && len(rStmt.Results) == 1 {
													_, okRetE := isIdentNamed(rStmt.Results[0], eID.Name)
													u, okU := unwrapParens(rStmt.Results[0]).(*ast.UnaryExpr)
													_, tName := compositeWriterLit(rStmt.Results[0])
													if okRetE || (okU && u.Op == token.AND && tName == "PathError") {
														pfdCloseIdx = idx
														directReturnOnErr = true
														break
													}
												}
											}
											if errVar != "" && len(ifs.Body.List) >= 1 {
												lastAssign, okLA := ifs.Body.List[len(ifs.Body.List)-1].(*ast.AssignStmt)
												if okLA && lastAssign.Tok == token.ASSIGN && len(lastAssign.Lhs) == 1 && len(lastAssign.Rhs) == 1 {
													_, okL := isIdentNamed(lastAssign.Lhs[0], errVar)
													u, okU := unwrapParens(lastAssign.Rhs[0]).(*ast.UnaryExpr)
													_, tName := compositeWriterLit(lastAssign.Rhs[0])
													preErrOK := true
													for _, preS := range ifs.Body.List[:len(ifs.Body.List)-1] {
														preIf, okPI := preS.(*ast.IfStmt)
														if !okPI || preIf.Init != nil || preIf.Else != nil || len(preIf.Body.List) != 1 || exprContainsAnyCall(preIf.Cond) {
															preErrOK = false
															break
														}
														preAs, okPA := preIf.Body.List[0].(*ast.AssignStmt)
														if !okPA || preAs.Tok != token.ASSIGN || len(preAs.Lhs) != 1 || len(preAs.Rhs) != 1 {
															preErrOK = false
															break
														}
														_, okPL := isIdentNamed(preAs.Lhs[0], eID.Name)
														_, okPR := isIdentNamed(preAs.Rhs[0], "ErrClosed")
														if !okPL || !okPR {
															preErrOK = false
															break
														}
													}
													if okL && okU && u.Op == token.AND && tName == "PathError" && preErrOK {
														pfdCloseIdx = idx
														break
													}
												}
											}
										}
									}
								}
							}
						}
						preOK = false
						break
					}
					if preOK && pfdCloseIdx >= 1 {
						postOK := true
						for _, postSt := range rcFn.Body.List[pfdCloseIdx+1 : len(rcFn.Body.List)-1] {
							if !isSetFinalizerNilStmt(postSt) {
								postOK = false
								break
							}
						}
						if lastRet, okLR := rcFn.Body.List[len(rcFn.Body.List)-1].(*ast.ReturnStmt); postOK && okLR && len(lastRet.Results) == 1 {
							if directReturnOnErr {
								if _, okNil := isIdentNamed(lastRet.Results[0], "nil"); okNil {
									validPFDClose = true
								}
							} else if errVar != "" {
								if _, okEV := isIdentNamed(lastRet.Results[0], errVar); okEV {
									validPFDClose = true
								}
							}
						}
					}
				}
			}
		}
		validPlan9Close := false
		if !validPFDClose && len(rcFn.Body.List) >= 3 {
			decFn := rawFileMethods["decref"]
			desFn := rawFileMethods["destroy"]
			if decFn != nil && desFn != nil && len(decFn.Body.List) == 2 && len(desFn.Body.List) == 3 &&
				fileImportsSyscall[funcFile[desFn]] &&
				!rawFileMethodShadowsReserved(decFn) && !bodyHasControlFlowOrRecoverBypass(decFn.Body) &&
				!rawFileMethodShadowsReserved(desFn) && !bodyHasControlFlowOrRecoverBypass(desFn.Body) {
				decRecv := recvVarName(decFn)
				desRecv := recvVarName(desFn)
				// 1. (*file).close List[0]: if !file.fdmu.IncrefAndClose() { return &PathError{...} }
				ifs0, okI0 := rcFn.Body.List[0].(*ast.IfStmt)
				var closeGuardOK bool
				if okI0 && ifs0.Init == nil && ifs0.Else == nil && len(ifs0.Body.List) == 1 {
					if u0, okU0 := unwrapParens(ifs0.Cond).(*ast.UnaryExpr); okU0 && u0.Op == token.NOT {
						if icCall, okIC := unwrapParens(u0.X).(*ast.CallExpr); okIC && !icCall.Ellipsis.IsValid() && len(icCall.Args) == 0 {
							if icSel, okS := unwrapParens(icCall.Fun).(*ast.SelectorExpr); okS && icSel.Sel.Name == "IncrefAndClose" {
								if _, okFDMU := isSelectorBaseField(icSel.X, rcRecv, "fdmu"); okFDMU {
									if r0, okR0 := ifs0.Body.List[0].(*ast.ReturnStmt); okR0 && len(r0.Results) == 1 {
										_, okEC := isIdentNamed(r0.Results[0], "ErrClosed")
										uPE, okUPE := unwrapParens(r0.Results[0]).(*ast.UnaryExpr)
										_, tPE := compositeWriterLit(r0.Results[0])
										closeGuardOK = okEC || (okUPE && uPE.Op == token.AND && tPE == "PathError")
									}
								}
							}
						}
					}
				}
				// 2. (*file).decref: if file.fdmu.Decref() { return file.destroy() }; return nil
				var decOK bool
				if decRecv != "" && (decFn.Type.Params == nil || decFn.Type.Params.NumFields() == 0) && funcReturnsErrorLast(decFn.Type) && decFn.Type.Results.NumFields() == 1 {
					if dIf, okDI := decFn.Body.List[0].(*ast.IfStmt); okDI && dIf.Init == nil && dIf.Else == nil && len(dIf.Body.List) == 1 {
						if dCall, okDC := unwrapParens(dIf.Cond).(*ast.CallExpr); okDC && !dCall.Ellipsis.IsValid() && len(dCall.Args) == 0 {
							if dSel, okDS := unwrapParens(dCall.Fun).(*ast.SelectorExpr); okDS && dSel.Sel.Name == "Decref" {
								if _, okFDMU := isSelectorBaseField(dSel.X, decRecv, "fdmu"); okFDMU {
									if dRet, okDR := dIf.Body.List[0].(*ast.ReturnStmt); okDR && len(dRet.Results) == 1 {
										if _, okDest := isZeroArgMethodCallOnIdent(dRet.Results[0], decRecv, "destroy"); okDest {
											if dNil, okDN := decFn.Body.List[1].(*ast.ReturnStmt); okDN && len(dNil.Results) == 1 {
												_, decOK = isIdentNamed(dNil.Results[0], "nil")
											}
										}
									}
								}
							}
						}
					}
				}
				// 3. (*file).destroy: var err error; if e := syscall.Close(file.sysfd); e != nil { err = &PathError{...} }; return err
				var desOK bool
				if desRecv != "" && (desFn.Type.Params == nil || desFn.Type.Params.NumFields() == 0) && funcReturnsErrorLast(desFn.Type) && desFn.Type.Results.NumFields() == 1 && !bodyMutatesOrTakesAddrOfAny(desFn.Body, map[string]bool{desRecv: true}) {
					var desErrVar string
					if ds, okDS := desFn.Body.List[0].(*ast.DeclStmt); okDS {
						if gd, okGD := ds.Decl.(*ast.GenDecl); okGD && gd.Tok == token.VAR && len(gd.Specs) == 1 {
							if vs, okVS := gd.Specs[0].(*ast.ValueSpec); okVS && len(vs.Names) == 1 && len(vs.Values) == 0 {
								if _, okET := isIdentNamed(vs.Type, "error"); okET {
									desErrVar = vs.Names[0].Name
								}
							}
						}
					}
					if desErrVar != "" {
						if sIf, okSI := desFn.Body.List[1].(*ast.IfStmt); okSI && sIf.Init != nil && sIf.Else == nil && len(sIf.Body.List) == 1 {
							if sInit, okSIn := sIf.Init.(*ast.AssignStmt); okSIn && sInit.Tok == token.DEFINE && len(sInit.Lhs) == 1 && len(sInit.Rhs) == 1 {
								seID, okSE := unwrapParens(sInit.Lhs[0]).(*ast.Ident)
								scCall, okSC := unwrapParens(sInit.Rhs[0]).(*ast.CallExpr)
								if okSE && okSC && seID.Name != "" && seID.Name != "_" && condChecksNonZeroErr(sIf.Cond) == seID.Name && !scCall.Ellipsis.IsValid() && len(scCall.Args) == 1 {
									_, okSCSel := isSelectorBaseField(scCall.Fun, "syscall", "Close")
									_, okSysfd := isSelectorBaseField(scCall.Args[0], desRecv, "sysfd")
									if okSCSel && okSysfd {
										if eAs, okEA := sIf.Body.List[0].(*ast.AssignStmt); okEA && eAs.Tok == token.ASSIGN && len(eAs.Lhs) == 1 && len(eAs.Rhs) == 1 {
											_, okEL := isIdentNamed(eAs.Lhs[0], desErrVar)
											_, okER := isIdentNamed(eAs.Rhs[0], seID.Name)
											uPE, okUPE := unwrapParens(eAs.Rhs[0]).(*ast.UnaryExpr)
											_, tPE := compositeWriterLit(eAs.Rhs[0])
											if okEL && (okER || (okUPE && uPE.Op == token.AND && tPE == "PathError")) {
												if dLast, okDL := desFn.Body.List[2].(*ast.ReturnStmt); okDL && len(dLast.Results) == 1 {
													_, desOK = isIdentNamed(dLast.Results[0], desErrVar)
												}
											}
										}
									}
								}
							}
						}
					}
				}
				if closeGuardOK && decOK && desOK {
					if as, okA := rcFn.Body.List[1].(*ast.AssignStmt); okA && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
						eID, okE := unwrapParens(as.Lhs[0]).(*ast.Ident)
						midClean := true
						for _, mid := range rcFn.Body.List[2 : len(rcFn.Body.List)-1] {
							if !isSetFinalizerNilStmt(mid) {
								midClean = false
								break
							}
						}
						_, okDecref := isZeroArgMethodCallOnIdent(as.Rhs[0], rcRecv, "decref")
						if okE && eID.Name != "" && eID.Name != "_" && midClean && okDecref && !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: rcFn.Body.List[2:]}, map[string]bool{eID.Name: true}) {
							if lr, okLR := rcFn.Body.List[len(rcFn.Body.List)-1].(*ast.ReturnStmt); okLR && len(lr.Results) == 1 {
								if _, okRE := isIdentNamed(lr.Results[0], eID.Name); okRE {
									validPlan9Close = true
								}
							}
						}
					}
				}
			}
		}
		if !validPFDClose && !validPlan9Close {
			return nil, fmt.Errorf("os: (*file).close has unverified implementation")
		}
	}

	return sortedKeys(usedRuntimeGates), nil
}

func exprContainsAnyCall(expr ast.Expr) bool {
	if expr == nil {
		return false
	}
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		if _, ok := n.(*ast.CallExpr); ok {
			found = true
			return false
		}
		return true
	})
	return found
}

func verifyOSFileStructTypes(fileTypeSpec, rawFileTypeSpec *ast.TypeSpec, pkgDeclCounts map[string]int) error {
	if pkgDeclCounts["File"] != 1 || pkgDeclCounts["file"] != 1 || fileTypeSpec == nil || rawFileTypeSpec == nil {
		return fmt.Errorf("os: missing or duplicate File/file type declarations")
	}
	if fileTypeSpec.Assign.IsValid() || fileTypeSpec.TypeParams != nil || rawFileTypeSpec.Assign.IsValid() || rawFileTypeSpec.TypeParams != nil {
		return fmt.Errorf("os: File/file cannot be type aliases or generic")
	}
	fst, ok := unwrapParens(fileTypeSpec.Type).(*ast.StructType)
	if !ok || fst.Fields == nil || len(fst.Fields.List) != 1 || len(fst.Fields.List[0].Names) != 0 {
		return fmt.Errorf("os: File must be a struct with a single embedded *file field")
	}
	star, ok := unwrapParens(fst.Fields.List[0].Type).(*ast.StarExpr)
	if !ok {
		return fmt.Errorf("os: File embedded field is not a pointer")
	}
	if _, ok := isIdentNamed(star.X, "file"); !ok {
		return fmt.Errorf("os: File embedded field is not *file")
	}
	rst, ok := unwrapParens(rawFileTypeSpec.Type).(*ast.StructType)
	if !ok || rst.Fields == nil {
		return fmt.Errorf("os: file is not a struct")
	}
	seenFields := map[string]bool{}
	var sawName, sawFD bool
	for _, fld := range rst.Fields.List {
		if len(fld.Names) == 0 {
			return fmt.Errorf("os: embedded field on internal file struct forbidden")
		}
		for _, id := range fld.Names {
			if seenFields[id.Name] {
				return fmt.Errorf("os: duplicate field %s on file struct", id.Name)
			}
			seenFields[id.Name] = true
			switch id.Name {
			case "name":
				if _, okStr := isIdentNamed(fld.Type, "string"); !okStr {
					return fmt.Errorf("os: file.name must have type string")
				}
				sawName = true
			case "pfd", "sysfd":
				sawFD = true
			}
		}
	}
	if !sawName || !sawFD {
		return fmt.Errorf("os: file struct missing name or pfd/sysfd field")
	}
	return nil
}

func verifyOSExitIntegrity(files []*ast.File, exitFn *ast.FuncDecl, funcFile map[*ast.FuncDecl]*ast.File, fileImportsTestlog, fileImportsSyscall map[*ast.File]bool, osReserved map[string]bool) error {
	if exitFn == nil || exitFn.Body == nil || exitFn.Type == nil || exitFn.Type.TypeParams != nil {
		return fmt.Errorf("os: missing Exit function")
	}
	if !fileImportsTestlog[funcFile[exitFn]] || !fileImportsSyscall[funcFile[exitFn]] {
		return fmt.Errorf("os: file defining Exit missing internal/testlog or syscall import")
	}
	if funcShadowsAnyIdent(exitFn, osReserved) || bodyHasControlFlowOrRecoverBypass(exitFn.Body) {
		return fmt.Errorf("os: Exit shadows reserved identifier or has control-flow/recover bypass")
	}
	pNames := paramNamesFlat(exitFn.Type.Params)
	if len(pNames) != 1 || pNames[0] == "" || pNames[0] == "_" || len(exitFn.Type.Params.List) != 1 || (exitFn.Type.Results != nil && exitFn.Type.Results.NumFields() != 0) {
		return fmt.Errorf("os: Exit invalid signature")
	}
	if _, okInt := isIdentNamed(exitFn.Type.Params.List[0].Type, "int"); !okInt {
		return fmt.Errorf("os: Exit parameter is not int")
	}
	codeParam := pNames[0]
	if bodyMutatesOrTakesAddrOfAny(exitFn.Body, map[string]bool{codeParam: true}) || bodyDeclaresAnyIdent(exitFn.Body, map[string]bool{codeParam: true}) {
		return fmt.Errorf("os: Exit mutates or shadows %s", codeParam)
	}
	if len(exitFn.Body.List) != 2 && len(exitFn.Body.List) != 3 {
		return fmt.Errorf("os: Exit unexpected statement count %d", len(exitFn.Body.List))
	}
	s0, ok := exitFn.Body.List[0].(*ast.IfStmt)
	if !ok || s0.Init != nil || s0.Else != nil || len(s0.Body.List) != 1 {
		return fmt.Errorf("os: Exit missing PanicOnExit0 guard")
	}
	andBin, ok := unwrapParens(s0.Cond).(*ast.BinaryExpr)
	if !ok || andBin.Op != token.LAND {
		return fmt.Errorf("os: Exit guard condition is not &&")
	}
	eqBin, ok := unwrapParens(andBin.X).(*ast.BinaryExpr)
	if !ok || eqBin.Op != token.EQL {
		return fmt.Errorf("os: Exit guard LHS is not == 0")
	}
	_, okCodeL := isIdentNamed(eqBin.X, codeParam)
	_, okCodeR := isIdentNamed(eqBin.Y, codeParam)
	if !((okCodeL && isZeroIntLit(eqBin.Y)) || (isZeroIntLit(eqBin.X) && okCodeR)) {
		return fmt.Errorf("os: Exit guard does not compare %s == 0", codeParam)
	}
	if _, okPOE := isZeroArgMethodCallOnSelectorOrIdent(andBin.Y, "testlog", "PanicOnExit0"); !okPOE {
		return fmt.Errorf("os: Exit guard does not call testlog.PanicOnExit0()")
	}
	pES, ok := s0.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return fmt.Errorf("os: Exit guard body is not panic statement")
	}
	pCall, ok := unwrapParens(pES.X).(*ast.CallExpr)
	if !ok || pCall.Ellipsis.IsValid() || len(pCall.Args) != 1 {
		return fmt.Errorf("os: Exit guard invalid panic call")
	}
	if _, okP := isIdentNamed(pCall.Fun, "panic"); !okP {
		return fmt.Errorf("os: Exit guard does not call panic")
	}
	if lit, okLit := unwrapParens(pCall.Args[0]).(*ast.BasicLit); !okLit || lit.Kind != token.STRING {
		return fmt.Errorf("os: Exit panic argument must be string literal")
	}

	allowedBeforeExit := map[*ast.Ident]bool{}
	beforeExitDecls := 0
	for _, f := range files {
		for _, decl := range f.Decls {
			if fn, okF := decl.(*ast.FuncDecl); okF && fn.Recv == nil && fn.Name != nil && fn.Name.Name == "runtime_beforeExit" {
				beforeExitDecls++
				if fn.Body != nil || beforeExitDecls > 1 {
					return fmt.Errorf("os: invalid or duplicate runtime_beforeExit declaration")
				}
				allowedBeforeExit[fn.Name] = true
			}
		}
	}
	if len(exitFn.Body.List) == 3 {
		s1, okES := exitFn.Body.List[1].(*ast.ExprStmt)
		if !okES {
			return fmt.Errorf("os: Exit middle statement is not runtime_beforeExit call")
		}
		beCall, okC := unwrapParens(s1.X).(*ast.CallExpr)
		if !okC || beCall.Ellipsis.IsValid() || len(beCall.Args) != 1 {
			return fmt.Errorf("os: Exit invalid runtime_beforeExit call")
		}
		beID, okID := isIdentNamed(beCall.Fun, "runtime_beforeExit")
		_, okArg := isIdentNamed(beCall.Args[0], codeParam)
		if !okID || !okArg {
			return fmt.Errorf("os: Exit middle statement does not call runtime_beforeExit(%s)", codeParam)
		}
		allowedBeforeExit[beID] = true
	}

	lastES, ok := exitFn.Body.List[len(exitFn.Body.List)-1].(*ast.ExprStmt)
	if !ok {
		return fmt.Errorf("os: Exit final statement is not syscall.Exit call")
	}
	sysCall, ok := unwrapParens(lastES.X).(*ast.CallExpr)
	if !ok || sysCall.Ellipsis.IsValid() || len(sysCall.Args) != 1 {
		return fmt.Errorf("os: Exit invalid syscall.Exit call")
	}
	sysSel, ok := unwrapParens(sysCall.Fun).(*ast.SelectorExpr)
	if !ok || sysSel.Sel.Name != "Exit" {
		return fmt.Errorf("os: Exit does not call syscall.Exit")
	}
	if _, okSys := isIdentNamed(sysSel.X, "syscall"); !okSys {
		return fmt.Errorf("os: Exit final call receiver is not syscall")
	}
	if _, okArg := isIdentNamed(sysCall.Args[0], codeParam); !okArg {
		return fmt.Errorf("os: Exit does not forward %s to syscall.Exit", codeParam)
	}

	var exitLeak bool
	for _, f := range files {
		walkNonSelectorPropIdents(f, func(id *ast.Ident) {
			if id.Name == "Exit" && id != exitFn.Name {
				exitLeak = true
			}
			if id.Name == "runtime_beforeExit" && !allowedBeforeExit[id] {
				exitLeak = true
			}
		})
		ast.Inspect(f, func(n ast.Node) bool {
			if exitLeak || n == nil {
				return false
			}
			if sel, okS := n.(*ast.SelectorExpr); okS && sel != sysSel && (sel.Sel.Name == "Exit" || sel.Sel.Name == "ExitProcess") {
				if _, okSys := isIdentNamed(sel.X, "syscall"); okSys {
					exitLeak = true
					return false
				}
			}
			return true
		})
		if exitLeak {
			return fmt.Errorf("os: forbidden process-termination reference outside Exit")
		}
	}
	return nil
}

func verifyOSEpipecheck(fn *ast.FuncDecl, funcFile map[*ast.FuncDecl]*ast.File, fileImportsSyscall map[*ast.File]bool, osNoFileReserved, osAnyLinknameLocals map[string]bool) error {
	if fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || osAnyLinknameLocals["epipecheck"] {
		return fmt.Errorf("os: missing or invalid epipecheck")
	}
	if funcShadowsAnyIdent(fn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
		return fmt.Errorf("os: epipecheck shadows reserved identifier or has control-flow bypass")
	}
	pNames := paramNamesFlat(fn.Type.Params)
	if len(pNames) != 2 || pNames[0] == "" || pNames[0] == "_" || pNames[1] == "" || pNames[1] == "_" || (fn.Type.Results != nil && fn.Type.Results.NumFields() != 0) {
		return fmt.Errorf("os: epipecheck invalid signature")
	}
	if len(fn.Body.List) == 0 {
		return nil
	}
	if len(fn.Body.List) != 1 || !fileImportsSyscall[funcFile[fn]] {
		return fmt.Errorf("os: epipecheck unexpected body")
	}
	ifs, ok := fn.Body.List[0].(*ast.IfStmt)
	if !ok || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
		return fmt.Errorf("os: epipecheck body is not single EPIPE guard")
	}
	isEpipeCmp := func(expr ast.Expr) bool {
		bin, okB := unwrapParens(expr).(*ast.BinaryExpr)
		if !okB || bin.Op != token.EQL {
			return false
		}
		_, okE := isIdentNamed(bin.X, pNames[1])
		_, okSys := isSelectorBaseField(bin.Y, "syscall", "EPIPE")
		return okE && okSys
	}
	condOK := isEpipeCmp(ifs.Cond)
	if !condOK {
		if andBin, okA := unwrapParens(ifs.Cond).(*ast.BinaryExpr); okA && andBin.Op == token.LAND {
			_, okStd := isSelectorBaseField(andBin.Y, pNames[0], "stdoutOrErr")
			condOK = isEpipeCmp(andBin.X) && okStd
		}
	}
	es, okES := ifs.Body.List[0].(*ast.ExprStmt)
	if !condOK || !okES {
		return fmt.Errorf("os: epipecheck invalid condition or call")
	}
	sc, okC := unwrapParens(es.X).(*ast.CallExpr)
	if !okC || sc.Ellipsis.IsValid() || len(sc.Args) != 0 {
		return fmt.Errorf("os: epipecheck invalid sigpipe call")
	}
	if _, okSig := isIdentNamed(sc.Fun, "sigpipe"); !okSig {
		return fmt.Errorf("os: epipecheck does not call sigpipe()")
	}
	return nil
}

func verifyOSFileFdMethods(fdExported, fdLower *ast.FuncDecl, osNoFileReserved map[string]bool, skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool) error {
	if fdExported == nil || fdExported.Body == nil || len(fdExported.Body.List) != 1 || funcShadowsAnyIdent(fdExported, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(fdExported.Body) {
		return fmt.Errorf("os: missing or invalid (*File).Fd")
	}
	expRecv := recvVarName(fdExported)
	if expRecv == "" || (fdExported.Type.Params != nil && fdExported.Type.Params.NumFields() != 0) || fdExported.Type.Results == nil || fdExported.Type.Results.NumFields() != 1 || len(fdExported.Type.Results.List) != 1 {
		return fmt.Errorf("os: (*File).Fd invalid signature")
	}
	if _, okU := isIdentNamed(fdExported.Type.Results.List[0].Type, "uintptr"); !okU {
		return fmt.Errorf("os: (*File).Fd result is not uintptr")
	}
	expRet, ok := fdExported.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(expRet.Results) != 1 {
		return fmt.Errorf("os: (*File).Fd does not return single expression")
	}
	if _, okCall := isZeroArgMethodCallOnIdent(expRet.Results[0], expRecv, "fd"); !okCall {
		return fmt.Errorf("os: (*File).Fd does not delegate to %s.fd()", expRecv)
	}

	if fdLower == nil || fdLower.Body == nil || len(fdLower.Body.List) < 2 || funcShadowsAnyIdent(fdLower, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(fdLower.Body) {
		return fmt.Errorf("os: missing or invalid (*File).fd")
	}
	lowRecv := recvVarName(fdLower)
	if lowRecv == "" || (fdLower.Type.Params != nil && fdLower.Type.Params.NumFields() != 0) || fdLower.Type.Results == nil || fdLower.Type.Results.NumFields() != 1 || len(fdLower.Type.Results.List) != 1 {
		return fmt.Errorf("os: (*File).fd invalid signature")
	}
	if _, okU := isIdentNamed(fdLower.Type.Results.List[0].Type, "uintptr"); !okU {
		return fmt.Errorf("os: (*File).fd result is not uintptr")
	}
	if bodyMutatesOrTakesAddrOfAny(fdLower.Body, map[string]bool{lowRecv: true}) || bodyDeclaresAnyIdent(fdLower.Body, map[string]bool{lowRecv: true}) {
		return fmt.Errorf("os: (*File).fd mutates or shadows receiver")
	}
	ifs0, ok := fdLower.Body.List[0].(*ast.IfStmt)
	if !ok || ifs0.Init != nil || ifs0.Else != nil || !condChecksEqErr(ifs0.Cond, lowRecv) || len(ifs0.Body.List) != 1 {
		return fmt.Errorf("os: (*File).fd missing nil receiver guard")
	}
	ret0, ok := ifs0.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret0.Results) != 1 {
		return fmt.Errorf("os: (*File).fd invalid nil receiver return")
	}
	badNilRet := false
	ast.Inspect(ret0.Results[0], func(n ast.Node) bool {
		if badNilRet || n == nil {
			return false
		}
		if c, okC := n.(*ast.CallExpr); okC {
			if _, okConv := isIdentNamed(c.Fun, "uintptr"); !okConv || c.Ellipsis.IsValid() || len(c.Args) != 1 {
				badNilRet = true
				return false
			}
		}
		return true
	})
	if badNilRet {
		return fmt.Errorf("os: (*File).fd nil guard contains forbidden call")
	}
	pos := 1
	for pos < len(fdLower.Body.List)-1 && skipInactiveHookIf(fdLower.Body.List[pos], fdLower) {
		pos++
	}
	for _, mid := range fdLower.Body.List[pos : len(fdLower.Body.List)-1] {
		if ifs, okI := mid.(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
			if _, okNB := isSelectorBaseField(ifs.Cond, lowRecv, "nonblock"); okNB {
				if es, okES := ifs.Body.List[0].(*ast.ExprStmt); okES {
					if _, okSB := isZeroArgMethodCallOnSelector(es.X, lowRecv, "pfd", "SetBlocking"); okSB {
						continue
					}
				}
			}
		}
		if as, okA := mid.(*ast.AssignStmt); okA && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			if _, okBlank := isIdentNamed(as.Lhs[0], "_"); okBlank {
				if _, okDis := isZeroArgMethodCallOnSelector(as.Rhs[0], lowRecv, "pfd", "DisassociateIOCP"); okDis {
					continue
				}
			}
		}
		return fmt.Errorf("os: (*File).fd unexpected statement before final return")
	}
	lastRet, ok := fdLower.Body.List[len(fdLower.Body.List)-1].(*ast.ReturnStmt)
	if !ok || len(lastRet.Results) != 1 {
		return fmt.Errorf("os: (*File).fd invalid final return")
	}
	convCall, ok := unwrapParens(lastRet.Results[0]).(*ast.CallExpr)
	if !ok || convCall.Ellipsis.IsValid() || len(convCall.Args) != 1 {
		return fmt.Errorf("os: (*File).fd final return is not uintptr(...) conversion")
	}
	if _, okU := isIdentNamed(convCall.Fun, "uintptr"); !okU {
		return fmt.Errorf("os: (*File).fd final return is not uintptr(...)")
	}
	_, okSysfdDirect := isSelectorBaseField(convCall.Args[0], lowRecv, "sysfd")
	var okPFDSysfd bool
	if sel, okS := unwrapParens(convCall.Args[0]).(*ast.SelectorExpr); okS && sel.Sel.Name == "Sysfd" {
		_, okPFDSysfd = isSelectorBaseField(sel.X, lowRecv, "pfd")
	}
	if !okSysfdDirect && !okPFDSysfd {
		return fmt.Errorf("os: (*File).fd does not return uintptr(%s.pfd.Sysfd) or uintptr(%s.sysfd)", lowRecv, lowRecv)
	}
	return nil
}

func isDirinfoSwapCloseIf(st ast.Stmt, rcRecv string, dirInfoCloseFn *ast.FuncDecl, osNoFileReserved, osAnyLinknameLocals map[string]bool) bool {
	ifs, ok := st.(*ast.IfStmt)
	if !ok || ifs.Init == nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
		return false
	}
	initAs, ok := ifs.Init.(*ast.AssignStmt)
	if !ok || initAs.Tok != token.DEFINE || len(initAs.Lhs) != 1 || len(initAs.Rhs) != 1 {
		return false
	}
	infoID, ok := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
	if !ok || infoID.Name == "" || infoID.Name == "_" || condChecksNonZeroErr(ifs.Cond) != infoID.Name {
		return false
	}
	swapCall, ok := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
	if !ok || swapCall.Ellipsis.IsValid() || len(swapCall.Args) != 1 {
		return false
	}
	if _, okNil := isIdentNamed(swapCall.Args[0], "nil"); !okNil {
		return false
	}
	swapSel, ok := unwrapParens(swapCall.Fun).(*ast.SelectorExpr)
	if !ok || swapSel.Sel.Name != "Swap" {
		return false
	}
	if _, okDI := isSelectorBaseField(swapSel.X, rcRecv, "dirinfo"); !okDI {
		return false
	}
	es, ok := ifs.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	if _, okCl := isZeroArgMethodCallOnIdent(es.X, infoID.Name, "close"); !okCl {
		return false
	}
	if dirInfoCloseFn == nil || dirInfoCloseFn.Body == nil || osAnyLinknameLocals["close"] || funcShadowsAnyIdent(dirInfoCloseFn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(dirInfoCloseFn.Body) {
		return false
	}
	badDirClose := false
	ast.Inspect(dirInfoCloseFn.Body, func(n ast.Node) bool {
		if badDirClose || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.DeferStmt, *ast.GoStmt, *ast.FuncLit:
			badDirClose = true
			return false
		case *ast.Ident:
			if x.Name == "testlog" {
				badDirClose = true
				return false
			}
		case *ast.ReturnStmt:
			if len(x.Results) != 0 {
				badDirClose = true
				return false
			}
		}
		return true
	})
	return !badDirClose
}

func verifyOSOpenFileNolog(fn *ast.FuncDecl, allTopFuncs map[string]*ast.FuncDecl, funcFile map[*ast.FuncDecl]*ast.File, fileImportsSyscall map[*ast.File]bool, osNoFileReserved, osAnyLinknameLocals map[string]bool, skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool) error {
	if fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || osAnyLinknameLocals["openFileNolog"] {
		return fmt.Errorf("os: missing or invalid openFileNolog")
	}
	if funcShadowsAnyIdent(fn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
		return fmt.Errorf("os: openFileNolog shadows reserved identifier or has control-flow/recover bypass")
	}
	pNames := paramNamesFlat(fn.Type.Params)
	if len(pNames) != 3 || pNames[0] == "" || pNames[0] == "_" || pNames[1] == "" || pNames[1] == "_" || pNames[2] == "" || pNames[2] == "_" {
		return fmt.Errorf("os: openFileNolog invalid parameters")
	}
	if fn.Type.Results == nil || fn.Type.Results.NumFields() != 2 || !funcReturnsErrorLast(fn.Type) {
		return fmt.Errorf("os: openFileNolog invalid results")
	}
	if starF, okS := unwrapParens(fn.Type.Results.List[0].Type).(*ast.StarExpr); !okS {
		return fmt.Errorf("os: openFileNolog first result is not *File")
	} else if _, okF := isIdentNamed(starF.X, "File"); !okF {
		return fmt.Errorf("os: openFileNolog first result is not *File")
	}
	p0 := pNames[0]
	if bodyMutatesOrTakesAddrOfAny(fn.Body, map[string]bool{p0: true}) || bodyDeclaresAnyIdent(fn.Body, map[string]bool{p0: true}) {
		return fmt.Errorf("os: openFileNolog mutates or shadows %s", p0)
	}
	pos := 0
	for pos < len(fn.Body.List) && skipInactiveHookIf(fn.Body.List[pos], fn) {
		pos++
	}
	if len(fn.Body.List) < pos+3 {
		return fmt.Errorf("os: openFileNolog body too short")
	}

	isVerifiedFileLit := func(expr ast.Expr, fdNames map[string]bool, wantName string) bool {
		outerLit, outerType := compositeWriterLit(expr)
		if outerLit == nil || outerType != "File" || len(outerLit.Elts) != 1 {
			return false
		}
		innerExpr := outerLit.Elts[0]
		if kv, okKV := innerExpr.(*ast.KeyValueExpr); okKV {
			if _, okKey := isIdentNamed(kv.Key, "file"); !okKey {
				return false
			}
			innerExpr = kv.Value
		}
		innerLit, innerType := compositeWriterLit(innerExpr)
		if innerLit == nil || innerType != "file" {
			return false
		}
		var sawName, sawFD bool
		for _, elt := range innerLit.Elts {
			kv, okKV := elt.(*ast.KeyValueExpr)
			if !okKV {
				return false
			}
			kID, okK := unwrapParens(kv.Key).(*ast.Ident)
			if !okK {
				return false
			}
			switch kID.Name {
			case "name":
				if _, okN := isIdentNamed(kv.Value, wantName); !okN {
					return false
				}
				sawName = true
			case "sysfd":
				if vID, okV := unwrapParens(kv.Value).(*ast.Ident); !okV || !fdNames[vID.Name] {
					return false
				}
				sawFD = true
			case "pfd":
				pfdLit, okCL := unwrapParens(kv.Value).(*ast.CompositeLit)
				if !okCL {
					return false
				}
				for _, pElt := range pfdLit.Elts {
					pkv, okPKV := pElt.(*ast.KeyValueExpr)
					if !okPKV {
						return false
					}
					if _, okSys := isIdentNamed(pkv.Key, "Sysfd"); okSys {
						vID, okV := unwrapParens(pkv.Value).(*ast.Ident)
						if !okV || !fdNames[vID.Name] {
							return false
						}
						sawFD = true
					}
				}
			}
		}
		return sawName && sawFD
	}

	verifyNewFileHelper := func(nfFn *ast.FuncDecl) bool {
		if nfFn == nil || nfFn.Body == nil || osAnyLinknameLocals[nfFn.Name.Name] || funcShadowsAnyIdent(nfFn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(nfFn.Body) {
			return false
		}
		nfParams := paramNamesFlat(nfFn.Type.Params)
		if len(nfParams) < 2 || nfParams[0] == "" || nfParams[0] == "_" || nfParams[1] == "" || nfParams[1] == "_" {
			return false
		}
		fdP, nameP := nfParams[0], nfParams[1]
		if bodyMutatesOrTakesAddrOfAny(nfFn.Body, map[string]bool{fdP: true, nameP: true}) || bodyDeclaresAnyIdent(nfFn.Body, map[string]bool{fdP: true, nameP: true}) {
			return false
		}
		hasTestlog := false
		ast.Inspect(nfFn.Body, func(n ast.Node) bool {
			if id, okID := n.(*ast.Ident); okID && id.Name == "testlog" {
				hasTestlog = true
				return false
			}
			return !hasTestlog
		})
		if hasTestlog || len(nfFn.Body.List) == 0 {
			return false
		}
		fdAliases := map[string]bool{fdP: true}
		scanIdx := 0
		if as0, okA := nfFn.Body.List[0].(*ast.AssignStmt); okA && as0.Tok == token.DEFINE && len(as0.Lhs) == 1 && len(as0.Rhs) == 1 {
			if aID, okID := unwrapParens(as0.Lhs[0]).(*ast.Ident); okID && aID.Name != "" && aID.Name != "_" {
				if conv, okC := unwrapParens(as0.Rhs[0]).(*ast.CallExpr); okC && !conv.Ellipsis.IsValid() && len(conv.Args) == 1 {
					if _, okArg := isIdentNamed(conv.Args[0], fdP); okArg {
						_, okInt := isIdentNamed(conv.Fun, "int")
						_, okH := isSelectorBaseField(conv.Fun, "syscall", "Handle")
						if (okInt || okH) && !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: nfFn.Body.List[1:]}, map[string]bool{aID.Name: true}) {
							fdAliases[aID.Name] = true
							scanIdx = 1
						}
					}
				}
			}
		}
		if scanIdx < len(nfFn.Body.List) {
			if ifs, okI := nfFn.Body.List[scanIdx].(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
				if rNil, okR := ifs.Body.List[0].(*ast.ReturnStmt); okR && len(rNil.Results) == 1 {
					if _, okN := isIdentNamed(rNil.Results[0], "nil"); okN && !exprContainsAnyCall(ifs.Cond) {
						scanIdx++
					}
				}
			}
		}
		if scanIdx == len(nfFn.Body.List)-1 {
			if ret, okR := nfFn.Body.List[scanIdx].(*ast.ReturnStmt); okR && len(ret.Results) == 1 {
				if isVerifiedFileLit(ret.Results[0], fdAliases, nameP) {
					return true
				}
				if c, okC := unwrapParens(ret.Results[0]).(*ast.CallExpr); okC && !c.Ellipsis.IsValid() && len(c.Args) >= 2 {
					if cFun, okF := unwrapParens(c.Fun).(*ast.Ident); okF && cFun.Name == "newFile" {
						if a0, ok0 := unwrapParens(c.Args[0]).(*ast.Ident); ok0 && fdAliases[a0.Name] {
							if _, ok1 := isIdentNamed(c.Args[1], nameP); ok1 && nfFn.Name.Name != "newFile" {
								return allTopFuncs["newFile"] != nil
							}
						}
					}
				}
			}
		}
		fDeclIdx := -1
		var nfVar string
		for idx := scanIdx; idx < len(nfFn.Body.List); idx++ {
			if as, okA := nfFn.Body.List[idx].(*ast.AssignStmt); okA && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
				if vID, okID := unwrapParens(as.Lhs[0]).(*ast.Ident); okID && vID.Name != "" && vID.Name != "_" && isVerifiedFileLit(as.Rhs[0], fdAliases, nameP) {
					fDeclIdx = idx
					nfVar = vID.Name
					break
				}
			}
		}
		if fDeclIdx < 0 || nfVar == "" {
			return false
		}
		if bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: nfFn.Body.List[fDeclIdx+1:]}, map[string]bool{nfVar: true}) || bodyDeclaresAnyIdent(&ast.BlockStmt{List: nfFn.Body.List[fDeclIdx+1:]}, map[string]bool{nfVar: true}) {
			return false
		}
		badPost := false
		for _, st := range nfFn.Body.List[:fDeclIdx] {
			ast.Inspect(st, func(n ast.Node) bool {
				if _, isFL := n.(*ast.FuncLit); isFL {
					return false
				}
				if _, okR := n.(*ast.ReturnStmt); okR && st != nfFn.Body.List[scanIdx-1] {
					badPost = true
					return false
				}
				return !badPost
			})
		}
		for _, st := range nfFn.Body.List[fDeclIdx+1:] {
			ast.Inspect(st, func(n ast.Node) bool {
				if badPost || n == nil {
					return false
				}
				if as, okA := n.(*ast.AssignStmt); okA {
					for _, lhs := range as.Lhs {
						if sel, okS := unwrapParens(lhs).(*ast.SelectorExpr); okS {
							if _, okB := isIdentNamed(sel.X, nfVar); okB && (sel.Sel.Name == "file" || sel.Sel.Name == "pfd" || sel.Sel.Name == "sysfd" || sel.Sel.Name == "name") {
								badPost = true
								return false
							}
							if sel.Sel.Name == "Sysfd" {
								if _, okPFD := isSelectorBaseField(sel.X, nfVar, "pfd"); okPFD {
									badPost = true
									return false
								}
							}
						}
					}
				}
				return true
			})
			ast.Inspect(st, func(n ast.Node) bool {
				if badPost || n == nil {
					return false
				}
				if _, isFL := n.(*ast.FuncLit); isFL {
					return false
				}
				if r, okR := n.(*ast.ReturnStmt); okR {
					if len(r.Results) != 1 {
						badPost = true
						return false
					}
					if _, okV := isIdentNamed(r.Results[0], nfVar); !okV {
						badPost = true
						return false
					}
				}
				return true
			})
		}
		lastRet, okLR := nfFn.Body.List[len(nfFn.Body.List)-1].(*ast.ReturnStmt)
		if badPost || !okLR || len(lastRet.Results) != 1 {
			return false
		}
		_, okFinal := isIdentNamed(lastRet.Results[0], nfVar)
		return okFinal
	}

	matchNewFileCall := func(expr ast.Expr) (string, bool) {
		c, okC := unwrapParens(expr).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) < 2 {
			return "", false
		}
		fnID, okF := unwrapParens(c.Fun).(*ast.Ident)
		if !okF {
			return "", false
		}
		if _, okName := isIdentNamed(c.Args[1], p0); !okName {
			return "", false
		}
		switch fnID.Name {
		case "newFile":
			fdID, okFD := unwrapParens(c.Args[0]).(*ast.Ident)
			if !okFD || fdID.Name == "" || fdID.Name == "_" || !verifyNewFileHelper(allTopFuncs["newFile"]) {
				return "", false
			}
			return fdID.Name, true
		case "NewFile":
			if len(c.Args) != 2 {
				return "", false
			}
			uConv, okConv := unwrapParens(c.Args[0]).(*ast.CallExpr)
			if !okConv || uConv.Ellipsis.IsValid() || len(uConv.Args) != 1 {
				return "", false
			}
			if _, okU := isIdentNamed(uConv.Fun, "uintptr"); !okU {
				return "", false
			}
			fdID, okFD := unwrapParens(uConv.Args[0]).(*ast.Ident)
			nfExported := allTopFuncs["NewFile"]
			if !okFD || fdID.Name == "" || fdID.Name == "_" || nfExported == nil || nfExported.Body == nil || osAnyLinknameLocals["NewFile"] || len(nfExported.Body.List) == 0 {
				return "", false
			}
			nfExpParams := paramNamesFlat(nfExported.Type.Params)
			if len(nfExpParams) != 2 {
				return "", false
			}
			lastExp, okLE := nfExported.Body.List[len(nfExported.Body.List)-1].(*ast.ReturnStmt)
			if !okLE || len(lastExp.Results) != 1 {
				return "", false
			}
			delCall, okDC := unwrapParens(lastExp.Results[0]).(*ast.CallExpr)
			if !okDC || delCall.Ellipsis.IsValid() || len(delCall.Args) != 2 {
				return "", false
			}
			_, okDelFun := isIdentNamed(delCall.Fun, "newFileFromNewFile")
			_, okD0 := isIdentNamed(delCall.Args[0], nfExpParams[0])
			_, okD1 := isIdentNamed(delCall.Args[1], nfExpParams[1])
			if !okDelFun || !okD0 || !okD1 || !verifyNewFileHelper(allTopFuncs["newFileFromNewFile"]) {
				return "", false
			}
			if allTopFuncs["newFile"] != nil && !verifyNewFileHelper(allTopFuncs["newFile"]) {
				return "", false
			}
			return fdID.Name, true
		default:
			return "", false
		}
	}

	lastRet, ok := fn.Body.List[len(fn.Body.List)-1].(*ast.ReturnStmt)
	if !ok || len(lastRet.Results) != 2 {
		return fmt.Errorf("os: openFileNolog missing trailing 2-value return")
	}
	if _, okNil := isIdentNamed(lastRet.Results[1], "nil"); !okNil {
		return fmt.Errorf("os: openFileNolog final return error is not nil")
	}

	var wantFDVar string
	fConstructIdx := -1
	if fdV, okInline := matchNewFileCall(lastRet.Results[0]); okInline {
		wantFDVar = fdV
		fConstructIdx = len(fn.Body.List) - 1
	} else if fVarID, okFV := unwrapParens(lastRet.Results[0]).(*ast.Ident); okFV && fVarID.Name != "" && fVarID.Name != "_" {
		for candIdx := len(fn.Body.List) - 2; candIdx >= pos && candIdx >= len(fn.Body.List)-3; candIdx-- {
			as, okA := fn.Body.List[candIdx].(*ast.AssignStmt)
			if !okA || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				continue
			}
			if _, okLHS := isIdentNamed(as.Lhs[0], fVarID.Name); !okLHS {
				continue
			}
			fdV, okNF := matchNewFileCall(as.Rhs[0])
			if !okNF {
				continue
			}
			tailOK := !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: fn.Body.List[candIdx+1:]}, map[string]bool{fVarID.Name: true})
			for _, tailSt := range fn.Body.List[candIdx+1 : len(fn.Body.List)-1] {
				tAs, okTA := tailSt.(*ast.AssignStmt)
				if !okTA || tAs.Tok != token.ASSIGN || len(tAs.Lhs) != 1 || len(tAs.Rhs) != 1 || exprContainsAnyCall(tAs.Rhs[0]) {
					tailOK = false
					break
				}
				sel, okS := unwrapParens(tAs.Lhs[0]).(*ast.SelectorExpr)
				if !okS || sel.Sel.Name != "SysFile" {
					tailOK = false
					break
				}
				if _, okPFD := isSelectorBaseField(sel.X, fVarID.Name, "pfd"); !okPFD {
					tailOK = false
					break
				}
			}
			if tailOK {
				wantFDVar = fdV
				fConstructIdx = candIdx
				break
			}
		}
	}
	if fConstructIdx < pos+2 || wantFDVar == "" {
		return fmt.Errorf("os: openFileNolog missing verified newFile construction")
	}

	isPathErrorReturn := func(ret *ast.ReturnStmt) bool {
		if ret == nil || len(ret.Results) != 2 {
			return false
		}
		if _, okNil := isIdentNamed(ret.Results[0], "nil"); !okNil {
			return false
		}
		u, okU := unwrapParens(ret.Results[1]).(*ast.UnaryExpr)
		lit, tName := compositeWriterLit(ret.Results[1])
		if !okU || u.Op != token.AND || lit == nil || tName != "PathError" {
			return false
		}
		for _, elt := range lit.Elts {
			if kv, okKV := elt.(*ast.KeyValueExpr); okKV {
				if _, okE := isIdentNamed(kv.Key, "Err"); okE {
					_, isNilErr := isIdentNamed(kv.Value, "nil")
					return !isNilErr
				}
			}
		}
		return false
	}

	badMidReturn := false
	for _, st := range fn.Body.List[pos:fConstructIdx] {
		if _, isBareRet := st.(*ast.ReturnStmt); isBareRet {
			return fmt.Errorf("os: openFileNolog unexpected unconditional return before newFile")
		}
		ast.Inspect(st, func(n ast.Node) bool {
			if badMidReturn || n == nil {
				return false
			}
			if _, isFL := n.(*ast.FuncLit); isFL {
				return false
			}
			if ret, okR := n.(*ast.ReturnStmt); okR && !isPathErrorReturn(ret) {
				badMidReturn = true
				return false
			}
			return true
		})
		if badMidReturn {
			return fmt.Errorf("os: openFileNolog early return does not return (nil, &PathError)")
		}
	}

	verifyIgnoringEINTR := func(igFn *ast.FuncDecl) bool {
		return verifyOSIgnoringEINTR(igFn, funcFile, fileImportsSyscall, osNoFileReserved, osAnyLinknameLocals)
	}

	verifyJoinPathHelper := func(jpFn *ast.FuncDecl) bool {
		if jpFn == nil || jpFn.Body == nil || osAnyLinknameLocals["joinPath"] || funcShadowsAnyIdent(jpFn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(jpFn.Body) {
			return false
		}
		hasTestlog := false
		ast.Inspect(jpFn.Body, func(n ast.Node) bool {
			if id, okID := n.(*ast.Ident); okID && id.Name == "testlog" {
				hasTestlog = true
				return false
			}
			return !hasTestlog
		})
		return !hasTestlog
	}

	isMinusOneLit := func(expr ast.Expr) bool {
		u, okU := unwrapParens(expr).(*ast.UnaryExpr)
		if !okU || u.Op != token.SUB {
			return false
		}
		lit, okL := unwrapParens(u.X).(*ast.BasicLit)
		return okL && lit.Kind == token.INT && lit.Value == "1"
	}

	verifyOpenHelper := func(opFn *ast.FuncDecl) bool {
		if opFn == nil || opFn.Body == nil || osAnyLinknameLocals["open"] || !fileImportsSyscall[funcFile[opFn]] || funcShadowsAnyIdent(opFn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(opFn.Body) {
			return false
		}
		opParams := paramNamesFlat(opFn.Type.Params)
		if len(opParams) != 3 || opParams[0] == "" || opParams[0] == "_" || len(opFn.Body.List) < 2 {
			return false
		}
		if bodyMutatesOrTakesAddrOfAny(opFn.Body, map[string]bool{opParams[0]: true}) || bodyDeclaresAnyIdent(opFn.Body, map[string]bool{opParams[0]: true}) {
			return false
		}
		hasTestlog := false
		ast.Inspect(opFn.Body, func(n ast.Node) bool {
			if id, okID := n.(*ast.Ident); okID && id.Name == "testlog" {
				hasTestlog = true
				return false
			}
			return !hasTestlog
		})
		if hasTestlog {
			return false
		}
		lastRet, okLR := opFn.Body.List[len(opFn.Body.List)-1].(*ast.ReturnStmt)
		if !okLR || len(lastRet.Results) != 3 {
			return false
		}
		fdRetID, okFD := unwrapParens(lastRet.Results[0]).(*ast.Ident)
		errRetID, okER := unwrapParens(lastRet.Results[2]).(*ast.Ident)
		if !okFD || !okER || fdRetID.Name == "" || errRetID.Name == "" {
			return false
		}
		checkedErrIfRets := map[*ast.ReturnStmt]bool{}
		ast.Inspect(&ast.BlockStmt{List: opFn.Body.List[:len(opFn.Body.List)-1]}, func(n ast.Node) bool {
			if ifs, okI := n.(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
				if eName := condChecksNonZeroErr(ifs.Cond); eName != "" {
					if r, okR := ifs.Body.List[0].(*ast.ReturnStmt); okR && len(r.Results) == 3 && isMinusOneLit(r.Results[0]) {
						if _, okE := isIdentNamed(r.Results[2], eName); okE {
							checkedErrIfRets[r] = true
						}
					}
				}
			}
			return true
		})
		badEarlyRet := false
		ast.Inspect(&ast.BlockStmt{List: opFn.Body.List[:len(opFn.Body.List)-1]}, func(n ast.Node) bool {
			if badEarlyRet || n == nil {
				return false
			}
			if r, okR := n.(*ast.ReturnStmt); okR {
				if checkedErrIfRets[r] {
					return false
				}
				if len(r.Results) != 3 || !isMinusOneLit(r.Results[0]) {
					badEarlyRet = true
					return false
				}
				sel, okS := unwrapParens(r.Results[2]).(*ast.SelectorExpr)
				if !okS || sel.Sel.Name == "" {
					badEarlyRet = true
					return false
				}
				if _, okSys := isIdentNamed(sel.X, "syscall"); !okSys {
					badEarlyRet = true
					return false
				}
			}
			return true
		})
		if badEarlyRet {
			return false
		}
		opPathAliases := map[string]bool{opParams[0]: true}
		sawSyscallOpen := false
		for idx := 0; idx < len(opFn.Body.List)-1; idx++ {
			st := opFn.Body.List[idx]
			if as, okA := st.(*ast.AssignStmt); okA && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
				if aID, okID := unwrapParens(as.Lhs[0]).(*ast.Ident); okID && aID.Name != "" && aID.Name != "_" {
					if _, okSrc := isIdentNamed(as.Rhs[0], opParams[0]); okSrc {
						afterIdx := idx + 1
						if afterIdx < len(opFn.Body.List)-1 {
							if ifs, okI := opFn.Body.List[afterIdx].(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 3 {
								s0, ok0 := ifs.Body.List[0].(*ast.AssignStmt)
								s1, ok1 := ifs.Body.List[1].(*ast.IfStmt)
								s2, ok2 := ifs.Body.List[2].(*ast.AssignStmt)
								if ok0 && ok1 && ok2 && s0.Tok == token.DEFINE && len(s0.Lhs) == 2 && len(s0.Rhs) == 1 && s2.Tok == token.ASSIGN && len(s2.Lhs) == 1 && len(s2.Rhs) == 1 {
									wdID, okWD := unwrapParens(s0.Lhs[0]).(*ast.Ident)
									wdErrID, okWE := unwrapParens(s0.Lhs[1]).(*ast.Ident)
									wdCall, okWC := unwrapParens(s0.Rhs[0]).(*ast.CallExpr)
									_, okAliasLHS := isIdentNamed(s2.Lhs[0], aID.Name)
									jpCall, okJC := unwrapParens(s2.Rhs[0]).(*ast.CallExpr)
									if okWD && okWE && okWC && okAliasLHS && okJC && wdID.Name != "" && wdID.Name != "_" && wdErrID.Name != "" && !wdCall.Ellipsis.IsValid() && len(wdCall.Args) == 0 && !jpCall.Ellipsis.IsValid() && len(jpCall.Args) == 2 && condChecksNonZeroErr(s1.Cond) == wdErrID.Name && len(s1.Body.List) == 1 {
										_, okGetwd := isSelectorBaseField(wdCall.Fun, "syscall", "Getwd")
										_, okJP := isIdentNamed(jpCall.Fun, "joinPath")
										_, okJA0 := isIdentNamed(jpCall.Args[0], wdID.Name)
										_, okJA1 := isIdentNamed(jpCall.Args[1], opParams[0])
										_, okRet := s1.Body.List[0].(*ast.ReturnStmt)
										if okGetwd && okJP && okJA0 && okJA1 && okRet && verifyJoinPathHelper(allTopFuncs["joinPath"]) {
											afterIdx++
										}
									}
								}
							}
						}
						if !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: opFn.Body.List[afterIdx:]}, map[string]bool{aID.Name: true}) && !bodyDeclaresAnyIdent(&ast.BlockStmt{List: opFn.Body.List[idx+1:]}, map[string]bool{aID.Name: true}) {
							opPathAliases[aID.Name] = true
							continue
						}
					}
				}
			}
			as, okA := st.(*ast.AssignStmt)
			if !okA || len(as.Lhs) != 2 || len(as.Rhs) != 1 {
				continue
			}
			if _, okL0 := isIdentNamed(as.Lhs[0], fdRetID.Name); !okL0 {
				continue
			}
			if _, okL1 := isIdentNamed(as.Lhs[1], errRetID.Name); !okL1 {
				continue
			}
			sc, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
			if !okC || sc.Ellipsis.IsValid() || len(sc.Args) < 1 {
				continue
			}
			if _, okSel := isSelectorBaseField(sc.Fun, "syscall", "Open"); okSel {
				if pID, okP := unwrapParens(sc.Args[0]).(*ast.Ident); okP && opPathAliases[pID.Name] && !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: opFn.Body.List[idx+1:]}, map[string]bool{fdRetID.Name: true, errRetID.Name: true}) {
					sawSyscallOpen = true
					break
				}
			}
		}
		return sawSyscallOpen
	}

	pathAliases := map[string]bool{p0: true}
	openIdx := -1
	var openErrVar string
	for idx := pos; idx < fConstructIdx-1; idx++ {
		st := fn.Body.List[idx]
		if as, okA := st.(*ast.AssignStmt); okA && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			if pID, okP := unwrapParens(as.Lhs[0]).(*ast.Ident); okP && pID.Name != "" && pID.Name != "_" {
				if flCall, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr); okC && !flCall.Ellipsis.IsValid() && len(flCall.Args) == 1 {
					_, okFL := isIdentNamed(flCall.Fun, "fixLongPath")
					_, okArg := isIdentNamed(flCall.Args[0], p0)
					flFn := allTopFuncs["fixLongPath"]
					if okFL && okArg && flFn != nil && flFn.Body != nil && !osAnyLinknameLocals["fixLongPath"] && !funcShadowsAnyIdent(flFn, osNoFileReserved) && !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: fn.Body.List[idx+1:]}, map[string]bool{pID.Name: true}) {
						pathAliases[pID.Name] = true
						continue
					}
				}
			}
		}
		// Form 1: ignoringEINTR(func() error { <wantFDVar>, ..., <eVar> = open(<p0>, ...); return <eVar> })
		if es, okES := st.(*ast.ExprStmt); okES {
			if igCall, okC := unwrapParens(es.X).(*ast.CallExpr); okC && !igCall.Ellipsis.IsValid() && len(igCall.Args) == 1 {
				if _, okIG := isIdentNamed(igCall.Fun, "ignoringEINTR"); okIG && verifyIgnoringEINTR(allTopFuncs["ignoringEINTR"]) && verifyOpenHelper(allTopFuncs["open"]) {
					if fl, okFL := unwrapParens(igCall.Args[0]).(*ast.FuncLit); okFL && fl.Body != nil && len(fl.Body.List) == 2 {
						inAs, okIA := fl.Body.List[0].(*ast.AssignStmt)
						inRet, okIR := fl.Body.List[1].(*ast.ReturnStmt)
						if okIA && okIR && inAs.Tok == token.ASSIGN && len(inAs.Lhs) == 3 && len(inAs.Rhs) == 1 && len(inRet.Results) == 1 {
							_, okFD := isIdentNamed(inAs.Lhs[0], wantFDVar)
							eID, okE := unwrapParens(inAs.Lhs[2]).(*ast.Ident)
							opCall, okOC := unwrapParens(inAs.Rhs[0]).(*ast.CallExpr)
							if okFD && okE && okOC && eID.Name != "" && eID.Name != "_" && eID.Name != wantFDVar && !opCall.Ellipsis.IsValid() && len(opCall.Args) == 3 {
								_, okOpFun := isIdentNamed(opCall.Fun, "open")
								_, okOpArg := isIdentNamed(opCall.Args[0], p0)
								_, okRetE := isIdentNamed(inRet.Results[0], eID.Name)
								if okOpFun && okOpArg && okRetE {
									openIdx = idx
									openErrVar = eID.Name
									break
								}
							}
						}
					}
				}
			}
		}
		// Form 2: <wantFDVar>, <eVar> := syscall.Open(<path>, ...)
		if as, okA := st.(*ast.AssignStmt); okA && (as.Tok == token.DEFINE || as.Tok == token.ASSIGN) && len(as.Lhs) == 2 && len(as.Rhs) == 1 && fileImportsSyscall[funcFile[fn]] {
			_, okFD := isIdentNamed(as.Lhs[0], wantFDVar)
			eID, okE := unwrapParens(as.Lhs[1]).(*ast.Ident)
			sc, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
			if okFD && okE && okC && eID.Name != "" && eID.Name != "_" && eID.Name != wantFDVar && !sc.Ellipsis.IsValid() && len(sc.Args) >= 2 {
				if _, okSel := isSelectorBaseField(sc.Fun, "syscall", "Open"); okSel {
					if pArg, okPA := unwrapParens(sc.Args[0]).(*ast.Ident); okPA && pathAliases[pArg.Name] {
						openIdx = idx
						openErrVar = eID.Name
						break
					}
				}
			}
		}
		// Form 3 (Plan 9): if ... { <wantFDVar>, <eVar> = syscall.Create(<p0>, ...) } else { <wantFDVar>, <eVar> = syscall.Open(<p0>, ...); [if IsNotExist(<eVar>) && ... { <wantFDVar>, <eVar> = syscall.Create(<p0>, ...); if <eVar> != nil { return nil, &PathError{...} } }] }
		if ifs, okI := st.(*ast.IfStmt); okI && ifs.Else != nil && fileImportsSyscall[funcFile[fn]] {
			elseBlk, okEB := ifs.Else.(*ast.BlockStmt)
			if okEB && len(ifs.Body.List) == 1 && (len(elseBlk.List) == 1 || len(elseBlk.List) == 2) {
				as1, okA1 := ifs.Body.List[0].(*ast.AssignStmt)
				as2, okA2 := elseBlk.List[0].(*ast.AssignStmt)
				if okA1 && okA2 && as1.Tok == token.ASSIGN && as2.Tok == token.ASSIGN && len(as1.Lhs) == 2 && len(as1.Rhs) == 1 && len(as2.Lhs) == 2 && len(as2.Rhs) == 1 {
					_, okFD1 := isIdentNamed(as1.Lhs[0], wantFDVar)
					_, okFD2 := isIdentNamed(as2.Lhs[0], wantFDVar)
					e1, okE1 := unwrapParens(as1.Lhs[1]).(*ast.Ident)
					e2, okE2 := unwrapParens(as2.Lhs[1]).(*ast.Ident)
					c1, okC1 := unwrapParens(as1.Rhs[0]).(*ast.CallExpr)
					c2, okC2 := unwrapParens(as2.Rhs[0]).(*ast.CallExpr)
					if okFD1 && okFD2 && okE1 && okE2 && okC1 && okC2 && e1.Name != "" && e1.Name != "_" && e1.Name != wantFDVar && e1.Name == e2.Name && !c1.Ellipsis.IsValid() && !c2.Ellipsis.IsValid() && len(c1.Args) >= 1 && len(c2.Args) >= 1 {
						_, okCr := isSelectorBaseField(c1.Fun, "syscall", "Create")
						_, okOp := isSelectorBaseField(c2.Fun, "syscall", "Open")
						_, okP1 := isIdentNamed(c1.Args[0], p0)
						_, okP2 := isIdentNamed(c2.Args[0], p0)
						elseTailOK := len(elseBlk.List) == 1
						if len(elseBlk.List) == 2 {
							subIf, okSI := elseBlk.List[1].(*ast.IfStmt)
							if okSI && subIf.Init == nil && subIf.Else == nil && len(subIf.Body.List) == 2 {
								as3, okA3 := subIf.Body.List[0].(*ast.AssignStmt)
								errSubIf, okEI := subIf.Body.List[1].(*ast.IfStmt)
								if okA3 && okEI && as3.Tok == token.ASSIGN && len(as3.Lhs) == 2 && len(as3.Rhs) == 1 && errSubIf.Init == nil && errSubIf.Else == nil && condChecksNonZeroErr(errSubIf.Cond) == e1.Name && len(errSubIf.Body.List) == 1 {
									_, okFD3 := isIdentNamed(as3.Lhs[0], wantFDVar)
									_, okE3 := isIdentNamed(as3.Lhs[1], e1.Name)
									c3, okC3 := unwrapParens(as3.Rhs[0]).(*ast.CallExpr)
									subRet, okSR := errSubIf.Body.List[0].(*ast.ReturnStmt)
									if okFD3 && okE3 && okC3 && okSR && !c3.Ellipsis.IsValid() && len(c3.Args) >= 1 && isPathErrorReturn(subRet) {
										_, okCr3 := isSelectorBaseField(c3.Fun, "syscall", "Create")
										_, okP3 := isIdentNamed(c3.Args[0], p0)
										elseTailOK = okCr3 && okP3
									}
								}
							}
						}
						if okCr && okOp && okP1 && okP2 && elseTailOK {
							openIdx = idx
							openErrVar = e1.Name
							break
						}
					}
				}
			}
		}
	}
	if openIdx < 0 || openErrVar == "" {
		return fmt.Errorf("os: openFileNolog missing verified syscall.Open acquisition")
	}
	errIf, ok := fn.Body.List[openIdx+1].(*ast.IfStmt)
	if !ok || errIf.Init != nil || errIf.Else != nil || condChecksNonZeroErr(errIf.Cond) != openErrVar || len(errIf.Body.List) != 1 {
		return fmt.Errorf("os: openFileNolog missing error check immediately after open")
	}
	errRet, ok := errIf.Body.List[0].(*ast.ReturnStmt)
	if !ok || !isPathErrorReturn(errRet) {
		return fmt.Errorf("os: openFileNolog error check does not return &PathError")
	}
	if bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: fn.Body.List[openIdx+1 : fConstructIdx]}, map[string]bool{wantFDVar: true}) || bodyDeclaresAnyIdent(&ast.BlockStmt{List: fn.Body.List[openIdx+1:]}, map[string]bool{wantFDVar: true}) {
		return fmt.Errorf("os: openFileNolog mutates or shadows descriptor %s before newFile", wantFDVar)
	}
	return nil
}

func verifyOSReadFile(rfFn *ast.FuncDecl, rfP0 string, allTopFuncs, allFileMethods, allRawFileMethods map[string]*ast.FuncDecl, osNoFileReserved, osAnyLinknameLocals map[string]bool, skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool) error {
	if len(rfFn.Body.List) != 4 {
		return fmt.Errorf("os: ReadFile must have canonical 4-statement Open/Close/readFileContents body")
	}
	s0, ok0 := rfFn.Body.List[0].(*ast.AssignStmt)
	s1, ok1 := rfFn.Body.List[1].(*ast.IfStmt)
	s2, ok2 := rfFn.Body.List[2].(*ast.DeferStmt)
	s3, ok3 := rfFn.Body.List[3].(*ast.ReturnStmt)
	if !ok0 || (s0.Tok != token.DEFINE && s0.Tok != token.ASSIGN) || len(s0.Lhs) != 2 || len(s0.Rhs) != 1 || !ok1 || s1.Init != nil || s1.Else != nil || len(s1.Body.List) != 1 || !ok2 || !ok3 || len(s3.Results) != 1 {
		return fmt.Errorf("os: ReadFile invalid canonical body shape")
	}
	fID, okF := unwrapParens(s0.Lhs[0]).(*ast.Ident)
	eID, okE := unwrapParens(s0.Lhs[1]).(*ast.Ident)
	openCall, okOC := unwrapParens(s0.Rhs[0]).(*ast.CallExpr)
	if !okF || !okE || !okOC || fID.Name == "" || fID.Name == "_" || eID.Name == "" || eID.Name == "_" || fID.Name == eID.Name || openCall.Ellipsis.IsValid() || len(openCall.Args) != 1 {
		return fmt.Errorf("os: ReadFile first statement must be f, err := Open(%s)", rfP0)
	}
	_, okOpenFun := isIdentNamed(openCall.Fun, "Open")
	_, okOpenArg := isIdentNamed(openCall.Args[0], rfP0)
	if !okOpenFun || !okOpenArg || condChecksNonZeroErr(s1.Cond) != eID.Name {
		return fmt.Errorf("os: ReadFile Open call or error guard invalid")
	}
	errRet, okER := s1.Body.List[0].(*ast.ReturnStmt)
	if !okER || len(errRet.Results) != 2 {
		return fmt.Errorf("os: ReadFile error guard invalid return")
	}
	_, okNil0 := isIdentNamed(errRet.Results[0], "nil")
	_, okErr1 := isIdentNamed(errRet.Results[1], eID.Name)
	if !okNil0 || !okErr1 {
		return fmt.Errorf("os: ReadFile error guard does not return nil, %s", eID.Name)
	}
	if _, okClose := isZeroArgMethodCallOnIdent(s2.Call, fID.Name, "Close"); !okClose {
		return fmt.Errorf("os: ReadFile missing defer %s.Close()", fID.Name)
	}
	rfcCall, okRFC := unwrapParens(s3.Results[0]).(*ast.CallExpr)
	if !okRFC || rfcCall.Ellipsis.IsValid() || len(rfcCall.Args) != 2 {
		return fmt.Errorf("os: ReadFile final return is not readFileContents(statOrZero(f), f.Read)")
	}
	if _, okRFCFun := isIdentNamed(rfcCall.Fun, "readFileContents"); !okRFCFun {
		return fmt.Errorf("os: ReadFile does not call readFileContents")
	}
	sozCall, okSOZ := unwrapParens(rfcCall.Args[0]).(*ast.CallExpr)
	if !okSOZ || sozCall.Ellipsis.IsValid() || len(sozCall.Args) != 1 {
		return fmt.Errorf("os: ReadFile first arg to readFileContents is not statOrZero(%s)", fID.Name)
	}
	_, okSOZFun := isIdentNamed(sozCall.Fun, "statOrZero")
	_, okSOZArg := isIdentNamed(sozCall.Args[0], fID.Name)
	_, okReadSel := isSelectorBaseField(rfcCall.Args[1], fID.Name, "Read")
	if !okSOZFun || !okSOZArg || !okReadSel {
		return fmt.Errorf("os: ReadFile arguments to readFileContents are not (statOrZero(%s), %s.Read)", fID.Name, fID.Name)
	}

	type workItem struct {
		kind       string // "top", "file", "raw"
		name       string
		arg0IsFile bool
	}
	queue := []workItem{
		{kind: "top", name: "readFileContents"},
		{kind: "top", name: "statOrZero", arg0IsFile: true},
		{kind: "file", name: "Read"},
	}
	seen := map[workItem]bool{}
	enqueue := func(it workItem) {
		if !seen[it] {
			seen[it] = true
			queue = append(queue, it)
		}
	}
	for _, it := range queue {
		seen[it] = true
	}

	forbiddenTopCalls := map[string]bool{
		"Open": true, "OpenFile": true, "Create": true, "Stat": true, "Lstat": true,
		"Getenv": true, "LookupEnv": true, "Chdir": true, "ReadDir": true, "openDir": true,
		"Exit": true, "NewFile": true, "newFile": true,
	}
	forbiddenSyscallSels := map[string]bool{
		"Open": true, "Creat": true, "Stat": true, "Lstat": true,
		"Chdir": true, "Fchdir": true, "Getenv": true, "Exit": true, "ExitProcess": true,
	}
	collectPtrTypeIdents := func(fl *ast.FieldList, targetType string, dst map[string]bool) {
		if fl == nil {
			return
		}
		for _, fld := range fl.List {
			star, okS := unwrapParens(fld.Type).(*ast.StarExpr)
			if !okS {
				continue
			}
			if _, okT := isIdentNamed(star.X, targetType); !okT {
				continue
			}
			for _, id := range fld.Names {
				if id.Name != "" && id.Name != "_" {
					dst[id.Name] = true
				}
			}
		}
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		var hFn *ast.FuncDecl
		switch cur.kind {
		case "top":
			hFn = allTopFuncs[cur.name]
		case "file":
			hFn = allFileMethods[cur.name]
		case "raw":
			hFn = allRawFileMethods[cur.name]
		}
		if hFn == nil || hFn.Body == nil || osAnyLinknameLocals[cur.name] || funcShadowsAnyIdent(hFn, map[string]bool{"testlog": true, "syscall": true}) {
			return fmt.Errorf("os: ReadFile helper %s:%s missing, bodyless, linknamed, or shadowing reserved identifier", cur.kind, cur.name)
		}
		fileVars := map[string]bool{}
		rawFileVars := map[string]bool{}
		collectPtrTypeIdents(hFn.Recv, "File", fileVars)
		collectPtrTypeIdents(hFn.Type.Params, "File", fileVars)
		collectPtrTypeIdents(hFn.Recv, "file", rawFileVars)
		collectPtrTypeIdents(hFn.Type.Params, "file", rawFileVars)
		if cur.arg0IsFile && cur.kind == "top" {
			hParams := paramNamesFlat(hFn.Type.Params)
			if len(hParams) >= 1 && hParams[0] != "" && hParams[0] != "_" && !bodyMutatesOrTakesAddrOfAny(hFn.Body, map[string]bool{hParams[0]: true}) && !bodyDeclaresAnyIdent(hFn.Body, map[string]bool{hParams[0]: true}) {
				fileVars[hParams[0]] = true
			}
		}

		pos := 0
		for pos < len(hFn.Body.List) && skipInactiveHookIf(hFn.Body.List[pos], hFn) {
			pos++
		}
		var helperErr error
		var inspectHelperNode func(n ast.Node, curFileVars map[string]bool)
		inspectHelperNode = func(n ast.Node, curFileVars map[string]bool) {
			if helperErr != nil || n == nil {
				return
			}
			if ifs, okI := n.(*ast.IfStmt); okI && skipInactiveHookIf(ifs, hFn) {
				return
			}
			if ts, okTS := n.(*ast.TypeSwitchStmt); okTS {
				var switchTarget string
				var boundName string
				switch as := ts.Assign.(type) {
				case *ast.ExprStmt:
					if ta, okTA := unwrapParens(as.X).(*ast.TypeAssertExpr); okTA && ta.Type == nil {
						if id, okID := unwrapParens(ta.X).(*ast.Ident); okID {
							switchTarget = id.Name
						}
					}
				case *ast.AssignStmt:
					if as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
						if lhsID, okL := unwrapParens(as.Lhs[0]).(*ast.Ident); okL {
							if ta, okTA := unwrapParens(as.Rhs[0]).(*ast.TypeAssertExpr); okTA && ta.Type == nil {
								if id, okID := unwrapParens(ta.X).(*ast.Ident); okID {
									switchTarget = id.Name
									boundName = lhsID.Name
								}
							}
						}
					}
				}
				if switchTarget != "" && curFileVars[switchTarget] && ts.Init == nil && ts.Body != nil {
					for _, rawClause := range ts.Body.List {
						cc, okCC := rawClause.(*ast.CaseClause)
						if !okCC {
							continue
						}
						if len(cc.List) == 1 {
							star, okS := unwrapParens(cc.List[0]).(*ast.StarExpr)
							if okS {
								if _, okF := isIdentNamed(star.X, "File"); okF {
									nextFV := maps.Clone(curFileVars)
									if boundName != "" && boundName != "_" {
										nextFV[boundName] = true
									}
									for _, bs := range cc.Body {
										inspectHelperNode(bs, nextFV)
									}
									continue
								}
							}
							if cID, okID := unwrapParens(cc.List[0]).(*ast.Ident); okID && (cID.Name == "string" || cID.Name == "int" || cID.Name == "uintptr") {
								continue
							}
						}
						for _, bs := range cc.Body {
							inspectHelperNode(bs, curFileVars)
						}
					}
					return
				}
			}
			switch x := n.(type) {
			case *ast.Ident:
				if x.Name == "testlog" {
					helperErr = fmt.Errorf("os: ReadFile helper %s:%s references testlog", cur.kind, cur.name)
					return
				}
			case *ast.SelectorExpr:
				if baseID, okB := unwrapParens(x.X).(*ast.Ident); okB {
					if baseID.Name == "syscall" && forbiddenSyscallSels[x.Sel.Name] {
						helperErr = fmt.Errorf("os: ReadFile helper %s:%s references syscall.%s", cur.kind, cur.name, x.Sel.Name)
						return
					}
					if curFileVars[baseID.Name] && x.Sel.Name != "Close" {
						if allFileMethods[x.Sel.Name] != nil {
							enqueue(workItem{kind: "file", name: x.Sel.Name})
						} else if allRawFileMethods[x.Sel.Name] != nil {
							enqueue(workItem{kind: "raw", name: x.Sel.Name})
						}
					}
					if rawFileVars[baseID.Name] && x.Sel.Name != "close" && allRawFileMethods[x.Sel.Name] != nil {
						enqueue(workItem{kind: "raw", name: x.Sel.Name})
					}
				} else if innerSel, okIS := unwrapParens(x.X).(*ast.SelectorExpr); okIS && innerSel.Sel.Name == "file" {
					if baseID, okB := unwrapParens(innerSel.X).(*ast.Ident); okB && curFileVars[baseID.Name] && x.Sel.Name != "close" && allRawFileMethods[x.Sel.Name] != nil {
						enqueue(workItem{kind: "raw", name: x.Sel.Name})
					}
				}
			case *ast.CallExpr:
				if cID, okID := unwrapParens(x.Fun).(*ast.Ident); okID {
					if forbiddenTopCalls[cID.Name] {
						helperErr = fmt.Errorf("os: ReadFile helper %s:%s calls forbidden %s", cur.kind, cur.name, cID.Name)
						return
					}
					if osAnyLinknameLocals[cID.Name] {
						helperErr = fmt.Errorf("os: ReadFile helper %s:%s calls linknamed %s", cur.kind, cur.name, cID.Name)
						return
					}
					if allTopFuncs[cID.Name] != nil {
						a0File := false
						if !x.Ellipsis.IsValid() && len(x.Args) >= 1 {
							if aID, okA := unwrapParens(x.Args[0]).(*ast.Ident); okA && curFileVars[aID.Name] {
								a0File = true
							}
						}
						enqueue(workItem{kind: "top", name: cID.Name, arg0IsFile: a0File})
					}
				} else if cSel, okS := unwrapParens(x.Fun).(*ast.SelectorExpr); okS {
					if baseID, okB := unwrapParens(cSel.X).(*ast.Ident); okB {
						if curFileVars[baseID.Name] && cSel.Sel.Name != "Close" {
							if allFileMethods[cSel.Sel.Name] != nil {
								enqueue(workItem{kind: "file", name: cSel.Sel.Name})
							} else if allRawFileMethods[cSel.Sel.Name] != nil {
								enqueue(workItem{kind: "raw", name: cSel.Sel.Name})
							} else {
								helperErr = fmt.Errorf("os: ReadFile helper %s:%s calls unknown *File method %s", cur.kind, cur.name, cSel.Sel.Name)
								return
							}
						}
						if rawFileVars[baseID.Name] && cSel.Sel.Name != "close" {
							if allRawFileMethods[cSel.Sel.Name] == nil {
								helperErr = fmt.Errorf("os: ReadFile helper %s:%s calls unknown *file method %s", cur.kind, cur.name, cSel.Sel.Name)
								return
							}
							enqueue(workItem{kind: "raw", name: cSel.Sel.Name})
						}
					}
				}
			}
			ast.Inspect(n, func(ch ast.Node) bool {
				if ch == n {
					return true
				}
				inspectHelperNode(ch, curFileVars)
				return false
			})
		}
		for _, st := range hFn.Body.List[pos:] {
			inspectHelperNode(st, fileVars)
			if helperErr != nil {
				return helperErr
			}
		}
	}
	return nil
}

func funcHasUnnamedResults(ft *ast.FuncType, count int) bool {
	if ft == nil || ft.Results == nil || ft.Results.NumFields() != count || len(ft.Results.List) != count {
		return false
	}
	for _, fld := range ft.Results.List {
		if len(fld.Names) != 0 {
			return false
		}
	}
	return true
}

func verifyOSIgnoringEINTR(igFn *ast.FuncDecl, funcFile map[*ast.FuncDecl]*ast.File, fileImportsSyscall map[*ast.File]bool, osNoFileReserved, osAnyLinknameLocals map[string]bool) bool {
	if igFn == nil || igFn.Body == nil || igFn.Type == nil || igFn.Type.TypeParams != nil || !funcHasUnnamedResults(igFn.Type, 1) || osAnyLinknameLocals["ignoringEINTR"] || funcShadowsAnyIdent(igFn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(igFn.Body) {
		return false
	}
	igParams := paramNamesFlat(igFn.Type.Params)
	if len(igParams) != 1 || igParams[0] == "" || igParams[0] == "_" || len(igFn.Body.List) != 1 {
		return false
	}
	if ret, okRet := igFn.Body.List[0].(*ast.ReturnStmt); okRet && len(ret.Results) == 1 {
		c, okC := unwrapParens(ret.Results[0]).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) != 0 {
			return false
		}
		_, okFn := isIdentNamed(c.Fun, igParams[0])
		return okFn
	}
	fs, okFor := igFn.Body.List[0].(*ast.ForStmt)
	if !okFor || !fileImportsSyscall[funcFile[igFn]] || fs.Init != nil || fs.Cond != nil || fs.Post != nil || len(fs.Body.List) != 2 {
		return false
	}
	as, okA := fs.Body.List[0].(*ast.AssignStmt)
	if !okA || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
		return false
	}
	errID, okE := unwrapParens(as.Lhs[0]).(*ast.Ident)
	if !okE || errID.Name == "" || errID.Name == "_" {
		return false
	}
	c, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
	if !okC || c.Ellipsis.IsValid() || len(c.Args) != 0 {
		return false
	}
	if _, okFn := isIdentNamed(c.Fun, igParams[0]); !okFn {
		return false
	}
	ifs, okI := fs.Body.List[1].(*ast.IfStmt)
	if !okI || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
		return false
	}
	condBin, okCB := unwrapParens(ifs.Cond).(*ast.BinaryExpr)
	if !okCB || condBin.Op != token.NEQ {
		return false
	}
	_, okEL := isIdentNamed(condBin.X, errID.Name)
	_, okSysR := isSelectorBaseField(condBin.Y, "syscall", "EINTR")
	_, okSysL := isSelectorBaseField(condBin.X, "syscall", "EINTR")
	_, okER := isIdentNamed(condBin.Y, errID.Name)
	if !((okEL && okSysR) || (okSysL && okER)) {
		return false
	}
	ret, okR := ifs.Body.List[0].(*ast.ReturnStmt)
	if !okR || len(ret.Results) != 1 {
		return false
	}
	_, okRetErr := isIdentNamed(ret.Results[0], errID.Name)
	return okRetErr
}

func verifyOSGetwd(
	files []*ast.File,
	gwFn *ast.FuncDecl,
	allTopFuncs, allFileMethods, allRawFileMethods, allFileStatMethods map[string]*ast.FuncDecl,
	nonAliasStructSpecs map[string]*ast.TypeSpec,
	pkgDeclCounts, fileMethodCounts, rawFileMethodCounts, fileStatMethodCounts map[string]int,
	funcFile map[*ast.FuncDecl]*ast.File,
	fileImportsSyscall map[*ast.File]bool,
	verifiedNonNilOSErrIdents, osReserved, osNoFileReserved, osAnyLinknameLocals map[string]bool,
	osInactive *osInactiveState,
	skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool,
) error {
	if gwFn == nil || gwFn.Body == nil || gwFn.Type == nil || gwFn.Type.TypeParams != nil || osAnyLinknameLocals["Getwd"] {
		return fmt.Errorf("os: missing or invalid Getwd")
	}
	if !fileImportsSyscall[funcFile[gwFn]] || funcShadowsAnyIdent(gwFn, osReserved) {
		return fmt.Errorf("os: Getwd missing syscall import or shadows reserved identifier")
	}
	if (gwFn.Type.Params != nil && gwFn.Type.Params.NumFields() != 0) || gwFn.Type.Results == nil || gwFn.Type.Results.NumFields() != 2 || len(gwFn.Type.Results.List) != 2 || !funcReturnsErrorLast(gwFn.Type) {
		return fmt.Errorf("os: Getwd invalid signature")
	}
	if _, okStr := isIdentNamed(gwFn.Type.Results.List[0].Type, "string"); !okStr {
		return fmt.Errorf("os: Getwd first result is not string")
	}
	pos := 0
	for pos < len(gwFn.Body.List) && skipInactiveHookIf(gwFn.Body.List[pos], gwFn) {
		pos++
	}
	gwStmts := gwFn.Body.List[pos:]
	if len(gwStmts) == 0 {
		return fmt.Errorf("os: Getwd empty body")
	}
	for _, topSt := range gwStmts[:len(gwStmts)-1] {
		if _, isBareRet := topSt.(*ast.ReturnStmt); isBareRet {
			return fmt.Errorf("os: Getwd has unconditional early return")
		}
	}

	stmtUnwrapLabel := func(st ast.Stmt) ast.Stmt {
		for {
			ls, ok := st.(*ast.LabeledStmt)
			if !ok {
				return st
			}
			st = ls.Stmt
		}
	}
	isNonEmptyStrLit := func(expr ast.Expr) bool {
		lit, ok := unwrapParens(expr).(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return false
		}
		unq, err := strconv.Unquote(lit.Value)
		return err == nil && unq != ""
	}
	isSameFileCallPair := func(expr ast.Expr) (string, string, bool) {
		c, okC := unwrapParens(expr).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) != 2 {
			return "", "", false
		}
		if _, okSF := isIdentNamed(c.Fun, "SameFile"); !okSF {
			return "", "", false
		}
		a0, ok0 := unwrapParens(c.Args[0]).(*ast.Ident)
		a1, ok1 := unwrapParens(c.Args[1]).(*ast.Ident)
		if !ok0 || !ok1 || a0.Name == "" || a0.Name == "_" || a1.Name == "" || a1.Name == "_" {
			return "", "", false
		}
		return a0.Name, a1.Name, true
	}
	isDirectOrWrappedErrExpr := func(expr ast.Expr, wantErr string) bool {
		if _, okDirect := isIdentNamed(expr, wantErr); okDirect {
			return true
		}
		c, okC := unwrapParens(expr).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) != 2 {
			return false
		}
		_, okNSE := isIdentNamed(c.Fun, "NewSyscallError")
		_, okErr := isIdentNamed(c.Args[1], wantErr)
		return okNSE && isNonEmptyStrLit(c.Args[0]) && okErr
	}
	isVerifiedConstErrArg := func(expr ast.Expr) bool {
		if sel, okS := unwrapParens(expr).(*ast.SelectorExpr); okS {
			_, okSys := isIdentNamed(sel.X, "syscall")
			return okSys && strings.HasPrefix(sel.Sel.Name, "E") && len(sel.Sel.Name) > 1
		}
		if id, okID := unwrapParens(expr).(*ast.Ident); okID {
			return verifiedNonNilOSErrIdents[id.Name] && !funcShadowsAnyIdent(gwFn, map[string]bool{id.Name: true})
		}
		return false
	}
	isVerifiedConstGetwdErr := func(expr ast.Expr) bool {
		if isVerifiedConstErrArg(expr) {
			return true
		}
		c, okC := unwrapParens(expr).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) != 2 {
			return false
		}
		_, okNSE := isIdentNamed(c.Fun, "NewSyscallError")
		return okNSE && isNonEmptyStrLit(c.Args[0]) && isVerifiedConstErrArg(c.Args[1])
	}
	condChecksAbsSlashPrefix := func(cond ast.Expr, dirVar string) bool {
		found := false
		var check func(e ast.Expr)
		check = func(e ast.Expr) {
			if found || e == nil {
				return
			}
			bin, okB := unwrapParens(e).(*ast.BinaryExpr)
			if !okB {
				return
			}
			if bin.Op == token.LAND {
				check(bin.X)
				check(bin.Y)
				return
			}
			if bin.Op != token.EQL {
				return
			}
			matchIdxSlash := func(idxSide, charSide ast.Expr) bool {
				ix, okIX := unwrapParens(idxSide).(*ast.IndexExpr)
				lit, okL := unwrapParens(charSide).(*ast.BasicLit)
				if !okIX || !okL || !isZeroIntLit(ix.Index) {
					return false
				}
				if _, okD := isIdentNamed(ix.X, dirVar); !okD {
					return false
				}
				return lit.Kind == token.CHAR && lit.Value == `'/'`
			}
			if matchIdxSlash(bin.X, bin.Y) || matchIdxSlash(bin.Y, bin.X) {
				found = true
			}
		}
		check(cond)
		return found
	}
	isParentLenBoundCond := func(cond ast.Expr, parentLoopVars map[string]bool) bool {
		bin, okB := unwrapParens(cond).(*ast.BinaryExpr)
		if !okB {
			return false
		}
		checkLenLit := func(lenSide, litSide ast.Expr) bool {
			c, okC := unwrapParens(lenSide).(*ast.CallExpr)
			lit, okL := unwrapParens(litSide).(*ast.BasicLit)
			if !okC || !okL || c.Ellipsis.IsValid() || len(c.Args) != 1 || lit.Kind != token.INT {
				return false
			}
			if _, okLen := isIdentNamed(c.Fun, "len"); !okLen {
				return false
			}
			pID, okP := unwrapParens(c.Args[0]).(*ast.Ident)
			if !okP || !parentLoopVars[pID.Name] {
				return false
			}
			n, err := strconv.ParseInt(lit.Value, 0, 64)
			return err == nil && n >= 64
		}
		switch bin.Op {
		case token.GEQ, token.GTR:
			return checkLenLit(bin.X, bin.Y)
		case token.LEQ, token.LSS:
			return checkLenLit(bin.Y, bin.X)
		default:
			return false
		}
	}
	condChecksNonEmptyStr := func(cond ast.Expr, dirVar string) bool {
		found := false
		var check func(e ast.Expr)
		check = func(e ast.Expr) {
			if found || e == nil {
				return
			}
			bin, okB := unwrapParens(e).(*ast.BinaryExpr)
			if !okB {
				return
			}
			if bin.Op == token.LAND {
				check(bin.X)
				check(bin.Y)
				return
			}
			matchLenCall := func(side ast.Expr) bool {
				c, okC := unwrapParens(side).(*ast.CallExpr)
				if !okC || c.Ellipsis.IsValid() || len(c.Args) != 1 {
					return false
				}
				_, okLen := isIdentNamed(c.Fun, "len")
				_, okD := isIdentNamed(c.Args[0], dirVar)
				return okLen && okD
			}
			parseIntSide := func(side ast.Expr) (int64, bool) {
				lit, okL := unwrapParens(side).(*ast.BasicLit)
				if !okL || lit.Kind != token.INT {
					return 0, false
				}
				n, err := strconv.ParseInt(lit.Value, 0, 64)
				return n, err == nil
			}
			switch bin.Op {
			case token.GTR:
				if matchLenCall(bin.X) {
					if n, ok := parseIntSide(bin.Y); ok && n >= 0 {
						found = true
					}
				}
			case token.LSS:
				if matchLenCall(bin.Y) {
					if n, ok := parseIntSide(bin.X); ok && n >= 0 {
						found = true
					}
				}
			case token.GEQ:
				if matchLenCall(bin.X) {
					if n, ok := parseIntSide(bin.Y); ok && n >= 1 {
						found = true
					}
				}
			case token.LEQ:
				if matchLenCall(bin.Y) {
					if n, ok := parseIntSide(bin.X); ok && n >= 1 {
						found = true
					}
				}
			case token.NEQ:
				isEmpty := func(side ast.Expr) bool {
					lit, okL := unwrapParens(side).(*ast.BasicLit)
					return okL && lit.Kind == token.STRING && lit.Value == `""`
				}
				_, okLX := isIdentNamed(bin.X, dirVar)
				_, okLY := isIdentNamed(bin.Y, dirVar)
				if (okLX && isEmpty(bin.Y)) || (okLY && isEmpty(bin.X)) {
					found = true
				}
			}
		}
		check(cond)
		return found
	}
	isGetenvPWDCall := func(expr ast.Expr) bool {
		c, okC := unwrapParens(expr).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) != 1 {
			return false
		}
		_, okGE := isIdentNamed(c.Fun, "Getenv")
		lit, okLit := unwrapParens(c.Args[0]).(*ast.BasicLit)
		return okGE && okLit && lit.Kind == token.STRING && lit.Value == `"PWD"`
	}
	collectCompoundStmtMutations := func(node ast.Node, mutated, assignedPWD map[string]bool) {
		ast.Inspect(node, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range x.Lhs {
					if id, okID := unwrapParens(lhs).(*ast.Ident); okID && id.Name != "" && id.Name != "_" {
						mutated[id.Name] = true
						if len(x.Lhs) == len(x.Rhs) && i < len(x.Rhs) && isGetenvPWDCall(x.Rhs[i]) {
							assignedPWD[id.Name] = true
						}
					}
				}
			case *ast.ValueSpec:
				for i, id := range x.Names {
					if id.Name != "" && id.Name != "_" {
						mutated[id.Name] = true
						if i < len(x.Values) && isGetenvPWDCall(x.Values[i]) {
							assignedPWD[id.Name] = true
						}
					}
				}
			case *ast.RangeStmt:
				if x.Key != nil {
					if id, okK := unwrapParens(x.Key).(*ast.Ident); okK && id.Name != "" && id.Name != "_" {
						mutated[id.Name] = true
					}
				}
				if x.Value != nil {
					if id, okV := unwrapParens(x.Value).(*ast.Ident); okV && id.Name != "" && id.Name != "_" {
						mutated[id.Name] = true
					}
				}
			case *ast.IncDecStmt:
				if id, okID := unwrapParens(x.X).(*ast.Ident); okID && id.Name != "" && id.Name != "_" {
					mutated[id.Name] = true
				}
			}
			return true
		})
	}
	stmtsMutateIdentBefore := func(list []ast.Stmt, stopAt ast.Node, target string) bool {
		mutated := false
		stopped := false
		for _, s := range list {
			ast.Inspect(s, func(n ast.Node) bool {
				if mutated || stopped || n == nil {
					return false
				}
				if stopAt != nil && n == stopAt {
					stopped = true
					return false
				}
				switch x := n.(type) {
				case *ast.AssignStmt:
					for _, lhs := range x.Lhs {
						if _, okID := isIdentNamed(lhs, target); okID {
							mutated = true
							return false
						}
					}
				case *ast.ValueSpec:
					for _, id := range x.Names {
						if id.Name == target {
							mutated = true
							return false
						}
					}
				case *ast.RangeStmt:
					if x.Key != nil {
						if _, okK := isIdentNamed(x.Key, target); okK {
							mutated = true
							return false
						}
					}
					if x.Value != nil {
						if _, okV := isIdentNamed(x.Value, target); okV {
							mutated = true
							return false
						}
					}
				case *ast.IncDecStmt:
					if _, okID := isIdentNamed(x.X, target); okID {
						mutated = true
						return false
					}
				}
				return true
			})
			if mutated || stopped {
				break
			}
		}
		return mutated
	}
	isCheckedErrGuardIf := func(st ast.Stmt, wantErr string) (*ast.ReturnStmt, bool) {
		ifs, okI := st.(*ast.IfStmt)
		if !okI || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 || condChecksNonZeroErr(ifs.Cond) != wantErr {
			return nil, false
		}
		ret, okR := ifs.Body.List[0].(*ast.ReturnStmt)
		if !okR || len(ret.Results) != 2 {
			return nil, false
		}
		r0Lit, ok0 := unwrapParens(ret.Results[0]).(*ast.BasicLit)
		_, ok1 := isIdentNamed(ret.Results[1], wantErr)
		if !ok0 || r0Lit.Kind != token.STRING || r0Lit.Value != `""` || !ok1 {
			return nil, false
		}
		return ret, true
	}
	isCloseCallOn := func(st ast.Stmt, fdVar string) bool {
		es, okE := st.(*ast.ExprStmt)
		if !okE {
			return false
		}
		c, okC := unwrapParens(es.X).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) != 0 {
			return false
		}
		_, okSel := isSelectorBaseField(c.Fun, fdVar, "Close")
		return okSel
	}

	var sawSyscallGetwd, usedIgnoringEINTR2, usedNewSyscallError, usedSameFile, usedStatHelpers, usedOpenDirNolog, usedFstatNolog, usedFileStatInGetwd, usedGetwdCache bool
	allowedSyscallGetwdSels := map[*ast.SelectorExpr]bool{}
	allowedReturns := map[*ast.ReturnStmt]bool{}
	validErrIfs := map[*ast.IfStmt]string{}
	dotSeedAssigns := map[*ast.AssignStmt]bool{}
	rootSeedAssigns := map[*ast.AssignStmt]bool{}
	fdSeedAssigns := map[*ast.AssignStmt]bool{}
	pdSeedAssigns := map[*ast.AssignStmt]bool{}
	shape1Assigns := map[*ast.AssignStmt]bool{}
	parentInitAssigns := map[*ast.AssignStmt]bool{}
	parentStepAssigns := map[*ast.AssignStmt]bool{}
	dotVars := map[string]bool{}
	rootVars := map[string]bool{}
	fdVarsInLoop := map[string]bool{}
	pdVarsInLoop := map[string]bool{}
	shape2ReturnedDirVars := map[string]bool{}
	parentLoopVars := map[string]bool{}
	var topParentLoop *ast.ForStmt
	topParentLoopIdx := -1
	sawLoopInGetwd := false

	var verifyBlock func(stmts []ast.Stmt, enclosingIfs []*ast.IfStmt, inLoop bool, pwdUncheckedVars, validErrVars map[string]bool) error
	verifyBlock = func(stmts []ast.Stmt, enclosingIfs []*ast.IfStmt, inLoop bool, pwdUncheckedVars, validErrVars map[string]bool) error {
		curPWD := maps.Clone(pwdUncheckedVars)
		curValidErr := maps.Clone(validErrVars)
		for idx := 0; idx < len(stmts); idx++ {
			raw := stmts[idx]
			if _, isLbl := raw.(*ast.LabeledStmt); isLbl {
				clear(curValidErr)
			}
			st := stmtUnwrapLabel(raw)

			if ds, okDS := st.(*ast.DeclStmt); okDS {
				if gd, okGD := ds.Decl.(*ast.GenDecl); okGD {
					for _, spec := range gd.Specs {
						if vs, okVS := spec.(*ast.ValueSpec); okVS {
							for i, id := range vs.Names {
								if id.Name != "" && id.Name != "_" {
									delete(curValidErr, id.Name)
									if i < len(vs.Values) && isGetenvPWDCall(vs.Values[i]) {
										curPWD[id.Name] = true
									} else if len(vs.Values) == 0 {
										delete(curPWD, id.Name)
									} else if i < len(vs.Values) {
										if lit, okLit := unwrapParens(vs.Values[i]).(*ast.BasicLit); okLit && lit.Kind == token.STRING && lit.Value == `""` {
											delete(curPWD, id.Name)
										}
									}
								}
							}
						}
					}
				}
			}

			if as, okA := st.(*ast.AssignStmt); okA {
				// Track PWD vs getwdCache.dir hint state on 1-LHS assignments.
				if len(as.Lhs) == 1 && len(as.Rhs) == 1 {
					if lID, okL := unwrapParens(as.Lhs[0]).(*ast.Ident); okL && lID.Name != "" && lID.Name != "_" {
						if isGetenvPWDCall(as.Rhs[0]) {
							curPWD[lID.Name] = true
						} else if _, okCache := isSelectorBaseField(as.Rhs[0], "getwdCache", "dir"); okCache {
							usedGetwdCache = true
							delete(curPWD, lID.Name)
						} else if lit, okLit := unwrapParens(as.Rhs[0]).(*ast.BasicLit); okLit && lit.Kind == token.STRING && lit.Value == `""` {
							delete(curPWD, lID.Name)
						}
					}
				}

				producesValidErr := false
				var validErrName string
				if (as.Tok == token.DEFINE || as.Tok == token.ASSIGN) && len(as.Lhs) == 2 && len(as.Rhs) == 1 {
					l0, ok0 := unwrapParens(as.Lhs[0]).(*ast.Ident)
					l1, ok1 := unwrapParens(as.Lhs[1]).(*ast.Ident)
					c, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
					if ok0 && ok1 && okC && !c.Ellipsis.IsValid() && l0.Name != "" && l0.Name != "_" && l1.Name != "_" && l0.Name != l1.Name {
						if l1.Name != "" {
							if _, okLS := isIdentNamed(c.Fun, "lstatNolog"); okLS && len(c.Args) == 1 {
								usedStatHelpers = true
								producesValidErr = true
								validErrName = l1.Name
							}
						}
					}
					if ok0 && ok1 && okC && !c.Ellipsis.IsValid() && l0.Name != "" && l0.Name != "_" && l1.Name != "" && l1.Name != "_" && l0.Name != l1.Name {
						// Shape 1: <dVar>, <eVar> =|:= syscall.Getwd() | ignoringEINTR2(syscall.Getwd).
						var sgSel *ast.SelectorExpr
						if _, okSG := isSelectorBaseField(c.Fun, "syscall", "Getwd"); okSG && len(c.Args) == 0 {
							sgSel = unwrapParens(c.Fun).(*ast.SelectorExpr)
						} else if _, okIG := isIdentNamed(c.Fun, "ignoringEINTR2"); okIG && len(c.Args) == 1 {
							if _, okSG := isSelectorBaseField(c.Args[0], "syscall", "Getwd"); okSG {
								sgSel = unwrapParens(c.Args[0]).(*ast.SelectorExpr)
							}
						}
						if sgSel != nil {
							producesValidErr = true
							validErrName = l1.Name
							if idx+1 >= len(stmts) {
								return fmt.Errorf("os: Getwd syscall.Getwd call missing immediate return")
							}
							nextSt := stmts[idx+1]
							var matchedRet *ast.ReturnStmt
							if ret, okR := nextSt.(*ast.ReturnStmt); okR && len(ret.Results) == 2 {
								if _, okD := isIdentNamed(ret.Results[0], l0.Name); okD && isDirectOrWrappedErrExpr(ret.Results[1], l1.Name) {
									matchedRet = ret
								}
							} else if ifs, okI := nextSt.(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
								if ret, okR := ifs.Body.List[0].(*ast.ReturnStmt); okR && len(ret.Results) == 2 {
									if _, okD := isIdentNamed(ret.Results[0], l0.Name); okD && isDirectOrWrappedErrExpr(ret.Results[1], l1.Name) {
										matchedRet = ret
									}
								}
							}
							if matchedRet == nil {
								return fmt.Errorf("os: Getwd syscall.Getwd result (%s, %s) not immediately returned with its error", l0.Name, l1.Name)
							}
							allowedSyscallGetwdSels[sgSel] = true
							allowedReturns[matchedRet] = true
							shape1Assigns[as] = true
							delete(curPWD, l0.Name)
							sawSyscallGetwd = true
						}

						// Seed dot/root/Shape 2 via statNolog(...).
						if _, okSN := isIdentNamed(c.Fun, "statNolog"); okSN && len(c.Args) == 1 {
							usedStatHelpers = true
							producesValidErr = true
							validErrName = l1.Name
							if lit, okLit := unwrapParens(c.Args[0]).(*ast.BasicLit); okLit && lit.Kind == token.STRING {
								if (lit.Value == `"."` || lit.Value == `"/"`) && idx+1 < len(stmts) {
									if errRet, okG := isCheckedErrGuardIf(stmts[idx+1], l1.Name); okG {
										allowedReturns[errRet] = true
										if lit.Value == `"."` {
											dotSeedAssigns[as] = true
											dotVars[l0.Name] = true
										} else {
											rootSeedAssigns[as] = true
											rootVars[l0.Name] = true
										}
									}
								}
							} else if dirArgID, okDA := unwrapParens(c.Args[0]).(*ast.Ident); okDA && !inLoop && !sawLoopInGetwd && dirArgID.Name != "" && dirArgID.Name != "_" && dirArgID.Name != l0.Name && dirArgID.Name != l1.Name && idx+1 < len(stmts) {
								if ifs, okI := stmts[idx+1].(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
									if bin, okB := unwrapParens(ifs.Cond).(*ast.BinaryExpr); okB && bin.Op == token.LAND && condChecksEqErr(bin.X, l1.Name) {
										if a0, a1, okSF := isSameFileCallPair(bin.Y); okSF {
											dotCand := ""
											if a0 == l0.Name && dotVars[a1] {
												dotCand = a1
											} else if a1 == l0.Name && dotVars[a0] {
												dotCand = a0
											}
											if dotCand != "" {
												if ret, okR := ifs.Body.List[0].(*ast.ReturnStmt); okR && len(ret.Results) == 2 {
													_, okRD := isIdentNamed(ret.Results[0], dirArgID.Name)
													_, okRN := isIdentNamed(ret.Results[1], "nil")
													if okRD && okRN {
														hasNonEmptyGuard := false
														for _, enc := range enclosingIfs {
															if condChecksNonEmptyStr(enc.Cond, dirArgID.Name) {
																hasNonEmptyGuard = true
																break
															}
														}
														if !hasNonEmptyGuard {
															return fmt.Errorf("os: Getwd hint %s returned without non-empty guard", dirArgID.Name)
														}
														if curPWD[dirArgID.Name] {
															hasSlashGuard := false
															for _, enc := range enclosingIfs {
																if condChecksAbsSlashPrefix(enc.Cond, dirArgID.Name) {
																	hasSlashGuard = true
																	break
																}
															}
															if !hasSlashGuard {
																return fmt.Errorf("os: Getwd PWD hint %s returned without leading '/' guard", dirArgID.Name)
															}
														}
														allowedReturns[ret] = true
														shape2ReturnedDirVars[dirArgID.Name] = true
														usedSameFile = true
													}
												}
											}
										}
									}
								}
							}
						}

						// Loop parent openDirNolog(parent), Readdirnames, and fstatNolog(fd)/fd.Stat() seeds.
						if inLoop {
							if _, okOD := isIdentNamed(c.Fun, "openDirNolog"); okOD && len(c.Args) == 1 {
								if pID, okP := unwrapParens(c.Args[0]).(*ast.Ident); okP && parentLoopVars[pID.Name] {
									producesValidErr = true
									validErrName = l1.Name
									if idx+1 < len(stmts) {
										if errRet, okG := isCheckedErrGuardIf(stmts[idx+1], l1.Name); okG {
											allowedReturns[errRet] = true
											fdSeedAssigns[as] = true
											fdVarsInLoop[l0.Name] = true
											usedOpenDirNolog = true
										}
									}
								}
							}
							if sel, okS := unwrapParens(c.Fun).(*ast.SelectorExpr); okS && sel.Sel.Name == "Readdirnames" {
								if fdID, okFD := unwrapParens(sel.X).(*ast.Ident); okFD && fdVarsInLoop[fdID.Name] {
									producesValidErr = true
									validErrName = l1.Name
								}
							}
							var fdStatTarget string
							var isFstatCall, isFileStatCall bool
							if _, okFN := isIdentNamed(c.Fun, "fstatNolog"); okFN && len(c.Args) == 1 {
								if fdID, okFD := unwrapParens(c.Args[0]).(*ast.Ident); okFD && fdVarsInLoop[fdID.Name] {
									fdStatTarget = fdID.Name
									isFstatCall = true
								}
							} else if sel, okS := unwrapParens(c.Fun).(*ast.SelectorExpr); okS && sel.Sel.Name == "Stat" && len(c.Args) == 0 {
								if fdID, okFD := unwrapParens(sel.X).(*ast.Ident); okFD && fdVarsInLoop[fdID.Name] {
									fdStatTarget = fdID.Name
									isFileStatCall = true
								}
							}
							if fdStatTarget != "" {
								usedStatHelpers = true
								producesValidErr = true
								validErrName = l1.Name
								if isFstatCall {
									usedFstatNolog = true
								}
								if isFileStatCall {
									usedFileStatInGetwd = true
								}
								guardIdx := idx + 1
								if guardIdx < len(stmts) && isCloseCallOn(stmts[guardIdx], fdStatTarget) {
									guardIdx++
								}
								if guardIdx < len(stmts) {
									if errRet, okG := isCheckedErrGuardIf(stmts[guardIdx], l1.Name); okG {
										allowedReturns[errRet] = true
										pdSeedAssigns[as] = true
										pdVarsInLoop[l0.Name] = true
									}
								}
							}
						}
					}
				}
				for _, lhs := range as.Lhs {
					if id, okID := unwrapParens(lhs).(*ast.Ident); okID {
						delete(curValidErr, id.Name)
					}
				}
				if producesValidErr && validErrName != "" && validErrName != "_" {
					curValidErr[validErrName] = true
				}
			}

			switch x := st.(type) {
			case *ast.ReturnStmt:
				if len(x.Results) != 2 {
					return fmt.Errorf("os: Getwd return must have 2 explicit results")
				}
				if !allowedReturns[x] {
					if lit, okL := unwrapParens(x.Results[0]).(*ast.BasicLit); okL && lit.Kind == token.STRING {
						if lit.Value == `"/"` {
							_, okNil := isIdentNamed(x.Results[1], "nil")
							hasRootSameFile := false
							for _, enc := range enclosingIfs {
								if enc.Init == nil {
									if a0, a1, okSF := isSameFileCallPair(enc.Cond); okSF {
										if (rootVars[a0] && dotVars[a1]) || (rootVars[a1] && dotVars[a0]) {
											hasRootSameFile = true
											break
										}
									}
								}
							}
							if okNil && hasRootSameFile {
								allowedReturns[x] = true
								usedSameFile = true
								usedStatHelpers = true
							}
						} else if lit.Value == `""` && len(enclosingIfs) > 0 {
							if eID, okE := unwrapParens(x.Results[1]).(*ast.Ident); okE && eID.Name != "" && eID.Name != "_" && eID.Name != "nil" {
								for _, enc := range enclosingIfs {
									if validErrIfs[enc] == eID.Name && !stmtsMutateIdentBefore(enc.Body.List, x, eID.Name) {
										allowedReturns[x] = true
										break
									}
								}
							}
							if !allowedReturns[x] && isVerifiedConstGetwdErr(x.Results[1]) {
								for _, enc := range enclosingIfs {
									if (validErrIfs[enc] != "" && !stmtsMutateIdentBefore(enc.Body.List, x, validErrIfs[enc])) || isParentLenBoundCond(enc.Cond, parentLoopVars) {
										allowedReturns[x] = true
										break
									}
								}
							}
						}
					}
				}
			case *ast.IfStmt:
				if x.Init != nil {
					return fmt.Errorf("os: Getwd contains unexpected if init statement")
				}
				if checkedErr := condChecksNonZeroErr(x.Cond); checkedErr != "" && curValidErr[checkedErr] {
					validErrIfs[x] = checkedErr
				}
				nextIfs := append(slices.Clone(enclosingIfs), x)
				if err := verifyBlock(x.Body.List, nextIfs, inLoop, curPWD, curValidErr); err != nil {
					return err
				}
				if x.Else != nil {
					switch eb := x.Else.(type) {
					case *ast.BlockStmt:
						if err := verifyBlock(eb.List, enclosingIfs, inLoop, curPWD, curValidErr); err != nil {
							return err
						}
					case *ast.IfStmt:
						if err := verifyBlock([]ast.Stmt{eb}, enclosingIfs, inLoop, curPWD, curValidErr); err != nil {
							return err
						}
					default:
						return fmt.Errorf("os: Getwd unexpected else clause")
					}
				}
				mut, pwd := map[string]bool{}, map[string]bool{}
				collectCompoundStmtMutations(x, mut, pwd)
				for m := range mut {
					delete(curValidErr, m)
				}
				for p := range pwd {
					curPWD[p] = true
				}
			case *ast.ForStmt:
				sawLoopInGetwd = true
				if !inLoop && x.Cond == nil && topParentLoop == nil {
					topParentLoop = x
					topParentLoopIdx = idx
					initAs, okIA := x.Init.(*ast.AssignStmt)
					postAs, okPA := x.Post.(*ast.AssignStmt)
					if okIA && initAs.Tok == token.DEFINE && len(initAs.Lhs) == 1 && len(initAs.Rhs) == 1 && okPA && postAs.Tok == token.ASSIGN && len(postAs.Lhs) == 1 && len(postAs.Rhs) == 1 {
						if pID, okP := unwrapParens(initAs.Lhs[0]).(*ast.Ident); okP && pID.Name != "" && pID.Name != "_" {
							lit, okL := unwrapParens(initAs.Rhs[0]).(*ast.BasicLit)
							_, okPostLHS := isIdentNamed(postAs.Lhs[0], pID.Name)
							postBin, okPB := unwrapParens(postAs.Rhs[0]).(*ast.BinaryExpr)
							if okL && lit.Kind == token.STRING && lit.Value == `".."` && okPostLHS && okPB && postBin.Op == token.ADD {
								stepLit, okSL := unwrapParens(postBin.X).(*ast.BasicLit)
								_, okStepVar := isIdentNamed(postBin.Y, pID.Name)
								if okSL && stepLit.Kind == token.STRING && stepLit.Value == `"../"` && okStepVar {
									parentLoopVars[pID.Name] = true
									parentInitAssigns[initAs] = true
									parentStepAssigns[postAs] = true
								}
							}
						}
					}
				}
				if err := verifyBlock(x.Body.List, enclosingIfs, true, curPWD, curValidErr); err != nil {
					return err
				}
				mut, pwd := map[string]bool{}, map[string]bool{}
				collectCompoundStmtMutations(x, mut, pwd)
				for m := range mut {
					delete(curValidErr, m)
				}
				for p := range pwd {
					curPWD[p] = true
				}
			case *ast.RangeStmt:
				sawLoopInGetwd = true
				if err := verifyBlock(x.Body.List, enclosingIfs, true, curPWD, curValidErr); err != nil {
					return err
				}
				mut, pwd := map[string]bool{}, map[string]bool{}
				collectCompoundStmtMutations(x, mut, pwd)
				for m := range mut {
					delete(curValidErr, m)
				}
				for p := range pwd {
					curPWD[p] = true
				}
			case *ast.BlockStmt:
				if err := verifyBlock(x.List, enclosingIfs, inLoop, curPWD, curValidErr); err != nil {
					return err
				}
				mut, pwd := map[string]bool{}, map[string]bool{}
				collectCompoundStmtMutations(x, mut, pwd)
				for m := range mut {
					delete(curValidErr, m)
				}
				for p := range pwd {
					curPWD[p] = true
				}
			case *ast.AssignStmt, *ast.DeclStmt, *ast.ExprStmt, *ast.BranchStmt, *ast.EmptyStmt:
			default:
				return fmt.Errorf("os: Getwd contains unexpected statement %T", st)
			}
		}
		return nil
	}

	if err := verifyBlock(gwStmts, nil, false, map[string]bool{}, map[string]bool{}); err != nil {
		return err
	}

	// Verify Shape 5 if the trailing statement of Getwd is `return <dirVar>, nil`.
	shape5Verified := false
	shape5DirVar := ""
	if lastRet, okLR := stmtUnwrapLabel(gwStmts[len(gwStmts)-1]).(*ast.ReturnStmt); okLR && !allowedReturns[lastRet] {
		if len(lastRet.Results) == 2 {
			dirID, okD := unwrapParens(lastRet.Results[0]).(*ast.Ident)
			_, okNil := isIdentNamed(lastRet.Results[1], "nil")
			if okD && okNil && dirID.Name != "" && dirID.Name != "_" && topParentLoop != nil && topParentLoopIdx >= 1 {
				resetAs, okRA := stmtUnwrapLabel(gwStmts[topParentLoopIdx-1]).(*ast.AssignStmt)
				resetOK := false
				if okRA && (resetAs.Tok == token.ASSIGN || resetAs.Tok == token.DEFINE) && len(resetAs.Lhs) == 1 && len(resetAs.Rhs) == 1 {
					_, okLHS := isIdentNamed(resetAs.Lhs[0], dirID.Name)
					lit, okLit := unwrapParens(resetAs.Rhs[0]).(*ast.BasicLit)
					resetOK = okLHS && okLit && lit.Kind == token.STRING && lit.Value == `""`
				}
				afterUnmutated := !stmtsMutateIdentBefore(gwStmts[topParentLoopIdx+1:], lastRet, dirID.Name)
				if resetOK && afterUnmutated {
					// Verify outer loop break guards and all assignments to dirID inside topParentLoop.
					loopOK := len(dotVars) > 0 && len(rootVars) > 0
					sawClimbAssign := false
					var checkOuterLoop func(stmts []ast.Stmt, encIfs []*ast.IfStmt, nestedLoop bool, validNamesVars, lstatVars, rangeElemVars map[string]bool)
					checkOuterLoop = func(stmts []ast.Stmt, encIfs []*ast.IfStmt, nestedLoop bool, validNamesVars, lstatVars, rangeElemVars map[string]bool) {
						if !loopOK {
							return
						}
						curNames := maps.Clone(validNamesVars)
						curLstat := maps.Clone(lstatVars)
						for i, raw := range stmts {
							if _, isLbl := raw.(*ast.LabeledStmt); isLbl {
								clear(curNames)
								clear(curLstat)
							}
							s := stmtUnwrapLabel(raw)
							if ds, okDS := s.(*ast.DeclStmt); okDS {
								if gd, okGD := ds.Decl.(*ast.GenDecl); okGD {
									for _, spec := range gd.Specs {
										if vs, okVS := spec.(*ast.ValueSpec); okVS {
											for _, id := range vs.Names {
												delete(curNames, id.Name)
												delete(curLstat, id.Name)
												if rangeElemVars[id.Name] || id.Name == dirID.Name {
													loopOK = false
													return
												}
											}
										}
									}
								}
							}
							if as, okA := s.(*ast.AssignStmt); okA {
								for _, lhs := range as.Lhs {
									if id, okID := unwrapParens(lhs).(*ast.Ident); okID {
										delete(curNames, id.Name)
										delete(curLstat, id.Name)
										if rangeElemVars[id.Name] {
											loopOK = false
											return
										}
									}
								}
								// Track `names, err := fd.Readdirnames(...)` guarded by `if err != nil { ... return ... }`.
								if (as.Tok == token.DEFINE || as.Tok == token.ASSIGN) && len(as.Lhs) == 2 && len(as.Rhs) == 1 {
									nID, okN := unwrapParens(as.Lhs[0]).(*ast.Ident)
									eID, okE := unwrapParens(as.Lhs[1]).(*ast.Ident)
									rc, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
									if okN && okE && okC && !rc.Ellipsis.IsValid() && nID.Name != "" && nID.Name != "_" && nID.Name != eID.Name {
										if sel, okS := unwrapParens(rc.Fun).(*ast.SelectorExpr); okS && sel.Sel.Name == "Readdirnames" && eID.Name != "" && eID.Name != "_" && i+1 < len(stmts) {
											if fdID, okFD := unwrapParens(sel.X).(*ast.Ident); okFD && fdVarsInLoop[fdID.Name] {
												if gIf, okGI := stmts[i+1].(*ast.IfStmt); okGI && gIf.Init == nil && gIf.Else == nil && condChecksNonZeroErr(gIf.Cond) == eID.Name && len(gIf.Body.List) > 0 {
													if _, okLastRet := gIf.Body.List[len(gIf.Body.List)-1].(*ast.ReturnStmt); okLastRet {
														curNames[nID.Name] = true
													}
												}
											}
										}
										if _, okLS := isIdentNamed(rc.Fun, "lstatNolog"); okLS && len(rc.Args) == 1 {
											usedStatHelpers = true
											curLstat[nID.Name] = true
										}
									}
								}
								for idxLHS, lhs := range as.Lhs {
									if _, okT := isIdentNamed(lhs, dirID.Name); okT {
										if as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || idxLHS != 0 {
											loopOK = false
											return
										}
										// Must be `"/" + <rangeElem> + <dirVar>` inside `if SameFile(<lstatVar>, <dotVar>)`.
										addOuter, okAO := unwrapParens(as.Rhs[0]).(*ast.BinaryExpr)
										if !okAO || addOuter.Op != token.ADD {
											loopOK = false
											return
										}
										addInner, okAI := unwrapParens(addOuter.X).(*ast.BinaryExpr)
										_, okTail := isIdentNamed(addOuter.Y, dirID.Name)
										if !okAI || addInner.Op != token.ADD || !okTail {
											loopOK = false
											return
										}
										slashLit, okSL := unwrapParens(addInner.X).(*ast.BasicLit)
										elemID, okEL := unwrapParens(addInner.Y).(*ast.Ident)
										if !okSL || slashLit.Kind != token.STRING || slashLit.Value != `"/"` || !okEL || !rangeElemVars[elemID.Name] {
											loopOK = false
											return
										}
										guardedByLstatSameFile := false
										for _, enc := range encIfs {
											if enc.Init == nil {
												if a0, a1, okSF := isSameFileCallPair(enc.Cond); okSF {
													if (curLstat[a0] && dotVars[a1]) || (curLstat[a1] && dotVars[a0]) {
														guardedByLstatSameFile = true
														break
													}
												}
											}
										}
										if !guardedByLstatSameFile {
											loopOK = false
											return
										}
										sawClimbAssign = true
										usedSameFile = true
									}
								}
							}
							switch x := s.(type) {
							case *ast.BranchStmt:
								if x.Tok == token.BREAK && !nestedLoop {
									if x.Label != nil || len(encIfs) == 0 {
										loopOK = false
										return
									}
									innerEnc := encIfs[len(encIfs)-1]
									a0, a1, okSF := isSameFileCallPair(innerEnc.Cond)
									if !okSF || !((pdVarsInLoop[a0] && rootVars[a1]) || (pdVarsInLoop[a1] && rootVars[a0])) {
										loopOK = false
										return
									}
									usedSameFile = true
								}
							case *ast.IfStmt:
								if x.Init != nil {
									loopOK = false
									return
								}
								nextIfs := append(slices.Clone(encIfs), x)
								checkOuterLoop(x.Body.List, nextIfs, nestedLoop, curNames, curLstat, rangeElemVars)
								if x.Else != nil {
									if eb, okEB := x.Else.(*ast.BlockStmt); okEB {
										checkOuterLoop(eb.List, encIfs, nestedLoop, curNames, curLstat, rangeElemVars)
									} else if ei, okEI := x.Else.(*ast.IfStmt); okEI {
										checkOuterLoop([]ast.Stmt{ei}, encIfs, nestedLoop, curNames, curLstat, rangeElemVars)
									} else {
										loopOK = false
										return
									}
								}
								mut, pwd := map[string]bool{}, map[string]bool{}
								collectCompoundStmtMutations(x, mut, pwd)
								for m := range mut {
									delete(curNames, m)
									delete(curLstat, m)
								}
							case *ast.ForStmt:
								checkOuterLoop(x.Body.List, encIfs, true, curNames, curLstat, rangeElemVars)
								mut, pwd := map[string]bool{}, map[string]bool{}
								collectCompoundStmtMutations(x, mut, pwd)
								for m := range mut {
									delete(curNames, m)
									delete(curLstat, m)
								}
							case *ast.RangeStmt:
								if x.Key != nil {
									if kID, okK := unwrapParens(x.Key).(*ast.Ident); okK && (kID.Name == dirID.Name || rangeElemVars[kID.Name]) {
										loopOK = false
										return
									}
								}
								if x.Value != nil {
									if vID, okV := unwrapParens(x.Value).(*ast.Ident); okV && (vID.Name == dirID.Name || rangeElemVars[vID.Name]) {
										loopOK = false
										return
									}
								}
								nextElem := maps.Clone(rangeElemVars)
								if rX, okRX := unwrapParens(x.X).(*ast.Ident); okRX && curNames[rX.Name] && x.Value != nil {
									if vID, okV := unwrapParens(x.Value).(*ast.Ident); okV && vID.Name != "" && vID.Name != "_" {
										nextElem[vID.Name] = true
									}
								}
								checkOuterLoop(x.Body.List, encIfs, true, curNames, curLstat, nextElem)
								mut, pwd := map[string]bool{}, map[string]bool{}
								collectCompoundStmtMutations(x, mut, pwd)
								for m := range mut {
									delete(curNames, m)
									delete(curLstat, m)
								}
							case *ast.BlockStmt:
								checkOuterLoop(x.List, encIfs, nestedLoop, curNames, curLstat, rangeElemVars)
								mut, pwd := map[string]bool{}, map[string]bool{}
								collectCompoundStmtMutations(x, mut, pwd)
								for m := range mut {
									delete(curNames, m)
									delete(curLstat, m)
								}
							case *ast.AssignStmt, *ast.DeclStmt, *ast.ExprStmt, *ast.ReturnStmt, *ast.EmptyStmt:
							default:
								loopOK = false
								return
							}
						}
					}
					checkOuterLoop(topParentLoop.Body.List, nil, false, map[string]bool{}, map[string]bool{}, map[string]bool{})
					if loopOK && sawClimbAssign {
						allowedReturns[lastRet] = true
						shape5Verified = true
						shape5DirVar = dirID.Name
					}
				}
			}
		}
	}

	// Whole-body structural audit: enforce loop label bounds, ban defer/go/closures/address-taking,
	// ensure every syscall.Getwd reference is Shape 1, ensure every ReturnStmt is in allowedReturns,
	// and verify dot/root/Shape-2 variable assignment discipline.
	var walkErr error
	var walkStmt func(n ast.Node, loopLabels map[string]bool, insideParentLoop bool)
	walkStmt = func(n ast.Node, loopLabels map[string]bool, insideParentLoop bool) {
		if walkErr != nil || n == nil {
			return
		}
		switch x := n.(type) {
		case *ast.DeferStmt, *ast.GoStmt, *ast.FuncLit, *ast.SendStmt, *ast.IncDecStmt:
			walkErr = fmt.Errorf("os: Getwd contains forbidden defer/go/closure/send/incdec")
			return
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				walkErr = fmt.Errorf("os: Getwd contains forbidden address-taking expression")
				return
			}
		case *ast.LabeledStmt:
			if len(loopLabels) == 0 || !loopLabels[x.Label.Name] {
				walkErr = fmt.Errorf("os: Getwd contains label outside loop")
				return
			}
			walkStmt(x.Stmt, loopLabels, insideParentLoop)
			return
		case *ast.BranchStmt:
			switch x.Tok {
			case token.FALLTHROUGH:
				walkErr = fmt.Errorf("os: Getwd contains fallthrough")
				return
			case token.BREAK, token.CONTINUE:
				if x.Label != nil {
					walkErr = fmt.Errorf("os: Getwd contains labeled break/continue")
					return
				}
			case token.GOTO:
				if x.Label == nil || !loopLabels[x.Label.Name] {
					walkErr = fmt.Errorf("os: Getwd contains goto outside enclosing loop")
					return
				}
			}
			return
		case *ast.ForStmt:
			nextLabels := maps.Clone(loopLabels)
			if nextLabels == nil {
				nextLabels = map[string]bool{}
			}
			for _, st := range x.Body.List {
				if ls, okLS := st.(*ast.LabeledStmt); okLS && ls.Label != nil {
					nextLabels[ls.Label.Name] = true
				}
			}
			nextInParent := insideParentLoop || x == topParentLoop
			if x.Init != nil {
				walkStmt(x.Init, nextLabels, nextInParent)
			}
			if x.Cond != nil {
				walkStmt(x.Cond, nextLabels, nextInParent)
			}
			if x.Post != nil {
				walkStmt(x.Post, nextLabels, nextInParent)
			}
			for _, st := range x.Body.List {
				walkStmt(st, nextLabels, nextInParent)
			}
			return
		case *ast.RangeStmt:
			for _, expr := range []ast.Expr{x.Key, x.Value} {
				if expr == nil {
					continue
				}
				if rID, okID := unwrapParens(expr).(*ast.Ident); okID {
					if dotVars[rID.Name] || rootVars[rID.Name] || fdVarsInLoop[rID.Name] || pdVarsInLoop[rID.Name] || parentLoopVars[rID.Name] || shape2ReturnedDirVars[rID.Name] {
						walkErr = fmt.Errorf("os: Getwd tracked variable %s overwritten by range clause", rID.Name)
						return
					}
				}
			}
		case *ast.ValueSpec:
			for idx, id := range x.Names {
				if dotVars[id.Name] && len(x.Values) != 0 {
					walkErr = fmt.Errorf("os: Getwd dot variable %s initialized outside statNolog(\".\")", id.Name)
					return
				}
				if rootVars[id.Name] && len(x.Values) != 0 {
					walkErr = fmt.Errorf("os: Getwd root variable %s initialized outside statNolog(\"/\")", id.Name)
					return
				}
				if fdVarsInLoop[id.Name] && len(x.Values) != 0 {
					walkErr = fmt.Errorf("os: Getwd fd variable %s initialized outside openDirNolog", id.Name)
					return
				}
				if pdVarsInLoop[id.Name] && len(x.Values) != 0 {
					walkErr = fmt.Errorf("os: Getwd pd variable %s initialized outside verified fd stat", id.Name)
					return
				}
				if parentLoopVars[id.Name] {
					walkErr = fmt.Errorf("os: Getwd parent variable %s redeclared", id.Name)
					return
				}
				if shape2ReturnedDirVars[id.Name] && idx < len(x.Values) {
					walkErr = fmt.Errorf("os: Getwd hint variable %s has unexpected ValueSpec initializer", id.Name)
					return
				}
			}
		case *ast.AssignStmt:
			for idxLHS, lhs := range x.Lhs {
				lID, okID := unwrapParens(lhs).(*ast.Ident)
				if !okID {
					continue
				}
				if dotVars[lID.Name] && !dotSeedAssigns[x] {
					stepOK := insideParentLoop && x.Tok == token.ASSIGN && len(x.Lhs) == 1 && len(x.Rhs) == 1
					if stepOK {
						if rhsID, okR := unwrapParens(x.Rhs[0]).(*ast.Ident); !okR || !pdVarsInLoop[rhsID.Name] {
							stepOK = false
						}
					}
					if !stepOK {
						walkErr = fmt.Errorf("os: Getwd dot variable %s assigned from unverified source", lID.Name)
						return
					}
				}
				if rootVars[lID.Name] && !rootSeedAssigns[x] {
					walkErr = fmt.Errorf("os: Getwd root variable %s reassigned", lID.Name)
					return
				}
				if fdVarsInLoop[lID.Name] && !fdSeedAssigns[x] {
					walkErr = fmt.Errorf("os: Getwd fd variable %s reassigned", lID.Name)
					return
				}
				if pdVarsInLoop[lID.Name] && !pdSeedAssigns[x] {
					walkErr = fmt.Errorf("os: Getwd pd variable %s reassigned", lID.Name)
					return
				}
				if parentLoopVars[lID.Name] && !parentInitAssigns[x] && !parentStepAssigns[x] {
					walkErr = fmt.Errorf("os: Getwd parent variable %s reassigned", lID.Name)
					return
				}
				if shape2ReturnedDirVars[lID.Name] && !shape1Assigns[x] {
					if insideParentLoop && shape5Verified && lID.Name == shape5DirVar {
						// Verified by checkOuterLoop to be "/" + name + dir.
						continue
					}
					hintOK := !insideParentLoop && (x.Tok == token.ASSIGN || x.Tok == token.DEFINE) && len(x.Lhs) == 1 && len(x.Rhs) == 1 && idxLHS == 0
					if hintOK {
						rhs := unwrapParens(x.Rhs[0])
						if lit, okLit := rhs.(*ast.BasicLit); okLit && lit.Kind == token.STRING && lit.Value == `""` {
							// allowed reset
						} else if _, okCache := isSelectorBaseField(rhs, "getwdCache", "dir"); okCache {
							usedGetwdCache = true
						} else if c, okC := rhs.(*ast.CallExpr); okC && !c.Ellipsis.IsValid() && len(c.Args) == 1 {
							_, okGE := isIdentNamed(c.Fun, "Getenv")
							aLit, okAL := unwrapParens(c.Args[0]).(*ast.BasicLit)
							hintOK = okGE && okAL && aLit.Kind == token.STRING && aLit.Value == `"PWD"`
						} else {
							hintOK = false
						}
					}
					if !hintOK {
						walkErr = fmt.Errorf("os: Getwd hint variable %s assigned from unverified source", lID.Name)
						return
					}
				}
			}
		case *ast.Ident:
			if x.Name == "testlog" {
				walkErr = fmt.Errorf("os: Getwd references testlog")
				return
			}
		case *ast.SelectorExpr:
			if _, okSG := isSelectorBaseField(x, "syscall", "Getwd"); okSG && !allowedSyscallGetwdSels[x] {
				walkErr = fmt.Errorf("os: Getwd references syscall.Getwd outside verified return pair")
				return
			}
			if _, okSys := isIdentNamed(x.X, "syscall"); okSys && (x.Sel.Name == "Chdir" || x.Sel.Name == "Fchdir") {
				walkErr = fmt.Errorf("os: Getwd calls syscall.%s", x.Sel.Name)
				return
			}
		case *ast.CallExpr:
			if cID, okID := unwrapParens(x.Fun).(*ast.Ident); okID {
				switch cID.Name {
				case "recover", "Chdir", "Fchdir":
					walkErr = fmt.Errorf("os: Getwd calls forbidden %s", cID.Name)
					return
				case "ignoringEINTR2":
					usedIgnoringEINTR2 = true
				case "NewSyscallError":
					usedNewSyscallError = true
				case "SameFile":
					usedSameFile = true
				case "openDirNolog":
					usedOpenDirNolog = true
				case "statNolog", "lstatNolog":
					usedStatHelpers = true
				case "fstatNolog":
					usedStatHelpers = true
					usedFstatNolog = true
				}
			} else if sel, okS := unwrapParens(x.Fun).(*ast.SelectorExpr); okS && sel.Sel.Name == "Stat" && len(x.Args) == 0 {
				usedStatHelpers = true
				usedFileStatInGetwd = true
			}
		case *ast.ReturnStmt:
			if !allowedReturns[x] {
				walkErr = fmt.Errorf("os: Getwd contains unverified return statement")
				return
			}
		}
		ast.Inspect(n, func(ch ast.Node) bool {
			if ch == n {
				return true
			}
			walkStmt(ch, loopLabels, insideParentLoop)
			return false
		})
	}
	for _, st := range gwStmts {
		walkStmt(st, nil, false)
		if walkErr != nil {
			return walkErr
		}
	}
	if !sawSyscallGetwd {
		return fmt.Errorf("os: Getwd does not invoke syscall.Getwd")
	}

	if usedGetwdCache {
		if pkgDeclCounts["getwdCache"] != 1 {
			return fmt.Errorf("os: invalid getwdCache declaration count")
		}
		var cacheDeclIdent *ast.Ident
		for _, f := range files {
			for _, decl := range f.Decls {
				gd, okGD := decl.(*ast.GenDecl)
				if !okGD || gd.Tok != token.VAR {
					continue
				}
				for _, spec := range gd.Specs {
					vs, okVS := spec.(*ast.ValueSpec)
					if !okVS || len(vs.Names) != 1 || vs.Names[0].Name != "getwdCache" {
						continue
					}
					if len(vs.Values) != 0 {
						return fmt.Errorf("os: getwdCache must be zero-initialized")
					}
					if _, okST := unwrapParens(vs.Type).(*ast.StructType); !okST {
						return fmt.Errorf("os: getwdCache must be an unexported anonymous struct")
					}
					cacheDeclIdent = vs.Names[0]
				}
			}
		}
		if cacheDeclIdent == nil {
			return fmt.Errorf("os: missing getwdCache var declaration")
		}
		postLoopAssigns := map[*ast.AssignStmt]bool{}
		if shape5Verified && topParentLoopIdx >= 0 && topParentLoopIdx+1 < len(gwStmts) {
			for _, st := range gwStmts[topParentLoopIdx+1:] {
				ast.Inspect(st, func(n ast.Node) bool {
					if as, okA := n.(*ast.AssignStmt); okA {
						postLoopAssigns[as] = true
					}
					return true
				})
			}
		}
		fileHasUnaliasedImport := func(f *ast.File, want string) bool {
			if f == nil {
				return false
			}
			for _, imp := range f.Imports {
				if imp.Name != nil {
					continue
				}
				if p, err := strconv.Unquote(imp.Path.Value); err == nil && p == want {
					return true
				}
			}
			return false
		}
		chdirFn := allTopFuncs["Chdir"]
		chdirParam0 := ""
		chdirAbsIfs := map[*ast.IfStmt]bool{}
		if chdirFn != nil && chdirFn.Body != nil && chdirFn.Type != nil && fileHasUnaliasedImport(funcFile[chdirFn], "internal/filepathlite") && !funcShadowsAnyIdent(chdirFn, map[string]bool{"filepathlite": true, "getwdCache": true}) {
			if pNames := paramNamesFlat(chdirFn.Type.Params); len(pNames) == 1 && pNames[0] != "" && pNames[0] != "_" && !stmtsMutateIdentBefore(chdirFn.Body.List, nil, pNames[0]) {
				chdirParam0 = pNames[0]
				absAssignCounts := map[string]int{}
				absVerifiedVars := map[string]bool{}
				ast.Inspect(chdirFn.Body, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.AssignStmt:
						for i, lhs := range x.Lhs {
							if id, okID := unwrapParens(lhs).(*ast.Ident); okID && id.Name != "" && id.Name != "_" {
								absAssignCounts[id.Name]++
								if len(x.Lhs) == 1 && len(x.Rhs) == 1 && i == 0 && (x.Tok == token.DEFINE || x.Tok == token.ASSIGN) {
									if c, okC := unwrapParens(x.Rhs[0]).(*ast.CallExpr); okC && !c.Ellipsis.IsValid() && len(c.Args) == 1 {
										_, okFP := isSelectorBaseField(c.Fun, "filepathlite", "IsAbs")
										_, okP0 := isIdentNamed(c.Args[0], chdirParam0)
										if okFP && okP0 {
											absVerifiedVars[id.Name] = true
										}
									}
								}
							}
						}
					case *ast.ValueSpec:
						for _, id := range x.Names {
							if id.Name != "" && id.Name != "_" {
								absAssignCounts[id.Name]++
							}
						}
					}
					return true
				})
				ast.Inspect(chdirFn.Body, func(n ast.Node) bool {
					if ifs, okI := n.(*ast.IfStmt); okI && ifs.Init == nil {
						if cID, okID := unwrapParens(ifs.Cond).(*ast.Ident); okID && absVerifiedVars[cID.Name] && absAssignCounts[cID.Name] == 1 {
							chdirAbsIfs[ifs] = true
						}
					}
					return true
				})
			}
		}
		for _, f := range files {
			for _, decl := range f.Decls {
				switch d := decl.(type) {
				case *ast.GenDecl:
					var gdErr error
					ast.Inspect(d, func(n ast.Node) bool {
						if gdErr != nil || n == nil {
							return false
						}
						if id, okID := n.(*ast.Ident); okID && id.Name == "getwdCache" && id != cacheDeclIdent {
							gdErr = fmt.Errorf("os: unexpected package-level reference to getwdCache")
							return false
						}
						return true
					})
					if gdErr != nil {
						return gdErr
					}
				case *ast.FuncDecl:
					if d.Body == nil {
						continue
					}
					mentionsCache := false
					ast.Inspect(d.Body, func(n ast.Node) bool {
						if id, okID := n.(*ast.Ident); okID && id.Name == "getwdCache" {
							mentionsCache = true
							return false
						}
						return true
					})
					if !mentionsCache {
						continue
					}
					if funcShadowsAnyIdent(d, map[string]bool{"getwdCache": true}) {
						return fmt.Errorf("os: function %s shadows getwdCache", d.Name.Name)
					}
					validBaseIdents := map[*ast.Ident]bool{}
					ast.Inspect(d.Body, func(n ast.Node) bool {
						if sel, okS := n.(*ast.SelectorExpr); okS {
							if bID, okB := unwrapParens(sel.X).(*ast.Ident); okB && bID.Name == "getwdCache" && (sel.Sel.Name == "Lock" || sel.Sel.Name == "Unlock" || sel.Sel.Name == "dir") {
								validBaseIdents[bID] = true
							}
						}
						return true
					})
					var cacheErr error
					var auditCache func(n ast.Node, inAbsBody bool)
					auditCache = func(n ast.Node, inAbsBody bool) {
						if cacheErr != nil || n == nil {
							return
						}
						if ifs, okI := n.(*ast.IfStmt); okI {
							if skipInactiveHookIf(ifs, d) {
								return
							}
							if ifs.Init != nil {
								auditCache(ifs.Init, inAbsBody)
							}
							auditCache(ifs.Cond, inAbsBody)
							auditCache(ifs.Body, inAbsBody || chdirAbsIfs[ifs])
							if ifs.Else != nil {
								auditCache(ifs.Else, inAbsBody)
							}
							return
						}
						switch x := n.(type) {
						case *ast.Ident:
							if x.Name == "getwdCache" && !validBaseIdents[x] {
								cacheErr = fmt.Errorf("os: unsupported getwdCache reference in %s", d.Name.Name)
								return
							}
						case *ast.UnaryExpr:
							if x.Op == token.AND {
								if _, okCD := isSelectorBaseField(x.X, "getwdCache", "dir"); okCD {
									cacheErr = fmt.Errorf("os: address taken of getwdCache.dir in %s", d.Name.Name)
									return
								}
							}
						case *ast.IncDecStmt:
							if _, okCD := isSelectorBaseField(x.X, "getwdCache", "dir"); okCD {
								cacheErr = fmt.Errorf("os: inc/dec on getwdCache.dir in %s", d.Name.Name)
								return
							}
						case *ast.RangeStmt:
							for _, expr := range []ast.Expr{x.Key, x.Value} {
								if expr != nil {
									if _, okCD := isSelectorBaseField(expr, "getwdCache", "dir"); okCD {
										cacheErr = fmt.Errorf("os: range write to getwdCache.dir in %s", d.Name.Name)
										return
									}
								}
							}
						case *ast.AssignStmt:
							for idxLHS, lhs := range x.Lhs {
								if _, okCD := isSelectorBaseField(lhs, "getwdCache", "dir"); okCD {
									writeOK := false
									if x.Tok == token.ASSIGN {
										if len(x.Lhs) == 1 && len(x.Rhs) == 1 {
											rhs := unwrapParens(x.Rhs[0])
											if lit, okL := rhs.(*ast.BasicLit); okL && lit.Kind == token.STRING && lit.Value == `""` {
												writeOK = true
											} else if d == gwFn && shape5Verified && postLoopAssigns[x] {
												_, writeOK = isIdentNamed(rhs, shape5DirVar)
											} else if d == chdirFn && inAbsBody && chdirParam0 != "" {
												_, writeOK = isIdentNamed(rhs, chdirParam0)
											}
										} else if len(x.Lhs) == 2 && len(x.Rhs) == 1 && idxLHS == 0 && fileImportsSyscall[f] && !funcShadowsAnyIdent(d, map[string]bool{"syscall": true}) {
											_, okBlank := isIdentNamed(x.Lhs[1], "_")
											if c, okC := unwrapParens(x.Rhs[0]).(*ast.CallExpr); okBlank && okC && !c.Ellipsis.IsValid() && len(c.Args) == 0 {
												_, writeOK = isSelectorBaseField(c.Fun, "syscall", "Getwd")
											}
										}
									}
									if !writeOK {
										cacheErr = fmt.Errorf("os: unverified write to getwdCache.dir in %s", d.Name.Name)
										return
									}
								}
							}
						}
						ast.Inspect(n, func(ch ast.Node) bool {
							if ch == n {
								return true
							}
							auditCache(ch, inAbsBody)
							return false
						})
					}
					auditCache(d.Body, false)
					if cacheErr != nil {
						return cacheErr
					}
				}
			}
		}
	}

	if usedIgnoringEINTR2 {
		ig2 := allTopFuncs["ignoringEINTR2"]
		if ig2 == nil || ig2.Body == nil || ig2.Type == nil || (ig2.Type.TypeParams != nil && ig2.Type.TypeParams.NumFields() > 1) || !funcHasUnnamedResults(ig2.Type, 2) || pkgDeclCounts["ignoringEINTR2"] != 1 || osAnyLinknameLocals["ignoringEINTR2"] || funcShadowsAnyIdent(ig2, osReserved) || bodyHasControlFlowOrRecoverBypass(ig2.Body) || len(ig2.Body.List) != 1 {
			return fmt.Errorf("os: invalid ignoringEINTR2 helper")
		}
		igParams := paramNamesFlat(ig2.Type.Params)
		if len(igParams) != 1 || igParams[0] == "" || igParams[0] == "_" {
			return fmt.Errorf("os: ignoringEINTR2 invalid parameters")
		}
		if ret, okRet := ig2.Body.List[0].(*ast.ReturnStmt); okRet && len(ret.Results) == 1 {
			c, okC := unwrapParens(ret.Results[0]).(*ast.CallExpr)
			if !okC || c.Ellipsis.IsValid() || len(c.Args) != 0 {
				return fmt.Errorf("os: ignoringEINTR2 invalid fn() return")
			}
			if _, okFn := isIdentNamed(c.Fun, igParams[0]); !okFn {
				return fmt.Errorf("os: ignoringEINTR2 does not call %s()", igParams[0])
			}
		} else {
			fs, okFor := ig2.Body.List[0].(*ast.ForStmt)
			if !okFor || !fileImportsSyscall[funcFile[ig2]] || fs.Init != nil || fs.Cond != nil || fs.Post != nil || len(fs.Body.List) != 2 {
				return fmt.Errorf("os: ignoringEINTR2 unexpected body")
			}
			as, okA := fs.Body.List[0].(*ast.AssignStmt)
			if !okA || as.Tok != token.DEFINE || len(as.Lhs) != 2 || len(as.Rhs) != 1 {
				return fmt.Errorf("os: ignoringEINTR2 missing fn() call")
			}
			vID, okV := unwrapParens(as.Lhs[0]).(*ast.Ident)
			errID, okE := unwrapParens(as.Lhs[1]).(*ast.Ident)
			if !okV || !okE || vID.Name == "" || vID.Name == "_" || errID.Name == "" || errID.Name == "_" || vID.Name == errID.Name {
				return fmt.Errorf("os: ignoringEINTR2 invalid result bindings")
			}
			c, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
			if !okC || c.Ellipsis.IsValid() || len(c.Args) != 0 {
				return fmt.Errorf("os: ignoringEINTR2 invalid fn() call")
			}
			if _, okFn := isIdentNamed(c.Fun, igParams[0]); !okFn {
				return fmt.Errorf("os: ignoringEINTR2 does not call %s()", igParams[0])
			}
			ifs, okI := fs.Body.List[1].(*ast.IfStmt)
			if !okI || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
				return fmt.Errorf("os: ignoringEINTR2 unexpected loop guard")
			}
			condBin, okCB := unwrapParens(ifs.Cond).(*ast.BinaryExpr)
			if !okCB || condBin.Op != token.NEQ {
				return fmt.Errorf("os: ignoringEINTR2 loop guard is not != syscall.EINTR")
			}
			_, okEL := isIdentNamed(condBin.X, errID.Name)
			_, okSysR := isSelectorBaseField(condBin.Y, "syscall", "EINTR")
			_, okSysL := isSelectorBaseField(condBin.X, "syscall", "EINTR")
			_, okER := isIdentNamed(condBin.Y, errID.Name)
			if !((okEL && okSysR) || (okSysL && okER)) {
				return fmt.Errorf("os: ignoringEINTR2 loop guard does not check %s != syscall.EINTR", errID.Name)
			}
			ret2, okR2 := ifs.Body.List[0].(*ast.ReturnStmt)
			if !okR2 || len(ret2.Results) != 2 {
				return fmt.Errorf("os: ignoringEINTR2 unexpected return")
			}
			_, okRV := isIdentNamed(ret2.Results[0], vID.Name)
			_, okRE := isIdentNamed(ret2.Results[1], errID.Name)
			if !okRV || !okRE {
				return fmt.Errorf("os: ignoringEINTR2 does not return (%s, %s)", vID.Name, errID.Name)
			}
		}
	}
	if usedNewSyscallError {
		nse := allTopFuncs["NewSyscallError"]
		if nse == nil || nse.Body == nil || nse.Type == nil || nse.Type.TypeParams != nil || !funcHasUnnamedResults(nse.Type, 1) || pkgDeclCounts["NewSyscallError"] != 1 || osAnyLinknameLocals["NewSyscallError"] || nonAliasStructSpecs["SyscallError"] == nil || pkgDeclCounts["SyscallError"] != 1 || funcShadowsAnyIdent(nse, map[string]bool{"nil": true, "error": true, "SyscallError": true}) || bodyHasControlFlowOrRecoverBypass(nse.Body) || len(nse.Body.List) != 2 {
			return fmt.Errorf("os: invalid NewSyscallError helper")
		}
		nseParams := paramNamesFlat(nse.Type.Params)
		if len(nseParams) != 2 || nseParams[0] == "" || nseParams[0] == "_" || nseParams[1] == "" || nseParams[1] == "_" || nseParams[0] == nseParams[1] || bodyMutatesOrTakesAddrOfAny(nse.Body, map[string]bool{nseParams[1]: true}) {
			return fmt.Errorf("os: NewSyscallError invalid parameters")
		}
		ifs, okI := nse.Body.List[0].(*ast.IfStmt)
		ret1, okR1 := nse.Body.List[1].(*ast.ReturnStmt)
		if !okI || ifs.Init != nil || ifs.Else != nil || !condChecksEqErr(ifs.Cond, nseParams[1]) || len(ifs.Body.List) != 1 || !okR1 || len(ret1.Results) != 1 {
			return fmt.Errorf("os: NewSyscallError unexpected body")
		}
		ret0, okR0 := ifs.Body.List[0].(*ast.ReturnStmt)
		if !okR0 || len(ret0.Results) != 1 {
			return fmt.Errorf("os: NewSyscallError nil branch does not return single value")
		}
		if _, okNil := isIdentNamed(ret0.Results[0], "nil"); !okNil {
			return fmt.Errorf("os: NewSyscallError nil branch does not return nil")
		}
		u, okU := unwrapParens(ret1.Results[0]).(*ast.UnaryExpr)
		cl, tName := compositeWriterLit(ret1.Results[0])
		if !okU || u.Op != token.AND || cl == nil || tName != "SyscallError" {
			return fmt.Errorf("os: NewSyscallError does not return &SyscallError")
		}
		bindsErrField := false
		if len(cl.Elts) == 2 {
			_, kv0 := cl.Elts[0].(*ast.KeyValueExpr)
			_, kv1 := cl.Elts[1].(*ast.KeyValueExpr)
			if !kv0 && !kv1 {
				_, bindsErrField = isIdentNamed(cl.Elts[1], nseParams[1])
			}
		}
		if !bindsErrField {
			for _, elt := range cl.Elts {
				kv, okKV := elt.(*ast.KeyValueExpr)
				if !okKV {
					bindsErrField = false
					break
				}
				if kID, okK := kv.Key.(*ast.Ident); okK && kID.Name == "Err" {
					_, bindsErrField = isIdentNamed(kv.Value, nseParams[1])
				}
			}
		}
		if !bindsErrField {
			return fmt.Errorf("os: NewSyscallError does not bind error parameter in SyscallError")
		}
	}
	if usedOpenDirNolog {
		odFn := allTopFuncs["openDirNolog"]
		if odFn == nil || odFn.Body == nil || odFn.Type == nil || odFn.Type.TypeParams != nil || pkgDeclCounts["openDirNolog"] != 1 || osAnyLinknameLocals["openDirNolog"] || funcShadowsAnyIdent(odFn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(odFn.Body) {
			return fmt.Errorf("os: invalid openDirNolog helper")
		}
		odParams := paramNamesFlat(odFn.Type.Params)
		if len(odParams) != 1 || odParams[0] == "" || odParams[0] == "_" || odFn.Type.Results == nil || odFn.Type.Results.NumFields() != 2 || !funcReturnsErrorLast(odFn.Type) {
			return fmt.Errorf("os: openDirNolog invalid signature")
		}
		if starF, okS := unwrapParens(odFn.Type.Results.List[0].Type).(*ast.StarExpr); !okS {
			return fmt.Errorf("os: openDirNolog first result is not *File")
		} else if _, okF := isIdentNamed(starF.X, "File"); !okF {
			return fmt.Errorf("os: openDirNolog first result is not *File")
		}
		odPos := 0
		for odPos < len(odFn.Body.List) && skipInactiveHookIf(odFn.Body.List[odPos], odFn) {
			odPos++
		}
		if odPos >= len(odFn.Body.List) {
			return fmt.Errorf("os: openDirNolog empty body")
		}
		var odErr error
		for _, st := range odFn.Body.List[odPos:] {
			ast.Inspect(st, func(n ast.Node) bool {
				if odErr != nil || n == nil {
					return false
				}
				if ifs, okI := n.(*ast.IfStmt); okI && skipInactiveHookIf(ifs, odFn) {
					return false
				}
				switch x := n.(type) {
				case *ast.Ident:
					if x.Name == "testlog" {
						odErr = fmt.Errorf("os: openDirNolog references testlog")
						return false
					}
				case *ast.SelectorExpr:
					if _, okSys := isIdentNamed(x.X, "syscall"); okSys {
						switch x.Sel.Name {
						case "Chdir", "Fchdir", "Unlink", "Rmdir", "Rename":
							odErr = fmt.Errorf("os: openDirNolog calls syscall.%s", x.Sel.Name)
							return false
						}
					}
				case *ast.CallExpr:
					if cID, okID := unwrapParens(x.Fun).(*ast.Ident); okID {
						if osAnyLinknameLocals[cID.Name] {
							odErr = fmt.Errorf("os: openDirNolog calls linknamed %s", cID.Name)
							return false
						}
						switch cID.Name {
						case "Open", "OpenFile", "Create", "Stat", "Lstat", "Chdir", "Fchdir", "Remove", "Rename", "Truncate", "openDir":
							odErr = fmt.Errorf("os: openDirNolog calls forbidden %s", cID.Name)
							return false
						case "fstatNolog":
							usedStatHelpers = true
							usedFstatNolog = true
						case "statNolog", "lstatNolog":
							usedStatHelpers = true
						}
					} else if sel, okS := unwrapParens(x.Fun).(*ast.SelectorExpr); okS && sel.Sel.Name == "Stat" && len(x.Args) == 0 {
						usedStatHelpers = true
						usedFileStatInGetwd = true
					}
				}
				return true
			})
			if odErr != nil {
				return odErr
			}
		}
	}
	var disjointAltStruct string
	if usedSameFile {
		var err error
		disjointAltStruct, err = verifyOSSameFile(allTopFuncs, nonAliasStructSpecs, pkgDeclCounts, osReserved, osNoFileReserved, osAnyLinknameLocals, osInactive, skipInactiveHookIf)
		if err != nil {
			return err
		}
	}
	if usedStatHelpers || usedSameFile {
		if err := verifyOSNologStatHelpers(allTopFuncs, allFileMethods, allRawFileMethods, allFileStatMethods, pkgDeclCounts, fileMethodCounts, rawFileMethodCounts, fileStatMethodCounts, funcFile, fileImportsSyscall, osInactive, osNoFileReserved, osAnyLinknameLocals, disjointAltStruct, usedSameFile, usedFstatNolog, usedFileStatInGetwd, skipInactiveHookIf); err != nil {
			return err
		}
	}
	return nil
}

func verifyOSSameFile(
	allTopFuncs map[string]*ast.FuncDecl,
	nonAliasStructSpecs map[string]*ast.TypeSpec,
	pkgDeclCounts map[string]int,
	osReserved, osNoFileReserved, osAnyLinknameLocals map[string]bool,
	osInactive *osInactiveState,
	skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool,
) (string, error) {
	sf := allTopFuncs["SameFile"]
	if sf == nil || sf.Body == nil || sf.Type == nil || sf.Type.TypeParams != nil || !funcHasUnnamedResults(sf.Type, 1) || pkgDeclCounts["SameFile"] != 1 || osAnyLinknameLocals["SameFile"] || funcShadowsAnyIdent(sf, osReserved) || bodyHasControlFlowOrRecoverBypass(sf.Body) {
		return "", fmt.Errorf("os: invalid SameFile helper")
	}
	if _, okBool := isIdentNamed(sf.Type.Results.List[0].Type, "bool"); !okBool {
		return "", fmt.Errorf("os: SameFile does not return bool")
	}
	sfParams := paramNamesFlat(sf.Type.Params)
	if len(sfParams) != 2 || sfParams[0] == "" || sfParams[0] == "_" || sfParams[1] == "" || sfParams[1] == "_" || sfParams[0] == sfParams[1] || bodyMutatesOrTakesAddrOfAny(sf.Body, map[string]bool{sfParams[0]: true, sfParams[1]: true}) {
		return "", fmt.Errorf("os: SameFile invalid parameters")
	}
	if nonAliasStructSpecs["fileStat"] == nil || pkgDeclCounts["fileStat"] != 1 {
		return "", fmt.Errorf("os: missing unique fileStat struct definition")
	}

	matchPtrStructTypeAssert := func(st ast.Stmt, wantParam string) (string, string, string, bool) {
		as, okA := st.(*ast.AssignStmt)
		if !okA || as.Tok != token.DEFINE || len(as.Lhs) != 2 || len(as.Rhs) != 1 {
			return "", "", "", false
		}
		vID, okV := unwrapParens(as.Lhs[0]).(*ast.Ident)
		okID, okO := unwrapParens(as.Lhs[1]).(*ast.Ident)
		ta, okTA := unwrapParens(as.Rhs[0]).(*ast.TypeAssertExpr)
		if !okV || !okO || !okTA || ta.Type == nil || vID.Name == "" || vID.Name == "_" || okID.Name == "" || okID.Name == "_" || vID.Name == okID.Name {
			return "", "", "", false
		}
		if _, okX := isIdentNamed(ta.X, wantParam); !okX {
			return "", "", "", false
		}
		star, okS := unwrapParens(ta.Type).(*ast.StarExpr)
		if !okS {
			return "", "", "", false
		}
		tID, okT := unwrapParens(star.X).(*ast.Ident)
		if !okT || tID.Name == "" {
			return "", "", "", false
		}
		return vID.Name, okID.Name, tID.Name, true
	}

	pos := 0
	for pos < len(sf.Body.List) && skipInactiveHookIf(sf.Body.List[pos], sf) {
		pos++
	}

	var disjointAltStruct string
	if pos < len(sf.Body.List) {
		var candInner *ast.IfStmt
		if outerIf, okOut := sf.Body.List[pos].(*ast.IfStmt); okOut && outerIf.Else == nil {
			if outerIf.Init != nil {
				candInner = outerIf
			} else if cID, okC := unwrapParens(outerIf.Cond).(*ast.Ident); okC && (cID.Name == "true" || (osInactive != nil && osInactive.trueConsts[cID.Name])) && !funcShadowsAnyIdent(sf, map[string]bool{cID.Name: true}) && len(outerIf.Body.List) == 1 {
				if inIf, okIn := outerIf.Body.List[0].(*ast.IfStmt); okIn && inIf.Else == nil {
					candInner = inIf
				}
			}
		}
		if candInner != nil && candInner.Init != nil && len(candInner.Body.List) == 1 {
			initAs, okIA := candInner.Init.(*ast.AssignStmt)
			retSt, okRS := candInner.Body.List[0].(*ast.ReturnStmt)
			if okIA && initAs.Tok == token.DEFINE && len(initAs.Lhs) == 2 && len(initAs.Rhs) == 1 && okRS && len(retSt.Results) == 1 {
				sID, okS := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
				hID, okH := unwrapParens(initAs.Lhs[1]).(*ast.Ident)
				hc, okHC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
				if okS && okH && okHC && !hc.Ellipsis.IsValid() && len(hc.Args) == 2 && sID.Name != "" && sID.Name != "_" && hID.Name != "" && hID.Name != "_" && sID.Name != hID.Name {
					_, okCond := isIdentNamed(candInner.Cond, hID.Name)
					_, okRet := isIdentNamed(retSt.Results[0], sID.Name)
					_, okA0 := isIdentNamed(hc.Args[0], sfParams[0])
					_, okA1 := isIdentNamed(hc.Args[1], sfParams[1])
					calleeID, okCallee := unwrapParens(hc.Fun).(*ast.Ident)
					if okCond && okRet && okA0 && okA1 && okCallee && !ast.IsExported(calleeID.Name) && pkgDeclCounts[calleeID.Name] == 1 && !osAnyLinknameLocals[calleeID.Name] && !funcShadowsAnyIdent(sf, map[string]bool{calleeID.Name: true}) {
						hFn := allTopFuncs[calleeID.Name]
						if hFn != nil && hFn.Body != nil && hFn.Type != nil && hFn.Type.TypeParams == nil && hFn.Type.Results != nil && hFn.Type.Results.NumFields() == 2 && !funcShadowsAnyIdent(hFn, map[string]bool{"false": true, "bool": true}) && !bodyHasControlFlowOrRecoverBypass(hFn.Body) {
							resAllBool := true
							hResNames := map[string]bool{}
							for _, fld := range hFn.Type.Results.List {
								if _, okB := isIdentNamed(fld.Type, "bool"); !okB {
									resAllBool = false
									break
								}
								for _, id := range fld.Names {
									hResNames[id.Name] = true
								}
							}
							qParams := paramNamesFlat(hFn.Type.Params)
							if resAllBool && len(qParams) == 2 && qParams[0] != "" && qParams[0] != "_" && qParams[1] != "" && qParams[1] != "_" && qParams[0] != qParams[1] && !bodyMutatesOrTakesAddrOfAny(hFn.Body, map[string]bool{qParams[0]: true, qParams[1]: true}) {
								hPos := 0
								for hPos < len(hFn.Body.List) && skipInactiveHookIf(hFn.Body.List[hPos], hFn) {
									hPos++
								}
								if hPos+3 <= len(hFn.Body.List) {
									d1, ok1, st1, m1 := matchPtrStructTypeAssert(hFn.Body.List[hPos], qParams[0])
									d2, ok2, st2, m2 := matchPtrStructTypeAssert(hFn.Body.List[hPos+1], qParams[1])
									gIf, okGI := hFn.Body.List[hPos+2].(*ast.IfStmt)
									distinctLocals := d1 != d2 && d1 != ok2 && ok1 != d2 && ok1 != ok2 && !hResNames[d1] && !hResNames[ok1] && !hResNames[d2] && !hResNames[ok2] && d1 != qParams[0] && d1 != qParams[1] && ok1 != qParams[0] && ok1 != qParams[1] && d2 != qParams[0] && d2 != qParams[1] && ok2 != qParams[0] && ok2 != qParams[1]
									if m1 && m2 && distinctLocals && st1 == st2 && !ast.IsExported(st1) && st1 != "fileStat" && nonAliasStructSpecs[st1] != nil && pkgDeclCounts[st1] == 1 && okGI && gIf.Init == nil && gIf.Else == nil && len(gIf.Body.List) == 1 {
										binAnd, okBA := unwrapParens(gIf.Cond).(*ast.BinaryExpr)
										gRet, okGR := gIf.Body.List[0].(*ast.ReturnStmt)
										if okBA && binAnd.Op == token.LAND && okGR && len(gRet.Results) == 2 {
											uL, okUL := unwrapParens(binAnd.X).(*ast.UnaryExpr)
											uR, okUR := unwrapParens(binAnd.Y).(*ast.UnaryExpr)
											_, okF0 := isIdentNamed(gRet.Results[0], "false")
											_, okF1 := isIdentNamed(gRet.Results[1], "false")
											if okUL && okUR && uL.Op == token.NOT && uR.Op == token.NOT && okF0 && okF1 {
												_, l1 := isIdentNamed(uL.X, ok1)
												_, r2 := isIdentNamed(uR.X, ok2)
												_, l2 := isIdentNamed(uL.X, ok2)
												_, r1 := isIdentNamed(uR.X, ok1)
												if (l1 && r2) || (l2 && r1) {
													disjointAltStruct = st1
													pos++
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	rem := sf.Body.List[pos:]
	if len(rem) != 4 {
		return "", fmt.Errorf("os: SameFile unexpected statement count %d", len(rem))
	}
	fs1, ok1, st1, m1 := matchPtrStructTypeAssert(rem[0], sfParams[0])
	fs2, ok2, st2, m2 := matchPtrStructTypeAssert(rem[1], sfParams[1])
	if !m1 || !m2 || st1 != "fileStat" || st2 != "fileStat" || fs1 == fs2 || fs1 == ok2 || ok1 == fs2 || ok1 == ok2 {
		return "", fmt.Errorf("os: SameFile missing (*fileStat) type assertions")
	}
	gIf, okGI := rem[2].(*ast.IfStmt)
	if !okGI || gIf.Init != nil || gIf.Else != nil || len(gIf.Body.List) != 1 {
		return "", fmt.Errorf("os: SameFile missing (!ok1 || !ok2) guard")
	}
	binOr, okBO := unwrapParens(gIf.Cond).(*ast.BinaryExpr)
	gRet, okGR := gIf.Body.List[0].(*ast.ReturnStmt)
	if !okBO || binOr.Op != token.LOR || !okGR || len(gRet.Results) != 1 {
		return "", fmt.Errorf("os: SameFile invalid (!ok1 || !ok2) guard")
	}
	uL, okUL := unwrapParens(binOr.X).(*ast.UnaryExpr)
	uR, okUR := unwrapParens(binOr.Y).(*ast.UnaryExpr)
	_, okFalse := isIdentNamed(gRet.Results[0], "false")
	if !okUL || !okUR || uL.Op != token.NOT || uR.Op != token.NOT || !okFalse {
		return "", fmt.Errorf("os: SameFile guard does not return false on !ok1 || !ok2")
	}
	_, l1 := isIdentNamed(uL.X, ok1)
	_, r2 := isIdentNamed(uR.X, ok2)
	_, l2 := isIdentNamed(uL.X, ok2)
	_, r1 := isIdentNamed(uR.X, ok1)
	if !((l1 && r2) || (l2 && r1)) {
		return "", fmt.Errorf("os: SameFile guard does not check (!%s || !%s)", ok1, ok2)
	}
	lastRet, okLR := rem[3].(*ast.ReturnStmt)
	if !okLR || len(lastRet.Results) != 1 {
		return "", fmt.Errorf("os: SameFile missing final return")
	}
	smCall, okSMC := unwrapParens(lastRet.Results[0]).(*ast.CallExpr)
	if !okSMC || smCall.Ellipsis.IsValid() || len(smCall.Args) != 2 {
		return "", fmt.Errorf("os: SameFile final return does not call sameFile")
	}
	_, okSMFun := isIdentNamed(smCall.Fun, "sameFile")
	_, c01 := isIdentNamed(smCall.Args[0], fs1)
	_, c12 := isIdentNamed(smCall.Args[1], fs2)
	_, c02 := isIdentNamed(smCall.Args[0], fs2)
	_, c11 := isIdentNamed(smCall.Args[1], fs1)
	if !okSMFun || !((c01 && c12) || (c02 && c11)) {
		return "", fmt.Errorf("os: SameFile does not delegate to sameFile(%s, %s)", fs1, fs2)
	}

	// Verify platform sameFile(fs1, fs2 *fileStat) bool compares corresponding fields across both arguments.
	sm := allTopFuncs["sameFile"]
	if sm == nil || sm.Body == nil || sm.Type == nil || sm.Type.TypeParams != nil || !funcHasUnnamedResults(sm.Type, 1) || pkgDeclCounts["sameFile"] != 1 || osAnyLinknameLocals["sameFile"] || funcShadowsAnyIdent(sm, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(sm.Body) || len(sm.Body.List) == 0 {
		return "", fmt.Errorf("os: invalid sameFile implementation")
	}
	if _, okBool := isIdentNamed(sm.Type.Results.List[0].Type, "bool"); !okBool {
		return "", fmt.Errorf("os: sameFile does not return bool")
	}
	smParams := paramNamesFlat(sm.Type.Params)
	if len(smParams) != 2 || smParams[0] == "" || smParams[0] == "_" || smParams[1] == "" || smParams[1] == "_" || smParams[0] == smParams[1] || bodyMutatesOrTakesAddrOfAny(sm.Body, map[string]bool{smParams[0]: true, smParams[1]: true}) {
		return "", fmt.Errorf("os: sameFile invalid parameters")
	}
	for _, fld := range sm.Type.Params.List {
		star, okS := unwrapParens(fld.Type).(*ast.StarExpr)
		if !okS {
			return "", fmt.Errorf("os: sameFile parameter is not *fileStat")
		}
		if _, okFS := isIdentNamed(star.X, "fileStat"); !okFS {
			return "", fmt.Errorf("os: sameFile parameter is not *fileStat")
		}
	}

	side0 := map[string]bool{smParams[0]: true}
	side1 := map[string]bool{smParams[1]: true}
	errVars := map[string]bool{}
	for _, st := range sm.Body.List[:len(sm.Body.List)-1] {
		switch s := st.(type) {
		case *ast.AssignStmt:
			if len(s.Lhs) != 1 || len(s.Rhs) != 1 {
				return "", fmt.Errorf("os: sameFile unexpected assignment")
			}
			lhsID, okL := unwrapParens(s.Lhs[0]).(*ast.Ident)
			if !okL || lhsID.Name == "" || lhsID.Name == "_" || side0[lhsID.Name] || side1[lhsID.Name] {
				return "", fmt.Errorf("os: sameFile invalid local assignment")
			}
			if ta, okTA := unwrapParens(s.Rhs[0]).(*ast.TypeAssertExpr); okTA && s.Tok == token.DEFINE && ta.Type != nil {
				sel, okSel := unwrapParens(ta.X).(*ast.SelectorExpr)
				if !okSel {
					return "", fmt.Errorf("os: sameFile invalid type assertion target")
				}
				bID, okB := unwrapParens(sel.X).(*ast.Ident)
				if !okB || (!side0[bID.Name] && !side1[bID.Name]) {
					return "", fmt.Errorf("os: sameFile type assertion not rooted on parameter")
				}
				if side0[bID.Name] {
					side0[lhsID.Name] = true
				} else {
					side1[lhsID.Name] = true
				}
				continue
			}
			if c, okC := unwrapParens(s.Rhs[0]).(*ast.CallExpr); okC && !c.Ellipsis.IsValid() && len(c.Args) == 0 {
				if sel, okSel := unwrapParens(c.Fun).(*ast.SelectorExpr); okSel && sel.Sel.Name == "loadFileId" {
					if bID, okB := unwrapParens(sel.X).(*ast.Ident); okB && (bID.Name == smParams[0] || bID.Name == smParams[1]) {
						errVars[lhsID.Name] = true
						continue
					}
				}
			}
			return "", fmt.Errorf("os: sameFile unexpected helper statement")
		case *ast.IfStmt:
			eVar := condChecksNonZeroErr(s.Cond)
			if s.Init != nil || s.Else != nil || !errVars[eVar] || len(s.Body.List) != 1 {
				return "", fmt.Errorf("os: sameFile unexpected guard statement")
			}
			r, okR := s.Body.List[0].(*ast.ReturnStmt)
			if !okR || len(r.Results) != 1 {
				return "", fmt.Errorf("os: sameFile guard does not return false")
			}
			if _, okF := isIdentNamed(r.Results[0], "false"); !okF {
				return "", fmt.Errorf("os: sameFile guard does not return false")
			}
		default:
			return "", fmt.Errorf("os: sameFile unexpected statement before return")
		}
	}

	extractSideFieldChain := func(expr ast.Expr) (int, []string, bool) {
		var fields []string
		cur := unwrapParens(expr)
		for {
			sel, okS := cur.(*ast.SelectorExpr)
			if !okS {
				break
			}
			fields = append(fields, sel.Sel.Name)
			cur = unwrapParens(sel.X)
		}
		if len(fields) == 0 {
			return -1, nil, false
		}
		id, okID := cur.(*ast.Ident)
		if !okID {
			return -1, nil, false
		}
		slices.Reverse(fields)
		if side0[id.Name] {
			return 0, fields, true
		}
		if side1[id.Name] {
			return 1, fields, true
		}
		return -1, nil, false
	}
	var verifyEqConj func(expr ast.Expr) bool
	verifyEqConj = func(expr ast.Expr) bool {
		bin, okB := unwrapParens(expr).(*ast.BinaryExpr)
		if !okB {
			return false
		}
		if bin.Op == token.LAND {
			return verifyEqConj(bin.X) && verifyEqConj(bin.Y)
		}
		if bin.Op != token.EQL {
			return false
		}
		sL, fL, okL := extractSideFieldChain(bin.X)
		sR, fR, okR := extractSideFieldChain(bin.Y)
		return okL && okR && sL != sR && slices.Equal(fL, fR)
	}

	smRet, okSMR := sm.Body.List[len(sm.Body.List)-1].(*ast.ReturnStmt)
	if !okSMR || len(smRet.Results) != 1 || !verifyEqConj(smRet.Results[0]) {
		return "", fmt.Errorf("os: sameFile return does not compare corresponding fields of both fileStat values")
	}
	return disjointAltStruct, nil
}

func verifyOSNologStatHelpers(
	allTopFuncs, allFileMethods, allRawFileMethods, allFileStatMethods map[string]*ast.FuncDecl,
	pkgDeclCounts, fileMethodCounts, rawFileMethodCounts, fileStatMethodCounts map[string]int,
	funcFile map[*ast.FuncDecl]*ast.File,
	fileImportsSyscall map[*ast.File]bool,
	osInactive *osInactiveState,
	osNoFileReserved, osAnyLinknameLocals map[string]bool,
	disjointAltStruct string,
	usedSameFile, usedFstatNolog, usedFileStatInGetwd bool,
	skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool,
) error {
	returnsFileInfoOrStat := func(fn *ast.FuncDecl) bool {
		if fn == nil || fn.Type == nil || fn.Type.Results == nil || len(fn.Type.Results.List) == 0 {
			return false
		}
		t0 := unwrapParens(fn.Type.Results.List[0].Type)
		if _, okFI := isIdentNamed(t0, "FileInfo"); okFI {
			return true
		}
		if star, okS := t0.(*ast.StarExpr); okS {
			if _, okFS := isIdentNamed(star.X, "fileStat"); okFS {
				return true
			}
		}
		return false
	}

	type statWorkItem struct {
		kind string // "top", "file", "raw", "filestat"
		name string
	}
	type statRootSpec struct {
		item       statWorkItem
		needKernel bool
		isFdStat   bool
	}
	roots := []statRootSpec{
		{item: statWorkItem{kind: "top", name: "statNolog"}, needKernel: true},
		{item: statWorkItem{kind: "top", name: "lstatNolog"}, needKernel: true},
	}
	if usedFstatNolog {
		roots = append(roots, statRootSpec{item: statWorkItem{kind: "top", name: "fstatNolog"}, needKernel: true, isFdStat: true})
	}
	if usedFileStatInGetwd {
		roots = append(roots, statRootSpec{item: statWorkItem{kind: "file", name: "Stat"}, needKernel: true, isFdStat: true})
	}
	if usedSameFile && allFileStatMethods["loadFileId"] != nil {
		roots = append(roots, statRootSpec{item: statWorkItem{kind: "filestat", name: "loadFileId"}, needKernel: false})
	}

	lookupStatCallable := func(it statWorkItem) (*ast.FuncDecl, bool) {
		switch it.kind {
		case "top":
			fn := allTopFuncs[it.name]
			if fn == nil || fn.Body == nil || fn.Type == nil || pkgDeclCounts[it.name] != 1 || osAnyLinknameLocals[it.name] {
				return nil, false
			}
			return fn, true
		case "file":
			fn := allFileMethods[it.name]
			if fn == nil || fn.Body == nil || fn.Type == nil || fn.Recv == nil || len(fn.Recv.List) != 1 || fileMethodCounts[it.name] != 1 || osAnyLinknameLocals[it.name] {
				return nil, false
			}
			if _, isPtr := unwrapParens(fn.Recv.List[0].Type).(*ast.StarExpr); !isPtr {
				return nil, false
			}
			return fn, true
		case "raw":
			fn := allRawFileMethods[it.name]
			if fn == nil || fn.Body == nil || fn.Type == nil || fn.Recv == nil || len(fn.Recv.List) != 1 || rawFileMethodCounts[it.name] != 1 || osAnyLinknameLocals[it.name] {
				return nil, false
			}
			if _, isPtr := unwrapParens(fn.Recv.List[0].Type).(*ast.StarExpr); !isPtr {
				return nil, false
			}
			return fn, true
		case "filestat":
			fn := allFileStatMethods[it.name]
			if fn == nil || fn.Body == nil || fn.Type == nil || fn.Recv == nil || len(fn.Recv.List) != 1 || fileStatMethodCounts[it.name] != 1 || osAnyLinknameLocals[it.name] {
				return nil, false
			}
			if _, isPtr := unwrapParens(fn.Recv.List[0].Type).(*ast.StarExpr); !isPtr {
				return nil, false
			}
			return fn, true
		default:
			return nil, false
		}
	}

	usedIgnoringEINTR := false
	for _, rootSpec := range roots {
		rootLabel := rootSpec.item.name
		if rootSpec.item.kind != "top" {
			rootLabel = rootSpec.item.kind + ":" + rootSpec.item.name
		}
		if _, okRoot := lookupStatCallable(rootSpec.item); !okRoot {
			return fmt.Errorf("os: missing or invalid %s helper", rootLabel)
		}
		visited := map[statWorkItem]bool{}
		queue := []statWorkItem{rootSpec.item}
		sawKernelStat := false

		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if visited[cur] {
				continue
			}
			visited[cur] = true
			curLabel := cur.name
			if cur.kind != "top" {
				curLabel = cur.kind + ":" + cur.name
			}
			fn, okFn := lookupStatCallable(cur)
			if !okFn || funcShadowsAnyIdent(fn, map[string]bool{"testlog": true, "syscall": true, "nil": true, "fileStat": true}) {
				return fmt.Errorf("os: invalid %s stat helper %s", rootLabel, curLabel)
			}
			hPos := 0
			for hPos < len(fn.Body.List) && skipInactiveHookIf(fn.Body.List[hPos], fn) {
				hPos++
			}
			stmts := fn.Body.List[hPos:]
			if len(stmts) == 0 {
				return fmt.Errorf("os: %s helper %s has empty body", rootLabel, curLabel)
			}

			type statLocalBinding struct {
				isZeroFileStat bool
				sawFresh       bool
				bad            bool
			}
			identBinding := map[*ast.Ident]*statLocalBinding{}
			topScope := map[string]*statLocalBinding{}
			topSame := map[string]*statLocalBinding{}
			if r := recvVarName(fn); r != "" && r != "_" {
				b := &statLocalBinding{bad: true}
				topScope[r] = b
				topSame[r] = b
			}
			for _, p := range paramNamesFlat(fn.Type.Params) {
				if p != "" && p != "_" {
					b := &statLocalBinding{bad: true}
					topScope[p] = b
					topSame[p] = b
				}
			}
			if fn.Type.Results != nil {
				for _, fld := range fn.Type.Results.List {
					for _, id := range fld.Names {
						if id.Name != "" && id.Name != "_" {
							b := &statLocalBinding{sawFresh: true}
							topScope[id.Name] = b
							topSame[id.Name] = b
							identBinding[id] = b
						}
					}
				}
			}

			fileImports := map[string]bool(nil)
			if osInactive != nil {
				fileImports = osInactive.fileImportNames[funcFile[fn]]
			}

			var helperErr error
			var bindStatExpr func(e ast.Expr, scope map[string]*statLocalBinding)
			var bindStatStmt func(s ast.Stmt, scope, sameBlock map[string]*statLocalBinding)

			bindStatExpr = func(e ast.Expr, scope map[string]*statLocalBinding) {
				if helperErr != nil || e == nil {
					return
				}
				switch x := e.(type) {
				case *ast.Ident:
					if b := scope[x.Name]; b != nil {
						identBinding[x] = b
					}
					return
				case *ast.SelectorExpr:
					bindStatExpr(x.X, scope)
					return
				case *ast.UnaryExpr:
					bindStatExpr(x.X, scope)
					if helperErr == nil && x.Op == token.AND {
						curExpr := unwrapParens(x.X)
						for {
							sel, okS := curExpr.(*ast.SelectorExpr)
							if !okS {
								break
							}
							curExpr = unwrapParens(sel.X)
						}
						if bID, okB := curExpr.(*ast.Ident); okB && identBinding[bID] == nil && pkgDeclCounts[bID.Name] > 0 {
							helperErr = fmt.Errorf("os: %s helper %s takes address of package declaration %s", rootLabel, curLabel, bID.Name)
						}
					}
					return
				case *ast.FuncLit:
					litScope := maps.Clone(scope)
					litSame := map[string]*statLocalBinding{}
					if x.Type != nil {
						if x.Type.Params != nil {
							for _, fld := range x.Type.Params.List {
								bindStatExpr(fld.Type, scope)
							}
						}
						if x.Type.Results != nil {
							for _, fld := range x.Type.Results.List {
								bindStatExpr(fld.Type, scope)
							}
						}
						for _, p := range paramNamesFlat(x.Type.Params) {
							if p != "" && p != "_" {
								b := &statLocalBinding{bad: true}
								litScope[p] = b
								litSame[p] = b
							}
						}
						if x.Type.Results != nil {
							for _, fld := range x.Type.Results.List {
								for _, id := range fld.Names {
									if id.Name != "" && id.Name != "_" {
										b := &statLocalBinding{bad: true}
										litScope[id.Name] = b
										litSame[id.Name] = b
										identBinding[id] = b
									}
								}
							}
						}
					}
					if x.Body != nil {
						for _, st := range x.Body.List {
							bindStatStmt(st, litScope, litSame)
						}
					}
					return
				}
				ast.Inspect(e, func(ch ast.Node) bool {
					if helperErr != nil || ch == nil {
						return false
					}
					if ch == e {
						return true
					}
					if subE, okE := ch.(ast.Expr); okE {
						bindStatExpr(subE, scope)
						return false
					}
					if subS, okS := ch.(ast.Stmt); okS {
						bindStatStmt(subS, scope, map[string]*statLocalBinding{})
						return false
					}
					return true
				})
			}

			bindStatStmt = func(s ast.Stmt, scope, sameBlock map[string]*statLocalBinding) {
				if helperErr != nil || s == nil {
					return
				}
				switch x := s.(type) {
				case *ast.BlockStmt:
					blkScope := maps.Clone(scope)
					blkSame := map[string]*statLocalBinding{}
					for _, st := range x.List {
						bindStatStmt(st, blkScope, blkSame)
					}
				case *ast.LabeledStmt:
					bindStatStmt(x.Stmt, scope, sameBlock)
				case *ast.BranchStmt, *ast.EmptyStmt:
				case *ast.DeclStmt:
					gd, okGD := x.Decl.(*ast.GenDecl)
					if !okGD {
						helperErr = fmt.Errorf("os: %s helper %s has unexpected declaration %T", rootLabel, curLabel, x.Decl)
						return
					}
					for _, spec := range gd.Specs {
						switch sp := spec.(type) {
						case *ast.TypeSpec:
							helperErr = fmt.Errorf("os: %s helper %s declares local type", rootLabel, curLabel)
							return
						case *ast.ValueSpec:
							if sp.Type != nil {
								bindStatExpr(sp.Type, scope)
							}
							for _, val := range sp.Values {
								bindStatExpr(val, scope)
							}
							isFSVal := gd.Tok == token.VAR && sp.Type != nil && len(sp.Values) == 0 && !fileImports["fileStat"]
							if isFSVal {
								_, isFSVal = isIdentNamed(sp.Type, "fileStat")
							}
							for _, id := range sp.Names {
								if id.Name == "" || id.Name == "_" {
									continue
								}
								b := &statLocalBinding{isZeroFileStat: isFSVal}
								identBinding[id] = b
								scope[id.Name] = b
								sameBlock[id.Name] = b
							}
						}
					}
				case *ast.AssignStmt:
					if x.Tok == token.DEFINE {
						for _, rhs := range x.Rhs {
							bindStatExpr(rhs, scope)
						}
						for _, lhs := range x.Lhs {
							if id, okID := unwrapParens(lhs).(*ast.Ident); okID {
								if id.Name == "" || id.Name == "_" {
									continue
								}
								if existing := sameBlock[id.Name]; existing != nil {
									identBinding[id] = existing
								} else {
									b := &statLocalBinding{}
									scope[id.Name] = b
									sameBlock[id.Name] = b
									identBinding[id] = b
								}
							} else {
								bindStatExpr(lhs, scope)
							}
						}
					} else {
						for _, lhs := range x.Lhs {
							bindStatExpr(lhs, scope)
						}
						for _, rhs := range x.Rhs {
							bindStatExpr(rhs, scope)
						}
					}
				case *ast.IfStmt:
					if skipInactiveHookIf(x, fn) {
						return
					}
					ifScope := maps.Clone(scope)
					ifSame := map[string]*statLocalBinding{}
					if x.Init != nil {
						bindStatStmt(x.Init, ifScope, ifSame)
					}
					bindStatExpr(x.Cond, ifScope)
					if x.Body != nil {
						bindStatStmt(x.Body, ifScope, ifSame)
					}
					if x.Else != nil {
						bindStatStmt(x.Else, maps.Clone(ifScope), map[string]*statLocalBinding{})
					}
				case *ast.ForStmt:
					forScope := maps.Clone(scope)
					forSame := map[string]*statLocalBinding{}
					if x.Init != nil {
						bindStatStmt(x.Init, forScope, forSame)
					}
					if x.Cond != nil {
						bindStatExpr(x.Cond, forScope)
					}
					if x.Post != nil {
						bindStatStmt(x.Post, forScope, forSame)
					}
					if x.Body != nil {
						bindStatStmt(x.Body, forScope, forSame)
					}
				case *ast.RangeStmt:
					bindStatExpr(x.X, scope)
					rngScope := maps.Clone(scope)
					rngSame := map[string]*statLocalBinding{}
					if x.Tok == token.DEFINE {
						for _, expr := range []ast.Expr{x.Key, x.Value} {
							if expr == nil {
								continue
							}
							if id, okID := unwrapParens(expr).(*ast.Ident); okID {
								if id.Name != "" && id.Name != "_" {
									b := &statLocalBinding{bad: true}
									rngScope[id.Name] = b
									rngSame[id.Name] = b
									identBinding[id] = b
								}
							} else {
								bindStatExpr(expr, rngScope)
							}
						}
					} else {
						if x.Key != nil {
							bindStatExpr(x.Key, rngScope)
						}
						if x.Value != nil {
							bindStatExpr(x.Value, rngScope)
						}
					}
					if x.Body != nil {
						bindStatStmt(x.Body, rngScope, rngSame)
					}
				case *ast.SwitchStmt:
					swScope := maps.Clone(scope)
					swSame := map[string]*statLocalBinding{}
					if x.Init != nil {
						bindStatStmt(x.Init, swScope, swSame)
					}
					if x.Tag != nil {
						bindStatExpr(x.Tag, swScope)
					}
					if x.Body != nil {
						for _, cs := range x.Body.List {
							if cc, okCC := cs.(*ast.CaseClause); okCC {
								for _, ce := range cc.List {
									bindStatExpr(ce, swScope)
								}
								ccScope := maps.Clone(swScope)
								ccSame := map[string]*statLocalBinding{}
								for _, bodySt := range cc.Body {
									bindStatStmt(bodySt, ccScope, ccSame)
								}
							}
						}
					}
				case *ast.TypeSwitchStmt:
					tsScope := maps.Clone(scope)
					tsSame := map[string]*statLocalBinding{}
					if x.Init != nil {
						bindStatStmt(x.Init, tsScope, tsSame)
					}
					var boundID *ast.Ident
					if as, okA := x.Assign.(*ast.AssignStmt); okA && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
						bindStatExpr(as.Rhs[0], tsScope)
						if id, okID := unwrapParens(as.Lhs[0]).(*ast.Ident); okID && id.Name != "" && id.Name != "_" {
							boundID = id
							identBinding[id] = &statLocalBinding{bad: true}
						}
					} else if x.Assign != nil {
						bindStatStmt(x.Assign, tsScope, tsSame)
					}
					if x.Body != nil {
						for _, cs := range x.Body.List {
							if cc, okCC := cs.(*ast.CaseClause); okCC {
								for _, ce := range cc.List {
									bindStatExpr(ce, tsScope)
								}
								ccScope := maps.Clone(tsScope)
								ccSame := map[string]*statLocalBinding{}
								if boundID != nil {
									b := &statLocalBinding{bad: true}
									ccScope[boundID.Name] = b
									ccSame[boundID.Name] = b
								}
								for _, bodySt := range cc.Body {
									bindStatStmt(bodySt, ccScope, ccSame)
								}
							}
						}
					}
				case *ast.SelectStmt:
					if x.Body != nil {
						for _, cs := range x.Body.List {
							if cm, okCM := cs.(*ast.CommClause); okCM {
								cmScope := maps.Clone(scope)
								cmSame := map[string]*statLocalBinding{}
								if cm.Comm != nil {
									bindStatStmt(cm.Comm, cmScope, cmSame)
								}
								for _, bodySt := range cm.Body {
									bindStatStmt(bodySt, cmScope, cmSame)
								}
							}
						}
					}
				case *ast.ReturnStmt:
					for _, r := range x.Results {
						bindStatExpr(r, scope)
					}
				case *ast.ExprStmt:
					bindStatExpr(x.X, scope)
				case *ast.SendStmt:
					bindStatExpr(x.Chan, scope)
					bindStatExpr(x.Value, scope)
				case *ast.IncDecStmt:
					bindStatExpr(x.X, scope)
				case *ast.GoStmt:
					bindStatExpr(x.Call, scope)
				case *ast.DeferStmt:
					bindStatExpr(x.Call, scope)
				default:
					helperErr = fmt.Errorf("os: %s helper %s has unsupported statement %T", rootLabel, curLabel, s)
				}
			}

			for _, st := range stmts {
				bindStatStmt(st, topScope, topSame)
				if helperErr != nil {
					return helperErr
				}
			}

			// Pass 2a: mark any address-taken non-fileStat local, any whole-value mutation of a zero-init
			// fileStat local, and any inc/dec/range/type-switch assignment target on its lexical binding
			// before evaluating isFreshStatExpr.
			for _, st := range stmts {
				ast.Inspect(st, func(n ast.Node) bool {
					if helperErr != nil || n == nil {
						return false
					}
					if ifs, okI := n.(*ast.IfStmt); okI && skipInactiveHookIf(ifs, fn) {
						return false
					}
					switch x := n.(type) {
					case *ast.UnaryExpr:
						if x.Op == token.AND {
							if directID, okD := unwrapParens(x.X).(*ast.Ident); okD {
								if b := identBinding[directID]; b != nil && !b.isZeroFileStat {
									b.bad = true
								}
							}
						}
					case *ast.AssignStmt:
						for _, lhs := range x.Lhs {
							if _, okStar := unwrapParens(lhs).(*ast.StarExpr); okStar {
								helperErr = fmt.Errorf("os: %s helper %s dereference-assigns pointer target", rootLabel, curLabel)
								return false
							}
							if lID, okID := unwrapParens(lhs).(*ast.Ident); okID {
								if b := identBinding[lID]; b != nil && b.isZeroFileStat {
									b.bad = true
								}
							}
						}
					case *ast.IncDecStmt:
						if _, okStar := unwrapParens(x.X).(*ast.StarExpr); okStar {
							helperErr = fmt.Errorf("os: %s helper %s dereference-mutates pointer target", rootLabel, curLabel)
							return false
						}
						if lID, okID := unwrapParens(x.X).(*ast.Ident); okID {
							if b := identBinding[lID]; b != nil {
								b.bad = true
							}
						}
					case *ast.RangeStmt:
						for _, expr := range []ast.Expr{x.Key, x.Value} {
							if expr != nil {
								if _, okStar := unwrapParens(expr).(*ast.StarExpr); okStar {
									helperErr = fmt.Errorf("os: %s helper %s dereference-assigns pointer target in range", rootLabel, curLabel)
									return false
								}
								if id, okID := unwrapParens(expr).(*ast.Ident); okID {
									if b := identBinding[id]; b != nil {
										b.bad = true
									}
								}
							}
						}
					case *ast.TypeSwitchStmt:
						if as, okA := x.Assign.(*ast.AssignStmt); okA {
							for _, lhs := range as.Lhs {
								if id, okID := unwrapParens(lhs).(*ast.Ident); okID {
									if b := identBinding[id]; b != nil {
										b.bad = true
									}
								}
							}
						}
					}
					return true
				})
				if helperErr != nil {
					return helperErr
				}
			}

			isFreshStatExpr := func(expr ast.Expr) bool {
				expr = unwrapParens(expr)
				if _, okNil := isIdentNamed(expr, "nil"); okNil && !fileImports["nil"] {
					return true
				}
				if u, okU := expr.(*ast.UnaryExpr); okU && u.Op == token.AND {
					if _, tName := compositeWriterLit(expr); tName == "fileStat" && !fileImports["fileStat"] {
						return true
					}
					if vID, okV := unwrapParens(u.X).(*ast.Ident); okV {
						b := identBinding[vID]
						return b != nil && b.isZeroFileStat && !b.bad
					}
					return false
				}
				if c, okC := expr.(*ast.CallExpr); okC && !c.Ellipsis.IsValid() {
					if cID, okID := unwrapParens(c.Fun).(*ast.Ident); okID && !fileImports[cID.Name] && allTopFuncs[cID.Name] != nil && pkgDeclCounts[cID.Name] == 1 && !osAnyLinknameLocals[cID.Name] && returnsFileInfoOrStat(allTopFuncs[cID.Name]) {
						return true
					}
				}
				return false
			}

			enqueueIfNew := func(it statWorkItem) {
				if !visited[it] {
					queue = append(queue, it)
				}
			}

			recordBindFreshness := func(id *ast.Ident, fresh bool) {
				if id == nil || id.Name == "" || id.Name == "_" {
					return
				}
				if b := identBinding[id]; b != nil {
					if fresh {
						b.sawFresh = true
					} else {
						b.bad = true
					}
				}
			}

			// Pass 2b: evaluate all variable initializers/assignments against finalized zero-fileStat
			// bindings, and audit calls and identifier references.
			checkReturns := returnsFileInfoOrStat(fn)
			for _, st := range stmts {
				ast.Inspect(st, func(n ast.Node) bool {
					if helperErr != nil || n == nil {
						return false
					}
					if ifs, okI := n.(*ast.IfStmt); okI && skipInactiveHookIf(ifs, fn) {
						return false
					}
					switch x := n.(type) {
					case *ast.GenDecl:
						for _, spec := range x.Specs {
							vs, okVS := spec.(*ast.ValueSpec)
							if !okVS {
								continue
							}
							if len(vs.Names) == 1 {
								if b := identBinding[vs.Names[0]]; b != nil && b.isZeroFileStat {
									continue
								}
							}
							allZeroFS := len(vs.Names) > 0
							for _, id := range vs.Names {
								if id.Name == "" || id.Name == "_" {
									continue
								}
								if b := identBinding[id]; b == nil || !b.isZeroFileStat {
									allZeroFS = false
									break
								}
							}
							if allZeroFS {
								continue
							}
							if len(vs.Values) == 0 {
								for _, id := range vs.Names {
									recordBindFreshness(id, x.Tok == token.VAR)
								}
							} else if len(vs.Values) == len(vs.Names) {
								for i, id := range vs.Names {
									recordBindFreshness(id, isFreshStatExpr(vs.Values[i]))
								}
							} else if len(vs.Values) == 1 && len(vs.Names) == 2 {
								recordBindFreshness(vs.Names[0], isFreshStatExpr(vs.Values[0]))
								recordBindFreshness(vs.Names[1], false)
							} else {
								for _, id := range vs.Names {
									recordBindFreshness(id, false)
								}
							}
						}
					case *ast.AssignStmt:
						if x.Tok != token.ASSIGN && x.Tok != token.DEFINE {
							for _, lhs := range x.Lhs {
								if lID, okID := unwrapParens(lhs).(*ast.Ident); okID {
									recordBindFreshness(lID, false)
								}
							}
						} else if len(x.Rhs) == 1 && len(x.Lhs) == 2 {
							if l0, ok0 := unwrapParens(x.Lhs[0]).(*ast.Ident); ok0 {
								recordBindFreshness(l0, isFreshStatExpr(x.Rhs[0]))
							}
							if l1, ok1 := unwrapParens(x.Lhs[1]).(*ast.Ident); ok1 {
								recordBindFreshness(l1, false)
							}
						} else if len(x.Lhs) == len(x.Rhs) {
							for i, lhs := range x.Lhs {
								if lID, okID := unwrapParens(lhs).(*ast.Ident); okID {
									recordBindFreshness(lID, isFreshStatExpr(x.Rhs[i]))
								}
							}
						} else {
							for _, lhs := range x.Lhs {
								if lID, okID := unwrapParens(lhs).(*ast.Ident); okID {
									recordBindFreshness(lID, false)
								}
							}
						}
					case *ast.Ident:
						if x.Name == "testlog" {
							helperErr = fmt.Errorf("os: %s helper %s references testlog", rootLabel, curLabel)
							return false
						}
						if disjointAltStruct != "" && x.Name == disjointAltStruct {
							helperErr = fmt.Errorf("os: %s helper %s references alternate FileInfo struct %s", rootLabel, curLabel, disjointAltStruct)
							return false
						}
					case *ast.CallExpr:
						if cID, okID := unwrapParens(x.Fun).(*ast.Ident); okID {
							if identBinding[cID] != nil {
								helperErr = fmt.Errorf("os: %s helper %s calls local variable %s", rootLabel, curLabel, cID.Name)
								return false
							}
							if osAnyLinknameLocals[cID.Name] {
								helperErr = fmt.Errorf("os: %s helper %s calls linknamed %s", rootLabel, curLabel, cID.Name)
								return false
							}
							if cID.Name == "ignoringEINTR" {
								usedIgnoringEINTR = true
							} else if allTopFuncs[cID.Name] != nil {
								enqueueIfNew(statWorkItem{kind: "top", name: cID.Name})
							}
						} else if sel, okS := unwrapParens(x.Fun).(*ast.SelectorExpr); okS {
							if _, okSys := isIdentNamed(sel.X, "syscall"); okSys {
								if rootSpec.isFdStat {
									if sel.Sel.Name == "Fstat" || sel.Sel.Name == "GetFileInformationByHandle" {
										sawKernelStat = true
									}
								} else {
									if sel.Sel.Name == "Stat" || sel.Sel.Name == "Lstat" || sel.Sel.Name == "GetFileAttributesEx" || sel.Sel.Name == "CreateFile" || sel.Sel.Name == "GetFileInformationByHandle" {
										sawKernelStat = true
									}
								}
							} else if rootSpec.isFdStat && sel.Sel.Name == "Fstat" {
								sawKernelStat = true
							}
							isNonImportRecv := false
							if bID, okB := unwrapParens(sel.X).(*ast.Ident); okB && !fileImports[bID.Name] {
								isNonImportRecv = true
							} else if _, okTA := unwrapParens(sel.X).(*ast.TypeAssertExpr); okTA {
								isNonImportRecv = true
							}
							if isNonImportRecv {
								if allFileStatMethods[sel.Sel.Name] != nil {
									enqueueIfNew(statWorkItem{kind: "filestat", name: sel.Sel.Name})
								} else if sel.Sel.Name != "Close" && allFileMethods[sel.Sel.Name] != nil {
									enqueueIfNew(statWorkItem{kind: "file", name: sel.Sel.Name})
								} else if sel.Sel.Name != "close" && allRawFileMethods[sel.Sel.Name] != nil {
									enqueueIfNew(statWorkItem{kind: "raw", name: sel.Sel.Name})
								}
							}
						}
					case *ast.FuncLit:
						// Only permitted as the callback argument of ignoringEINTR(...).
					}
					return true
				})
				if helperErr != nil {
					return helperErr
				}
			}

			if checkReturns {
				for _, st := range stmts {
					ast.Inspect(st, func(n ast.Node) bool {
						if helperErr != nil || n == nil {
							return false
						}
						if _, okFL := n.(*ast.FuncLit); okFL {
							return false
						}
						if ifs, okI := n.(*ast.IfStmt); okI && skipInactiveHookIf(ifs, fn) {
							return false
						}
						ret, okR := n.(*ast.ReturnStmt)
						if !okR {
							return true
						}
						if len(ret.Results) == 0 {
							helperErr = fmt.Errorf("os: %s helper %s has bare return", rootLabel, curLabel)
							return false
						}
						r0 := unwrapParens(ret.Results[0])
						if isFreshStatExpr(r0) {
							return true
						}
						if vID, okV := r0.(*ast.Ident); okV {
							if b := identBinding[vID]; b != nil && b.sawFresh && !b.bad {
								return true
							}
						}
						helperErr = fmt.Errorf("os: %s helper %s returns unverified FileInfo expression", rootLabel, curLabel)
						return false
					})
					if helperErr != nil {
						return helperErr
					}
				}
			}
		}

		if rootSpec.needKernel && !sawKernelStat {
			return fmt.Errorf("os: %s does not reach kernel stat operation", rootLabel)
		}
	}
	if usedIgnoringEINTR && !verifyOSIgnoringEINTR(allTopFuncs["ignoringEINTR"], funcFile, fileImportsSyscall, osNoFileReserved, osAnyLinknameLocals) {
		return fmt.Errorf("os: invalid ignoringEINTR helper used by statNolog")
	}
	return nil
}

type osFalseHelperKey struct {
	name    string
	arity   int
	boolIdx int
}

var osAllowedPureIntConversions = map[string]bool{
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true, "uintptr": true,
}

type osInactiveState struct {
	pkgDeclCounts       map[string]int
	funcFile            map[*ast.FuncDecl]*ast.File
	fileImportNames     map[*ast.File]map[string]bool
	falseConsts         map[string]bool
	trueConsts          map[string]bool
	osGateFuncs         map[string]string
	nilAccessors        map[string][]string
	falsePreds          map[string][]string
	falseHandledHelpers map[osFalseHelperKey][]string
}

func (s *osInactiveState) identShadowedInFunc(fn *ast.FuncDecl, name string) bool {
	if s == nil {
		return true
	}
	if funcShadowsAnyIdent(fn, map[string]bool{name: true}) {
		return true
	}
	if fn != nil && s.fileImportNames[s.funcFile[fn]][name] {
		return true
	}
	return false
}

func funcResultFieldTypeAt(results *ast.FieldList, targetIdx int) ast.Expr {
	if results == nil || targetIdx < 0 {
		return nil
	}
	cur := 0
	for _, fld := range results.List {
		n := len(fld.Names)
		if n == 0 {
			n = 1
		}
		if targetIdx < cur+n {
			return fld.Type
		}
		cur += n
	}
	return nil
}

func recvBaseTypeName(expr ast.Expr) string {
	t := unwrapParens(expr)
	if star, ok := t.(*ast.StarExpr); ok {
		t = unwrapParens(star.X)
	}
	return baseTypeIdentName(t)
}

func baseTypeIdentName(expr ast.Expr) string {
	switch t := unwrapParens(expr).(type) {
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return baseTypeIdentName(t.X)
	case *ast.IndexListExpr:
		return baseTypeIdentName(t.X)
	default:
		return ""
	}
}

type osFalseEvalEnv[D any] struct {
	st          *osInactiveState
	zeroDep     func() D
	gateDep     func(rtGate string) D
	falsePred   func(name string) (D, bool)
	nilAccessor func(name string) (D, bool)
	merge       func(a, b D) D
}

func evalOSFalseExpr[D any](env osFalseEvalEnv[D], expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) (D, bool) {
	var zero D
	if env.st == nil {
		return zero, false
	}
	expr = unwrapParens(expr)
	if id, okID := expr.(*ast.Ident); okID {
		if id.Name == "false" && env.st.pkgDeclCounts["false"] == 0 && !env.st.identShadowedInFunc(fn, "false") {
			return env.zeroDep(), true
		}
		if env.st.falseConsts[id.Name] && !env.st.identShadowedInFunc(fn, id.Name) {
			return env.zeroDep(), true
		}
		return zero, false
	}
	if call, okC := expr.(*ast.CallExpr); okC && !call.Ellipsis.IsValid() {
		if cID, okID := unwrapParens(call.Fun).(*ast.Ident); okID && !env.st.identShadowedInFunc(fn, cID.Name) {
			if len(call.Args) == 0 {
				if rtGate, okG := env.st.osGateFuncs[cID.Name]; okG {
					return env.gateDep(rtGate), true
				}
			}
			if len(call.Args) == 1 && env.st.isPureChain(call.Args[0], fn, params) {
				if d, okFP := env.falsePred(cID.Name); okFP {
					return d, true
				}
			}
		}
	}
	if bin, okB := expr.(*ast.BinaryExpr); okB {
		switch bin.Op {
		case token.NEQ:
			checkNilAccCall := func(callSide, nilSide ast.Expr) (D, bool) {
				if _, okNil := isIdentNamed(nilSide, "nil"); !okNil || env.st.pkgDeclCounts["nil"] != 0 || env.st.identShadowedInFunc(fn, "nil") {
					return zero, false
				}
				c, okC := unwrapParens(callSide).(*ast.CallExpr)
				if !okC || c.Ellipsis.IsValid() || len(c.Args) != 1 || !env.st.isPureChain(c.Args[0], fn, params) {
					return zero, false
				}
				cID, okID := unwrapParens(c.Fun).(*ast.Ident)
				if !okID || env.st.identShadowedInFunc(fn, cID.Name) {
					return zero, false
				}
				return env.nilAccessor(cID.Name)
			}
			if d, okL := checkNilAccCall(bin.X, bin.Y); okL {
				return d, true
			}
			if d, okR := checkNilAccCall(bin.Y, bin.X); okR {
				return d, true
			}
		case token.LAND:
			if dL, okL := evalOSFalseExpr(env, bin.X, fn, params); okL {
				return dL, true
			}
			if env.st.isPureGuardExpr(bin.X, fn, params) {
				return evalOSFalseExpr(env, bin.Y, fn, params)
			}
		case token.LOR:
			dL, okL := evalOSFalseExpr(env, bin.X, fn, params)
			if !okL {
				return zero, false
			}
			dR, okR := evalOSFalseExpr(env, bin.Y, fn, params)
			if !okR {
				return zero, false
			}
			return env.merge(dL, dR), true
		}
	}
	return zero, false
}

func discoverOSInactiveState(files []*ast.File, osRuntimePullMap map[string]string, osAnyLinknameLocals map[string]bool) *osInactiveState {
	pkgDeclCounts := map[string]int{}
	funcFile := map[*ast.FuncDecl]*ast.File{}
	fileImportNames := map[*ast.File]map[string]bool{}
	st := &osInactiveState{
		pkgDeclCounts:       pkgDeclCounts,
		funcFile:            funcFile,
		fileImportNames:     fileImportNames,
		falseConsts:         map[string]bool{},
		trueConsts:          map[string]bool{},
		osGateFuncs:         map[string]string{},
		nilAccessors:        map[string][]string{},
		falsePreds:          map[string][]string{},
		falseHandledHelpers: map[osFalseHelperKey][]string{},
	}

	constDeclNames := map[string]bool{}
	falseConstCand := map[string]bool{}
	trueConstCand := map[string]bool{}
	badBoolConst := map[string]bool{}
	topFuncs := map[string]*ast.FuncDecl{}
	fileImportsAtomic := map[*ast.File]bool{}
	fileImportsSync := map[*ast.File]bool{}
	fileImportsRuntime := map[*ast.File]bool{}
	fileImportsUnsafe := map[*ast.File]bool{}
	badSpecialImport := map[*ast.File]map[string]bool{}

	type tableStructCand struct {
		name           string
		spineField     string
		nonSpineFields map[string]bool
		methods        map[string]*ast.FuncDecl
		readNilMethods map[string]bool
		mutatorMethods map[string]bool
		valid          bool
	}
	structSpecs := map[string]*ast.TypeSpec{}
	structFiles := map[string]*ast.File{}

	type tableVarCand struct {
		name       string
		structName string
		declIdent  *ast.Ident
	}
	varCands := map[string]tableVarCand{}

	for _, f := range files {
		fileImportNames[f] = map[string]bool{}
		badSpecialImport[f] = map[string]bool{}
		for _, imp := range f.Imports {
			if imp.Name != nil && imp.Name.Name == "." {
				return st
			}
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return st
			}
			if imp.Name != nil {
				if imp.Name.Name != "_" {
					fileImportNames[f][imp.Name.Name] = true
					badSpecialImport[f][imp.Name.Name] = true
				}
				continue
			}
			base := p
			if slash := strings.LastIndexByte(p, '/'); slash >= 0 {
				base = p[slash+1:]
			}
			fileImportNames[f][base] = true
			switch p {
			case "sync/atomic":
				fileImportsAtomic[f] = true
			case "sync":
				fileImportsSync[f] = true
			case "runtime":
				fileImportsRuntime[f] = true
			case "unsafe":
				fileImportsUnsafe[f] = true
			default:
				if base == "atomic" || base == "sync" || base == "runtime" || base == "unsafe" {
					badSpecialImport[f][base] = true
				}
			}
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.ValueSpec:
						for idx, id := range sp.Names {
							if id.Name == "_" {
								continue
							}
							pkgDeclCounts[id.Name]++
							if d.Tok == token.CONST {
								constDeclNames[id.Name] = true
								if sp.Type == nil && idx < len(sp.Values) {
									if vID, okID := unwrapParens(sp.Values[idx]).(*ast.Ident); okID {
										switch vID.Name {
										case "false":
											if !fileImportNames[f]["false"] {
												falseConstCand[id.Name] = true
											} else {
												badBoolConst[id.Name] = true
											}
										case "true":
											if !fileImportNames[f]["true"] {
												trueConstCand[id.Name] = true
											} else {
												badBoolConst[id.Name] = true
											}
										default:
											badBoolConst[id.Name] = true
										}
									} else {
										badBoolConst[id.Name] = true
									}
								} else {
									badBoolConst[id.Name] = true
								}
							}
							if d.Tok == token.VAR && !ast.IsExported(id.Name) && len(sp.Names) == 1 && len(sp.Values) == 0 && sp.Type != nil {
								if sName := baseTypeIdentName(sp.Type); sName != "" && !ast.IsExported(sName) && !fileImportNames[f][sName] {
									varCands[id.Name] = tableVarCand{name: id.Name, structName: sName, declIdent: id}
								}
							}
						}
					case *ast.TypeSpec:
						if sp.Name != nil && sp.Name.Name != "_" {
							pkgDeclCounts[sp.Name.Name]++
							if !ast.IsExported(sp.Name.Name) && !sp.Assign.IsValid() {
								if _, okST := unwrapParens(sp.Type).(*ast.StructType); okST {
									structSpecs[sp.Name.Name] = sp
									structFiles[sp.Name.Name] = f
								}
							}
						}
					}
				}
			case *ast.FuncDecl:
				funcFile[d] = f
				if d.Recv == nil && d.Name != nil && d.Name.Name != "init" && d.Name.Name != "_" {
					pkgDeclCounts[d.Name.Name]++
					topFuncs[d.Name.Name] = d
				}
			}
		}
	}

	if pkgDeclCounts["false"] == 0 && pkgDeclCounts["true"] == 0 && pkgDeclCounts["bool"] == 0 {
		for name := range falseConstCand {
			if !badBoolConst[name] && !trueConstCand[name] && pkgDeclCounts[name] == 1 && !osAnyLinknameLocals[name] {
				st.falseConsts[name] = true
			}
		}
		for name := range trueConstCand {
			if !badBoolConst[name] && !falseConstCand[name] && pkgDeclCounts[name] == 1 && !osAnyLinknameLocals[name] {
				st.trueConsts[name] = true
			}
		}
	}

	for gName, fn := range topFuncs {
		if ast.IsExported(gName) || pkgDeclCounts[gName] != 1 || fn.Type == nil || fn.Type.TypeParams != nil {
			continue
		}
		if fn.Type.Params != nil && fn.Type.Params.NumFields() != 0 {
			continue
		}
		if !funcHasUnnamedResults(fn.Type, 1) || len(fn.Type.Results.List) != 1 {
			continue
		}
		if _, okBool := isIdentNamed(fn.Type.Results.List[0].Type, "bool"); !okBool || pkgDeclCounts["bool"] != 0 || st.identShadowedInFunc(fn, "bool") {
			continue
		}
		if fn.Body == nil {
			if rtTarget := osRuntimePullMap[gName]; strings.HasPrefix(rtTarget, "runtime.") {
				st.osGateFuncs[gName] = rtTarget
			}
			continue
		}
		if osAnyLinknameLocals[gName] || st.identShadowedInFunc(fn, "false") || bodyHasControlFlowOrRecoverBypass(fn.Body) || len(fn.Body.List) != 1 {
			continue
		}
		if ret, okR := fn.Body.List[0].(*ast.ReturnStmt); okR && len(ret.Results) == 1 {
			if rID, okID := unwrapParens(ret.Results[0]).(*ast.Ident); okID {
				if (rID.Name == "false" && pkgDeclCounts["false"] == 0) || (st.falseConsts[rID.Name] && !st.identShadowedInFunc(fn, rID.Name)) {
					st.osGateFuncs[gName] = ""
				}
			}
		}
	}

	// Discover generic/concrete atomic-spine state tables (e.g. struct holding an unexported atomic.Pointer[...] spine).
	allowedBasicFieldTypes := map[string]bool{
		"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
		"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true, "uintptr": true,
		"bool": true, "string": true, "byte": true,
	}
	isSafeNonSpineFieldType := func(sFile *ast.File, expr ast.Expr) bool {
		switch t := unwrapParens(expr).(type) {
		case *ast.ArrayType, *ast.MapType:
			return true
		case *ast.Ident:
			return allowedBasicFieldTypes[t.Name] && pkgDeclCounts[t.Name] == 0 && !fileImportNames[sFile][t.Name]
		case *ast.SelectorExpr:
			if t.Sel.Name != "Mutex" && t.Sel.Name != "RWMutex" {
				return false
			}
			_, okSync := isIdentNamed(t.X, "sync")
			return okSync && fileImportsSync[sFile] && !badSpecialImport[sFile]["sync"] && pkgDeclCounts["sync"] == 0
		default:
			return false
		}
	}
	tableStructs := map[string]*tableStructCand{}
	for sName, sp := range structSpecs {
		sFile := structFiles[sName]
		if pkgDeclCounts[sName] != 1 || pkgDeclCounts["atomic"] != 0 || !fileImportsAtomic[sFile] || badSpecialImport[sFile]["atomic"] {
			continue
		}
		stType, okST := unwrapParens(sp.Type).(*ast.StructType)
		if !okST || stType.Fields == nil {
			continue
		}
		var spineField string
		nonSpineFields := map[string]bool{}
		badStructField := false
		for _, fld := range stType.Fields.List {
			if len(fld.Names) == 0 {
				badStructField = true
				break
			}
			for _, id := range fld.Names {
				if id.Name == "" || id.Name == "_" || ast.IsExported(id.Name) {
					badStructField = true
					break
				}
			}
			if badStructField {
				break
			}
			isSpineType := false
			if idxExpr, okIdx := unwrapParens(fld.Type).(*ast.IndexExpr); okIdx {
				_, isSpineType = isSelectorBaseField(idxExpr.X, "atomic", "Pointer")
			}
			if isSpineType {
				if len(fld.Names) != 1 || spineField != "" {
					badStructField = true
					break
				}
				spineField = fld.Names[0].Name
			} else {
				if !isSafeNonSpineFieldType(sFile, fld.Type) {
					badStructField = true
					break
				}
				for _, id := range fld.Names {
					nonSpineFields[id.Name] = true
				}
			}
		}
		if badStructField || spineField == "" {
			continue
		}
		cand := &tableStructCand{
			name:           sName,
			spineField:     spineField,
			nonSpineFields: nonSpineFields,
			methods:        map[string]*ast.FuncDecl{},
			readNilMethods: map[string]bool{},
			mutatorMethods: map[string]bool{},
			valid:          true,
		}
		for _, f := range files {
			for _, decl := range f.Decls {
				fn, okF := decl.(*ast.FuncDecl)
				if !okF || fn.Recv == nil || len(fn.Recv.List) != 1 {
					continue
				}
				if recvBaseTypeName(fn.Recv.List[0].Type) != sName {
					continue
				}
				if fileImportNames[f][sName] {
					cand.valid = false
					break
				}
				_, isPtr := unwrapParens(fn.Recv.List[0].Type).(*ast.StarExpr)
				if !isPtr || fn.Body == nil || fn.Name == nil || osAnyLinknameLocals[fn.Name.Name] || cand.nonSpineFields[fn.Name.Name] || fn.Name.Name == spineField {
					cand.valid = false
					break
				}
				if _, dup := cand.methods[fn.Name.Name]; dup {
					cand.valid = false
					break
				}
				cand.methods[fn.Name.Name] = fn
			}
			if !cand.valid {
				break
			}
		}
		if !cand.valid || len(cand.methods) == 0 {
			continue
		}
		// Ensure spineField is accessed exclusively via pointer-receiver methods on sName using atomic Pointer methods,
		// and receiver pointers never escape or take field addresses.
		allowedSpineSels := map[*ast.SelectorExpr]bool{}
		methodCalleeMap := map[string]map[string]bool{}
		for mName, mFn := range cand.methods {
			mRecv := recvVarName(mFn)
			if mRecv == "" || pkgDeclCounts["nil"] != 0 || st.identShadowedInFunc(mFn, "nil") || bodyDeclaresAnyIdent(mFn.Body, map[string]bool{mRecv: true}) {
				cand.valid = false
				break
			}
			if mFn.Type != nil {
				for _, fl := range []*ast.FieldList{mFn.Type.TypeParams, mFn.Type.Params, mFn.Type.Results} {
					if fl == nil {
						continue
					}
					for _, fld := range fl.List {
						for _, id := range fld.Names {
							if id.Name == mRecv {
								cand.valid = false
							}
						}
					}
				}
			}
			if !cand.valid {
				break
			}
			allowedRecvIdents := map[*ast.Ident]bool{}
			methodCalleeMap[mName] = map[string]bool{}
			var mutatesSpine, badSpineUse bool
			ast.Inspect(mFn.Body, func(n ast.Node) bool {
				if badSpineUse || n == nil {
					return false
				}
				if u, okU := n.(*ast.UnaryExpr); okU && u.Op == token.AND {
					ast.Inspect(u.X, func(un ast.Node) bool {
						if id, okID := un.(*ast.Ident); okID && id.Name == mRecv {
							badSpineUse = true
							return false
						}
						return !badSpineUse
					})
					if badSpineUse {
						return false
					}
				}
				if sel, okS := n.(*ast.SelectorExpr); okS && cand.nonSpineFields[sel.Sel.Name] {
					if rID, okR := isIdentNamed(sel.X, mRecv); okR {
						allowedRecvIdents[rID] = true
					}
				}
				call, okC := n.(*ast.CallExpr)
				if !okC || call.Ellipsis.IsValid() {
					return true
				}
				opSel, okOS := unwrapParens(call.Fun).(*ast.SelectorExpr)
				if !okOS {
					return true
				}
				if rID, okRM := isIdentNamed(opSel.X, mRecv); okRM && cand.methods[opSel.Sel.Name] != nil {
					allowedRecvIdents[rID] = true
					methodCalleeMap[mName][opSel.Sel.Name] = true
					return true
				}
				spSel, okSS := unwrapParens(opSel.X).(*ast.SelectorExpr)
				if !okSS || spSel.Sel.Name != spineField {
					return true
				}
				rID, okR := isIdentNamed(spSel.X, mRecv)
				if !okR {
					badSpineUse = true
					return false
				}
				switch opSel.Sel.Name {
				case "Load":
					if len(call.Args) != 0 {
						badSpineUse = true
						return false
					}
					allowedSpineSels[spSel] = true
					allowedRecvIdents[rID] = true
				case "Store", "Swap":
					if len(call.Args) != 1 {
						badSpineUse = true
						return false
					}
					allowedSpineSels[spSel] = true
					allowedRecvIdents[rID] = true
					mutatesSpine = true
				case "CompareAndSwap":
					if len(call.Args) != 2 {
						badSpineUse = true
						return false
					}
					allowedSpineSels[spSel] = true
					allowedRecvIdents[rID] = true
					mutatesSpine = true
				default:
					badSpineUse = true
					return false
				}
				return true
			})
			if !badSpineUse {
				walkNonSelectorPropIdents(mFn.Body, func(id *ast.Ident) {
					if id.Name == mRecv && !allowedRecvIdents[id] {
						badSpineUse = true
					}
				})
			}
			if badSpineUse {
				cand.valid = false
				break
			}
			if mutatesSpine {
				cand.mutatorMethods[mName] = true
				continue
			}
			// Check whether read-only method returns nil immediately when spine.Load() == nil.
			if funcHasUnnamedResults(mFn.Type, 1) && !bodyHasControlFlowOrRecoverBypass(mFn.Body) && len(mFn.Body.List) >= 2 {
				as0, okA := mFn.Body.List[0].(*ast.AssignStmt)
				ifs1, okI := mFn.Body.List[1].(*ast.IfStmt)
				if okA && as0.Tok == token.DEFINE && len(as0.Lhs) == 1 && len(as0.Rhs) == 1 && okI && ifs1.Init == nil && ifs1.Else == nil && len(ifs1.Body.List) == 1 {
					vID, okV := unwrapParens(as0.Lhs[0]).(*ast.Ident)
					if okV && vID.Name != "" && vID.Name != "_" {
						if lCall, okLC := unwrapParens(as0.Rhs[0]).(*ast.CallExpr); okLC && !lCall.Ellipsis.IsValid() && len(lCall.Args) == 0 {
							if lSel, okLS := unwrapParens(lCall.Fun).(*ast.SelectorExpr); okLS && lSel.Sel.Name == "Load" {
								if _, okSP := isSelectorBaseField(lSel.X, mRecv, spineField); okSP {
									leftCond := ifs1.Cond
									for {
										orBin, okOr := unwrapParens(leftCond).(*ast.BinaryExpr)
										if !okOr || orBin.Op != token.LOR {
											break
										}
										leftCond = orBin.X
									}
									if condChecksEqErr(leftCond, vID.Name) {
										if rNil, okRN := ifs1.Body.List[0].(*ast.ReturnStmt); okRN && len(rNil.Results) == 1 {
											if _, okNil := isIdentNamed(rNil.Results[0], "nil"); okNil {
												cand.readNilMethods[mName] = true
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		if !cand.valid {
			continue
		}
		for {
			mProp := false
			for mName, callees := range methodCalleeMap {
				if cand.mutatorMethods[mName] {
					continue
				}
				for callee := range callees {
					if cand.mutatorMethods[callee] {
						cand.mutatorMethods[mName] = true
						delete(cand.readNilMethods, mName)
						mProp = true
						break
					}
				}
			}
			if !mProp {
				break
			}
		}
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				if !cand.valid || n == nil {
					return false
				}
				if sel, okS := n.(*ast.SelectorExpr); okS && sel.Sel.Name == spineField && !allowedSpineSels[sel] {
					cand.valid = false
					return false
				}
				return true
			})
		}
		if cand.valid {
			tableStructs[sName] = cand
		}
	}

	type mutCallSite struct {
		fn   *ast.FuncDecl
		call *ast.CallExpr
	}
	activeTables := map[string]tableVarCand{}
	mutSitesByTable := map[string][]mutCallSite{}
	for vName, vc := range varCands {
		ts := tableStructs[vc.structName]
		if ts == nil || pkgDeclCounts[vName] != 1 || osAnyLinknameLocals[vName] {
			continue
		}
		allowedIdents := map[*ast.Ident]bool{vc.declIdent: true}
		var sites []mutCallSite
		badUse := false
		for _, f := range files {
			if fileImportNames[f][vName] {
				badUse = true
				break
			}
			for _, decl := range f.Decls {
				fn, okF := decl.(*ast.FuncDecl)
				if !okF || fn.Body == nil {
					continue
				}
				if funcShadowsAnyIdent(fn, map[string]bool{vName: true}) {
					badUse = true
					break
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if badUse || n == nil {
						return false
					}
					if u, okU := n.(*ast.UnaryExpr); okU && u.Op == token.AND {
						ast.Inspect(u.X, func(un ast.Node) bool {
							if id, okID := un.(*ast.Ident); okID && id.Name == vName {
								badUse = true
								return false
							}
							return !badUse
						})
						if badUse {
							return false
						}
					}
					if sel, okS := n.(*ast.SelectorExpr); okS && ts.nonSpineFields[sel.Sel.Name] {
						if bID, okID := unwrapParens(sel.X).(*ast.Ident); okID && bID.Name == vName {
							allowedIdents[bID] = true
						}
					}
					call, okC := n.(*ast.CallExpr)
					if !okC || call.Ellipsis.IsValid() {
						return true
					}
					sel, okS := unwrapParens(call.Fun).(*ast.SelectorExpr)
					if !okS {
						return true
					}
					bID, okID := unwrapParens(sel.X).(*ast.Ident)
					if !okID || bID.Name != vName {
						return true
					}
					if ts.methods[sel.Sel.Name] == nil {
						badUse = true
						return false
					}
					if ts.mutatorMethods[sel.Sel.Name] {
						if fn.Recv == nil && fn.Name != nil && fn.Name.Name == "init" {
							badUse = true
							return false
						}
						sites = append(sites, mutCallSite{fn: fn, call: call})
					}
					allowedIdents[bID] = true
					return true
				})
				if badUse {
					break
				}
			}
			if badUse {
				break
			}
		}
		if !badUse && allNonSelPropIdentsIn(files, vName, allowedIdents) {
			activeTables[vName] = vc
			mutSitesByTable[vName] = sites
		}
	}

	pureIndexHelpers := map[string]bool{}
	for hName, fn := range topFuncs {
		if ast.IsExported(hName) || pkgDeclCounts[hName] != 1 || osAnyLinknameLocals[hName] || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || bodyHasControlFlowOrRecoverBypass(fn.Body) {
			continue
		}
		if !funcHasUnnamedResults(fn.Type, 2) || len(fn.Type.Results.List) != 2 {
			continue
		}
		r0ID, okR0 := unwrapParens(fn.Type.Results.List[0].Type).(*ast.Ident)
		_, okR1 := isIdentNamed(fn.Type.Results.List[1].Type, "bool")
		if !okR0 || !okR1 || !osAllowedPureIntConversions[r0ID.Name] || pkgDeclCounts[r0ID.Name] != 0 || st.identShadowedInFunc(fn, r0ID.Name) || pkgDeclCounts["bool"] != 0 || st.identShadowedInFunc(fn, "bool") {
			continue
		}
		hParams := paramNamesFlat(fn.Type.Params)
		if len(hParams) != 1 || hParams[0] == "" || hParams[0] == "_" {
			continue
		}
		hFile := funcFile[fn]

		var isParamFieldChain func(expr ast.Expr) bool
		isParamFieldChain = func(expr ast.Expr) bool {
			switch e := unwrapParens(expr).(type) {
			case *ast.Ident:
				return e.Name == hParams[0]
			case *ast.SelectorExpr:
				return isParamFieldChain(e.X)
			default:
				return false
			}
		}

		var isPureIdxExpr func(expr ast.Expr, scope map[string]bool) bool
		isPureIdxExpr = func(expr ast.Expr, scope map[string]bool) bool {
			if expr == nil {
				return false
			}
			switch x := unwrapParens(expr).(type) {
			case *ast.BasicLit:
				return true
			case *ast.Ident:
				if x.Name == hParams[0] || scope[x.Name] {
					return true
				}
				if x.Name == "true" || x.Name == "false" || x.Name == "nil" {
					return pkgDeclCounts[x.Name] == 0 && !st.identShadowedInFunc(fn, x.Name)
				}
				if constDeclNames[x.Name] && pkgDeclCounts[x.Name] == 1 && !osAnyLinknameLocals[x.Name] && !st.identShadowedInFunc(fn, x.Name) {
					return true
				}
				return false
			case *ast.SelectorExpr:
				return isParamFieldChain(x)
			case *ast.UnaryExpr:
				switch x.Op {
				case token.ADD, token.SUB, token.NOT, token.XOR:
					return isPureIdxExpr(x.X, scope)
				default:
					return false
				}
			case *ast.BinaryExpr:
				switch x.Op {
				case token.ADD, token.SUB, token.MUL, token.QUO, token.REM,
					token.AND, token.OR, token.XOR, token.AND_NOT, token.SHL, token.SHR,
					token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ,
					token.LAND, token.LOR:
					return isPureIdxExpr(x.X, scope) && isPureIdxExpr(x.Y, scope)
				default:
					return false
				}
			case *ast.CallExpr:
				if x.Ellipsis.IsValid() || len(x.Args) != 1 || !isPureIdxExpr(x.Args[0], scope) {
					return false
				}
				if cID, okID := unwrapParens(x.Fun).(*ast.Ident); okID {
					return osAllowedPureIntConversions[cID.Name] && pkgDeclCounts[cID.Name] == 0 && !st.identShadowedInFunc(fn, cID.Name) && !scope[cID.Name] && cID.Name != hParams[0]
				}
				if cSel, okS := unwrapParens(x.Fun).(*ast.SelectorExpr); okS {
					_, okU := isIdentNamed(cSel.X, "unsafe")
					if !okU || (cSel.Sel.Name != "Pointer" && cSel.Sel.Name != "Sizeof" && cSel.Sel.Name != "Alignof") {
						return false
					}
					return fileImportsUnsafe[hFile] && !badSpecialImport[hFile]["unsafe"] && pkgDeclCounts["unsafe"] == 0 && !funcShadowsAnyIdent(fn, map[string]bool{"unsafe": true}) && !scope["unsafe"] && hParams[0] != "unsafe"
				}
				return false
			default:
				return false
			}
		}

		isPureIdxAssign := func(as *ast.AssignStmt, scope map[string]bool) bool {
			if as == nil || len(as.Lhs) == 0 || len(as.Lhs) != len(as.Rhs) {
				return false
			}
			for _, rhs := range as.Rhs {
				if !isPureIdxExpr(rhs, scope) {
					return false
				}
			}
			switch as.Tok {
			case token.DEFINE:
				added := map[string]bool{}
				for _, lhs := range as.Lhs {
					id, okID := unwrapParens(lhs).(*ast.Ident)
					if !okID || id.Name == "" || id.Name == hParams[0] {
						return false
					}
					if id.Name == "_" {
						continue
					}
					if scope[id.Name] || added[id.Name] {
						return false
					}
					added[id.Name] = true
				}
				for name := range added {
					scope[name] = true
				}
				return true
			case token.ASSIGN, token.ADD_ASSIGN, token.SUB_ASSIGN, token.MUL_ASSIGN, token.QUO_ASSIGN, token.REM_ASSIGN,
				token.AND_ASSIGN, token.OR_ASSIGN, token.XOR_ASSIGN, token.SHL_ASSIGN, token.SHR_ASSIGN, token.AND_NOT_ASSIGN:
				for _, lhs := range as.Lhs {
					id, okID := unwrapParens(lhs).(*ast.Ident)
					if !okID || id.Name == "" || id.Name == hParams[0] {
						return false
					}
					if id.Name != "_" && !scope[id.Name] {
						return false
					}
				}
				return true
			default:
				return false
			}
		}

		var isPureIdxBlock func(stmts []ast.Stmt, parentScope map[string]bool) bool
		isPureIdxBlock = func(stmts []ast.Stmt, parentScope map[string]bool) bool {
			scope := maps.Clone(parentScope)
			for _, stmt := range stmts {
				switch s := stmt.(type) {
				case *ast.BlockStmt:
					if !isPureIdxBlock(s.List, scope) {
						return false
					}
				case *ast.ReturnStmt:
					if len(s.Results) != 2 || !isPureIdxExpr(s.Results[0], scope) || !isPureIdxExpr(s.Results[1], scope) {
						return false
					}
				case *ast.IfStmt:
					ifScope := maps.Clone(scope)
					if s.Init != nil {
						initAs, okA := s.Init.(*ast.AssignStmt)
						if !okA || initAs.Tok != token.DEFINE || !isPureIdxAssign(initAs, ifScope) {
							return false
						}
					}
					if !isPureIdxExpr(s.Cond, ifScope) || !isPureIdxBlock(s.Body.List, ifScope) {
						return false
					}
					if s.Else != nil {
						switch el := s.Else.(type) {
						case *ast.BlockStmt:
							if !isPureIdxBlock(el.List, ifScope) {
								return false
							}
						case *ast.IfStmt:
							if !isPureIdxBlock([]ast.Stmt{el}, ifScope) {
								return false
							}
						default:
							return false
						}
					}
				case *ast.DeclStmt:
					gd, okG := s.Decl.(*ast.GenDecl)
					if !okG || (gd.Tok != token.VAR && gd.Tok != token.CONST) {
						return false
					}
					for _, spec := range gd.Specs {
						vs, okV := spec.(*ast.ValueSpec)
						if !okV || len(vs.Names) == 0 || (len(vs.Values) != 0 && len(vs.Values) != len(vs.Names)) {
							return false
						}
						if gd.Tok == token.CONST && len(vs.Values) != len(vs.Names) {
							return false
						}
						if vs.Type != nil {
							tID, okT := unwrapParens(vs.Type).(*ast.Ident)
							if !okT || (!osAllowedPureIntConversions[tID.Name] && tID.Name != "bool") || pkgDeclCounts[tID.Name] != 0 || st.identShadowedInFunc(fn, tID.Name) || scope[tID.Name] || tID.Name == hParams[0] {
								return false
							}
						}
						for _, val := range vs.Values {
							if !isPureIdxExpr(val, scope) {
								return false
							}
						}
						added := map[string]bool{}
						for _, id := range vs.Names {
							if id.Name == "" || id.Name == hParams[0] {
								return false
							}
							if id.Name == "_" {
								continue
							}
							if scope[id.Name] || added[id.Name] {
								return false
							}
							added[id.Name] = true
						}
						for name := range added {
							scope[name] = true
						}
					}
				case *ast.AssignStmt:
					if !isPureIdxAssign(s, scope) {
						return false
					}
				default:
					return false
				}
			}
			return true
		}

		if isPureIdxBlock(fn.Body.List, map[string]bool{}) {
			pureIndexHelpers[hName] = true
		}
	}

	type depPair struct {
		gates map[string]bool
		tabs  map[string]bool
	}
	cloneDep := func(d depPair) depPair {
		out := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
		for g := range d.gates {
			if g != "" {
				out.gates[g] = true
			}
		}
		for t := range d.tabs {
			out.tabs[t] = true
		}
		return out
	}
	mergeDep := func(dst *depPair, src depPair) bool {
		changed := false
		for g := range src.gates {
			if g != "" && !dst.gates[g] {
				dst.gates[g] = true
				changed = true
			}
		}
		for t := range src.tabs {
			if !dst.tabs[t] {
				dst.tabs[t] = true
				changed = true
			}
		}
		return changed
	}

	funcParamSet := func(fn *ast.FuncDecl) map[string]bool {
		out := map[string]bool{}
		if fn == nil {
			return out
		}
		if r := recvVarName(fn); r != "" {
			out[r] = true
		}
		for _, p := range paramNamesFlat(fn.Type.Params) {
			if p != "" && p != "_" {
				out[p] = true
			}
		}
		return out
	}

	// Greatest fixpoint over activeTables: keep only tables whose mutator call sites are all gated/unreachable.
	var finalNilAcc, finalFalsePreds map[string]depPair
	var finalTableGates map[string]map[string]bool
	for {
		nilAcc := map[string]depPair{}
		falsePreds := map[string]depPair{}

		evalEnv := osFalseEvalEnv[depPair]{
			st: st,
			zeroDep: func() depPair {
				return depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
			},
			gateDep: func(rtGate string) depPair {
				d := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
				if rtGate != "" {
					d.gates[rtGate] = true
				}
				return d
			},
			falsePred: func(name string) (depPair, bool) {
				fp, okFP := falsePreds[name]
				if !okFP {
					return depPair{}, false
				}
				return cloneDep(fp), true
			},
			nilAccessor: func(name string) (depPair, bool) {
				na, okNA := nilAcc[name]
				if !okNA {
					return depPair{}, false
				}
				return cloneDep(na), true
			},
			merge: func(a, b depPair) depPair {
				out := cloneDep(a)
				mergeDep(&out, b)
				return out
			},
		}
		evalFalse := func(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) (depPair, bool) {
			return evalOSFalseExpr(evalEnv, expr, fn, params)
		}

		// Inner least fixpoint for nilAcc & falsePreds under current activeTables.
		for {
			innerChanged := false
			for fnName, fn := range topFuncs {
				if ast.IsExported(fnName) || pkgDeclCounts[fnName] != 1 || osAnyLinknameLocals[fnName] || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || bodyHasControlFlowOrRecoverBypass(fn.Body) {
					continue
				}
				pNames := paramNamesFlat(fn.Type.Params)
				if len(pNames) != 1 || pNames[0] == "" || pNames[0] == "_" || !funcHasUnnamedResults(fn.Type, 1) || len(fn.Type.Results.List) != 1 {
					continue
				}
				pSet := map[string]bool{pNames[0]: true}
				if _, isBoolRes := isIdentNamed(fn.Type.Results.List[0].Type, "bool"); isBoolRes {
					if pkgDeclCounts["bool"] != 0 || st.identShadowedInFunc(fn, "bool") {
						continue
					}
					if _, already := falsePreds[fnName]; already || len(fn.Body.List) != 1 || st.identShadowedInFunc(fn, "nil") || st.identShadowedInFunc(fn, "false") || st.identShadowedInFunc(fn, "true") {
						continue
					}
					if ret, okR := fn.Body.List[0].(*ast.ReturnStmt); okR && len(ret.Results) == 1 {
						if d, okF := evalFalse(ret.Results[0], fn, pSet); okF {
							falsePreds[fnName] = d
							innerChanged = true
						}
					}
					continue
				}
				if _, already := nilAcc[fnName]; already || pkgDeclCounts["nil"] != 0 || st.identShadowedInFunc(fn, "nil") || st.identShadowedInFunc(fn, "false") || st.identShadowedInFunc(fn, "true") {
					continue
				}
				fnFile := funcFile[fn]
				var proveBlockReturnsNil func(stmts []ast.Stmt, knownNil map[string]bool, declaredLocals map[string]bool, acc *depPair) bool
				proveBlockReturnsNil = func(stmts []ast.Stmt, knownNil map[string]bool, declaredLocals map[string]bool, acc *depPair) bool {
					for i := 0; i < len(stmts); i++ {
						switch s := stmts[i].(type) {
						case *ast.ReturnStmt:
							if len(s.Results) != 1 {
								return false
							}
							rID, okID := unwrapParens(s.Results[0]).(*ast.Ident)
							return okID && (rID.Name == "nil" || knownNil[rID.Name])
						case *ast.ExprStmt:
							kc, okKC := unwrapParens(s.X).(*ast.CallExpr)
							if !okKC || kc.Ellipsis.IsValid() || len(kc.Args) != 1 || !st.isPureChain(kc.Args[0], fn, pSet) {
								return false
							}
							if _, okKA := isSelectorBaseField(kc.Fun, "runtime", "KeepAlive"); !okKA {
								return false
							}
							if !fileImportsRuntime[fnFile] || badSpecialImport[fnFile]["runtime"] || pkgDeclCounts["runtime"] != 0 || funcShadowsAnyIdent(fn, map[string]bool{"runtime": true}) || declaredLocals["runtime"] {
								return false
							}
						case *ast.AssignStmt:
							if s.Tok == token.DEFINE && len(s.Lhs) == 1 && len(s.Rhs) == 1 {
								vID, okV := unwrapParens(s.Lhs[0]).(*ast.Ident)
								c, okC := unwrapParens(s.Rhs[0]).(*ast.CallExpr)
								if !okV || !okC || vID.Name == "" || vID.Name == "_" || declaredLocals[vID.Name] || c.Ellipsis.IsValid() || len(c.Args) != 1 {
									return false
								}
								if cID, okCID := unwrapParens(c.Fun).(*ast.Ident); okCID && !st.identShadowedInFunc(fn, cID.Name) && !declaredLocals[cID.Name] && st.isPureChain(c.Args[0], fn, pSet) {
									na, okNA := nilAcc[cID.Name]
									if !okNA {
										return false
									}
									mergeDep(acc, na)
									declaredLocals[vID.Name] = true
									knownNil[vID.Name] = true
									continue
								}
							}
							if s.Tok == token.DEFINE && len(s.Lhs) == 2 && len(s.Rhs) == 1 && i+2 < len(stmts) {
								idxID, okI0 := unwrapParens(s.Lhs[0]).(*ast.Ident)
								okVarID, okI1 := unwrapParens(s.Lhs[1]).(*ast.Ident)
								ic, okIC := unwrapParens(s.Rhs[0]).(*ast.CallExpr)
								if !okI0 || !okI1 || !okIC || idxID.Name == "" || idxID.Name == "_" || okVarID.Name == "" || okVarID.Name == "_" || idxID.Name == okVarID.Name || declaredLocals[idxID.Name] || declaredLocals[okVarID.Name] || ic.Ellipsis.IsValid() || len(ic.Args) != 1 || !st.isPureChain(ic.Args[0], fn, pSet) {
									return false
								}
								ihID, okIH := unwrapParens(ic.Fun).(*ast.Ident)
								if !okIH || !pureIndexHelpers[ihID.Name] || st.identShadowedInFunc(fn, ihID.Name) || declaredLocals[ihID.Name] {
									return false
								}
								guardIf, okGI := stmts[i+1].(*ast.IfStmt)
								getAs, okGA := stmts[i+2].(*ast.AssignStmt)
								if !okGI || guardIf.Init != nil || guardIf.Else != nil || len(guardIf.Body.List) != 1 || !okGA || getAs.Tok != token.DEFINE || len(getAs.Lhs) != 1 || len(getAs.Rhs) != 1 {
									return false
								}
								uNot, okUN := unwrapParens(guardIf.Cond).(*ast.UnaryExpr)
								gRet, okGR := guardIf.Body.List[0].(*ast.ReturnStmt)
								if !okUN || uNot.Op != token.NOT || !okGR || len(gRet.Results) != 1 {
									return false
								}
								_, okVarMatch := isIdentNamed(uNot.X, okVarID.Name)
								_, okRetNil := isIdentNamed(gRet.Results[0], "nil")
								if !okVarMatch || !okRetNil {
									return false
								}
								declaredLocals[idxID.Name] = true
								declaredLocals[okVarID.Name] = true
								sVarID, okSV := unwrapParens(getAs.Lhs[0]).(*ast.Ident)
								getCall, okGC := unwrapParens(getAs.Rhs[0]).(*ast.CallExpr)
								if !okSV || sVarID.Name == "" || sVarID.Name == "_" || declaredLocals[sVarID.Name] || !okGC || getCall.Ellipsis.IsValid() || len(getCall.Args) != 1 {
									return false
								}
								_, okIdxArg := isIdentNamed(getCall.Args[0], idxID.Name)
								getSel, okGS := unwrapParens(getCall.Fun).(*ast.SelectorExpr)
								if !okIdxArg || !okGS {
									return false
								}
								tabID, okTID := unwrapParens(getSel.X).(*ast.Ident)
								if !okTID || st.identShadowedInFunc(fn, tabID.Name) || declaredLocals[tabID.Name] {
									return false
								}
								vc, okTab := activeTables[tabID.Name]
								if !okTab || !tableStructs[vc.structName].readNilMethods[getSel.Sel.Name] {
									return false
								}
								acc.tabs[tabID.Name] = true
								declaredLocals[sVarID.Name] = true
								knownNil[sVarID.Name] = true
								i += 2
								continue
							}
							return false
						case *ast.IfStmt:
							if s.Else != nil {
								return false
							}
							if s.Init == nil {
								if d, okF := evalFalse(s.Cond, fn, pSet); okF {
									mergeDep(acc, d)
									continue
								}
								if nzVar := condChecksNonZeroErr(s.Cond); nzVar != "" && knownNil[nzVar] {
									continue
								}
								if condChecksEqErr(s.Cond, pNames[0]) && len(s.Body.List) == 1 {
									if r0, okR0 := s.Body.List[0].(*ast.ReturnStmt); okR0 && len(r0.Results) == 1 {
										if _, okN := isIdentNamed(r0.Results[0], "nil"); okN {
											continue
										}
									}
								}
								for kn := range knownNil {
									if condChecksEqErr(s.Cond, kn) {
										if proveBlockReturnsNil(s.Body.List, maps.Clone(knownNil), maps.Clone(declaredLocals), acc) {
											return true
										}
									}
								}
								return false
							}
							if initAs, okA := s.Init.(*ast.AssignStmt); okA && initAs.Tok == token.DEFINE && len(initAs.Lhs) == 1 && len(initAs.Rhs) == 1 {
								vID, okV := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
								c, okC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
								if okV && okC && vID.Name != "" && vID.Name != "_" && vID.Name != "nil" && condChecksNonZeroErr(s.Cond) == vID.Name && !c.Ellipsis.IsValid() && len(c.Args) == 1 && st.isPureChain(c.Args[0], fn, pSet) {
									if cID, okCID := unwrapParens(c.Fun).(*ast.Ident); okCID && !st.identShadowedInFunc(fn, cID.Name) && !declaredLocals[cID.Name] {
										if na, okNA := nilAcc[cID.Name]; okNA {
											mergeDep(acc, na)
											continue
										}
									}
								}
							}
							return false
						default:
							return false
						}
					}
					return false
				}
				acc := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
				if proveBlockReturnsNil(fn.Body.List, map[string]bool{}, map[string]bool{pNames[0]: true}, &acc) {
					nilAcc[fnName] = acc
					innerChanged = true
				}
			}
			if !innerChanged {
				break
			}
		}

		// Compute dead IfStmt branches & unreachableFuncs across files under (nilAcc, falsePreds).
		deadIfDeps := map[*ast.IfStmt]depPair{}
		for _, f := range files {
			for _, decl := range f.Decls {
				fn, okF := decl.(*ast.FuncDecl)
				if !okF || fn.Body == nil {
					continue
				}
				pSet := funcParamSet(fn)
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					ifs, okI := n.(*ast.IfStmt)
					if !okI {
						return true
					}
					if ifs.Init == nil && ifs.Else == nil && !bodyHasControlFlowOrRecoverBypass(ifs.Body) {
						if d, okF := evalFalse(ifs.Cond, fn, pSet); okF {
							deadIfDeps[ifs] = d
							return false
						}
					}
					return true
				})
			}
		}

		nodeDeadDep := func(fn *ast.FuncDecl, target ast.Node) (depPair, bool) {
			var found bool
			var out depPair
			var walk func(n ast.Node, cur *depPair)
			walk = func(n ast.Node, cur *depPair) {
				if found || n == nil {
					return
				}
				if n == target {
					if cur != nil {
						out = cloneDep(*cur)
						found = true
					}
					return
				}
				if ifs, okI := n.(*ast.IfStmt); okI {
					if d, okD := deadIfDeps[ifs]; okD {
						next := cloneDep(d)
						if cur != nil {
							mergeDep(&next, *cur)
						}
						for _, bs := range ifs.Body.List {
							walk(bs, &next)
						}
						return
					}
				}
				ast.Inspect(n, func(ch ast.Node) bool {
					if ch == n {
						return true
					}
					walk(ch, cur)
					return false
				})
			}
			walk(fn.Body, nil)
			return out, found
		}

		nodeContainsCall := func(root *ast.IfStmt, target *ast.CallExpr) bool {
			if root == nil || target == nil {
				return false
			}
			hit := false
			ast.Inspect(root, func(n ast.Node) bool {
				if n == target {
					hit = true
					return false
				}
				return !hit
			})
			return hit
		}

		unreachableFuncs := map[string]depPair{}
		seedRule1Head := map[string]*ast.IfStmt{}
		// Seed Rule 1: top-level concrete funcs whose first statement is `if !<falseCond> [|| ...] { return ... }`.
		for fnName, fn := range topFuncs {
			if pkgDeclCounts[fnName] != 1 || fn.Body == nil || len(fn.Body.List) == 0 {
				continue
			}
			ifs, okI := fn.Body.List[0].(*ast.IfStmt)
			if !okI || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 || bodyHasControlFlowOrRecoverBypass(ifs.Body) {
				continue
			}
			if _, okRet := ifs.Body.List[0].(*ast.ReturnStmt); !okRet {
				continue
			}
			negTarget := ifs.Cond
			for {
				orBin, okOr := unwrapParens(negTarget).(*ast.BinaryExpr)
				if !okOr || orBin.Op != token.LOR {
					break
				}
				negTarget = orBin.X
			}
			if uNot, okU := unwrapParens(negTarget).(*ast.UnaryExpr); okU && uNot.Op == token.NOT {
				if d, okF := evalFalse(uNot.X, fn, nil); okF {
					unreachableFuncs[fnName] = d
					seedRule1Head[fnName] = ifs
				}
			}
		}

		// Seed/iterate Rule 3: unexported non-linknamed top-level funcs called exclusively from deadIfDeps or unreachableFuncs.
		for {
			uChanged := false
			for fnName, fn := range topFuncs {
				if _, already := unreachableFuncs[fnName]; already || ast.IsExported(fnName) || pkgDeclCounts[fnName] != 1 || osAnyLinknameLocals[fnName] || fn.Body == nil {
					continue
				}
				allowedCallFunIdents := map[*ast.Ident]bool{fn.Name: true}
				agg := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
				allCovered := true
				for _, f := range files {
					if fileImportNames[f][fnName] {
						allCovered = false
						break
					}
					for _, decl := range f.Decls {
						caller, okF := decl.(*ast.FuncDecl)
						if !okF || caller.Body == nil {
							continue
						}
						callerUnreach, isCallerUnreach := unreachableFuncs[caller.Name.Name]
						callerHead := seedRule1Head[caller.Name.Name]
						if caller.Recv != nil {
							isCallerUnreach = false
							callerHead = nil
						}
						ast.Inspect(caller.Body, func(n ast.Node) bool {
							if !allCovered || n == nil {
								return false
							}
							call, okC := n.(*ast.CallExpr)
							if !okC {
								return true
							}
							cID, okID := unwrapParens(call.Fun).(*ast.Ident)
							if !okID || cID.Name != fnName {
								return true
							}
							if isCallerUnreach && !nodeContainsCall(callerHead, call) {
								allowedCallFunIdents[cID] = true
								mergeDep(&agg, callerUnreach)
								return true
							}
							if dDead, okD := nodeDeadDep(caller, call); okD {
								allowedCallFunIdents[cID] = true
								mergeDep(&agg, dDead)
								return true
							}
							allCovered = false
							return false
						})
						if !allCovered {
							break
						}
					}
					if !allCovered {
						break
					}
				}
				if allCovered && allNonSelPropIdentsIn(files, fnName, allowedCallFunIdents) {
					unreachableFuncs[fnName] = agg
					uChanged = true
				}
			}
			if !uChanged {
				break
			}
		}

		evicted := false
		curTableDeps := map[string]depPair{}
		for vName := range activeTables {
			agg := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
			covered := true
			for _, site := range mutSitesByTable[vName] {
				if site.fn.Recv == nil {
					if uDep, okU := unreachableFuncs[site.fn.Name.Name]; okU && !nodeContainsCall(seedRule1Head[site.fn.Name.Name], site.call) {
						mergeDep(&agg, uDep)
						continue
					}
				}
				if dDead, okD := nodeDeadDep(site.fn, site.call); okD {
					mergeDep(&agg, dDead)
					continue
				}
				covered = false
				break
			}
			if !covered {
				delete(activeTables, vName)
				evicted = true
				continue
			}
			curTableDeps[vName] = agg
		}
		if evicted {
			continue
		}

		// Propagate table-to-table dependencies to fixpoint and finalize gate sets.
		for {
			tChanged := false
			for vName, dp := range curTableDeps {
				for depTab := range dp.tabs {
					if other, okO := curTableDeps[depTab]; okO {
						for g := range other.gates {
							if !dp.gates[g] {
								dp.gates[g] = true
								tChanged = true
							}
						}
					}
				}
				curTableDeps[vName] = dp
			}
			if !tChanged {
				break
			}
		}
		finalTableGates = map[string]map[string]bool{}
		for vName, dp := range curTableDeps {
			finalTableGates[vName] = dp.gates
		}
		finalNilAcc = nilAcc
		finalFalsePreds = falsePreds
		break
	}

	resolveDepGates := func(dp depPair) []string {
		merged := map[string]bool{}
		for g := range dp.gates {
			if g != "" {
				merged[g] = true
			}
		}
		for t := range dp.tabs {
			for g := range finalTableGates[t] {
				if g != "" {
					merged[g] = true
				}
			}
		}
		out := sortedKeys(merged)
		if out == nil {
			out = make([]string, 0)
		}
		return out
	}

	for name, dp := range finalNilAcc {
		st.nilAccessors[name] = resolveDepGates(dp)
	}
	for name, dp := range finalFalsePreds {
		st.falsePreds[name] = resolveDepGates(dp)
	}

	// Discover unexported false-handled tuple helpers (e.g. `if ..., handled, ... := h(...); handled`).
	paramsOrResultsShadow := func(fn *ast.FuncDecl, names map[string]bool) bool {
		if fn == nil || fn.Type == nil {
			return false
		}
		for _, fl := range []*ast.FieldList{fn.Recv, fn.Type.TypeParams, fn.Type.Params, fn.Type.Results} {
			if fl == nil {
				continue
			}
			for _, fld := range fl.List {
				for _, id := range fld.Names {
					if names[id.Name] {
						return true
					}
				}
			}
		}
		return false
	}
	identShadowedAtHead := func(fn *ast.FuncDecl, name string) bool {
		return paramsOrResultsShadow(fn, map[string]bool{name: true}) || fileImportNames[funcFile[fn]][name]
	}
	isPureZeroResult := func(fn *ast.FuncDecl, expr ast.Expr) bool {
		expr = unwrapParens(expr)
		if id, okID := expr.(*ast.Ident); okID {
			if (id.Name == "nil" || id.Name == "false") && pkgDeclCounts[id.Name] == 0 && !identShadowedAtHead(fn, id.Name) {
				return true
			}
			if st.falseConsts[id.Name] && !identShadowedAtHead(fn, id.Name) {
				return true
			}
			return false
		}
		if isZeroIntLit(expr) {
			return true
		}
		if lit, okL := expr.(*ast.BasicLit); okL && lit.Kind == token.STRING && lit.Value == `""` {
			return true
		}
		return false
	}
	for hName, fn := range topFuncs {
		if ast.IsExported(hName) || pkgDeclCounts[hName] != 1 || osAnyLinknameLocals[hName] || fn.Body == nil || len(fn.Body.List) == 0 || fn.Type == nil || fn.Type.TypeParams != nil || fn.Type.Results == nil {
			continue
		}
		numRes := fn.Type.Results.NumFields()
		if numRes < 2 || pkgDeclCounts["false"] != 0 || pkgDeclCounts["bool"] != 0 || identShadowedAtHead(fn, "false") || identShadowedAtHead(fn, "nil") || identShadowedAtHead(fn, "bool") {
			continue
		}
		checkRetTuple := func(ret *ast.ReturnStmt, gates []string) {
			if len(ret.Results) != numRes {
				return
			}
			for idx, r := range ret.Results {
				rID, okID := unwrapParens(r).(*ast.Ident)
				if !okID || (rID.Name != "false" && (!st.falseConsts[rID.Name] || identShadowedAtHead(fn, rID.Name))) {
					continue
				}
				if _, okBool := isIdentNamed(funcResultFieldTypeAt(fn.Type.Results, idx), "bool"); !okBool {
					continue
				}
				othersZero := true
				for j, other := range ret.Results {
					if j != idx && !isPureZeroResult(fn, other) {
						othersZero = false
						break
					}
				}
				if othersZero {
					st.falseHandledHelpers[osFalseHelperKey{name: hName, arity: len(ret.Results), boolIdx: idx}] = gates
				}
			}
		}
		switch s0 := fn.Body.List[0].(type) {
		case *ast.ReturnStmt:
			checkRetTuple(s0, make([]string, 0))
		case *ast.IfStmt:
			if s0.Init == nil && s0.Else == nil && len(s0.Body.List) == 1 && !bodyHasControlFlowOrRecoverBypass(s0.Body) {
				if ret, okR := s0.Body.List[0].(*ast.ReturnStmt); okR {
					if uNot, okU := unwrapParens(s0.Cond).(*ast.UnaryExpr); okU && uNot.Op == token.NOT {
						if gates, okG := st.evalFalseCond(uNot.X, fn, nil); okG {
							checkRetTuple(ret, gates)
						}
					}
				}
			}
		}
	}

	return st
}

func (s *osInactiveState) isPureChain(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) bool {
	if s == nil {
		return false
	}
	switch x := unwrapParens(expr).(type) {
	case *ast.Ident:
		return params[x.Name]
	case *ast.SelectorExpr:
		return s.isPureChain(x.X, fn, params)
	case *ast.UnaryExpr:
		return x.Op == token.AND && s.isPureChain(x.X, fn, params)
	case *ast.CallExpr:
		if x.Ellipsis.IsValid() || len(x.Args) != 1 {
			return false
		}
		cID, okID := unwrapParens(x.Fun).(*ast.Ident)
		if !okID || !osAllowedPureIntConversions[cID.Name] {
			return false
		}
		if s.pkgDeclCounts[cID.Name] != 0 || s.identShadowedInFunc(fn, cID.Name) {
			return false
		}
		return s.isPureChain(x.Args[0], fn, params)
	default:
		return false
	}
}

func (s *osInactiveState) isPureArg(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) bool {
	if s == nil {
		return false
	}
	if s.isPureChain(expr, fn, params) {
		return true
	}
	switch x := unwrapParens(expr).(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		if x.Name == "true" || x.Name == "false" || x.Name == "nil" {
			return s.pkgDeclCounts[x.Name] == 0 && !s.identShadowedInFunc(fn, x.Name)
		}
		if s.trueConsts[x.Name] || s.falseConsts[x.Name] {
			return !s.identShadowedInFunc(fn, x.Name)
		}
	}
	return false
}

func (s *osInactiveState) isPureGuardExpr(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) bool {
	if s == nil {
		return false
	}
	if s.isPureChain(expr, fn, params) {
		return true
	}
	switch x := unwrapParens(expr).(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		if x.Name == "nil" || x.Name == "true" || x.Name == "false" {
			return s.pkgDeclCounts[x.Name] == 0 && !s.identShadowedInFunc(fn, x.Name)
		}
		if s.trueConsts[x.Name] || s.falseConsts[x.Name] {
			return !s.identShadowedInFunc(fn, x.Name)
		}
	case *ast.UnaryExpr:
		return x.Op == token.NOT && s.isPureGuardExpr(x.X, fn, params)
	case *ast.BinaryExpr:
		switch x.Op {
		case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ, token.LAND, token.LOR:
			return s.isPureGuardExpr(x.X, fn, params) && s.isPureGuardExpr(x.Y, fn, params)
		}
	}
	return false
}

func (s *osInactiveState) evalFalseCond(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) ([]string, bool) {
	if s == nil {
		return nil, false
	}
	env := osFalseEvalEnv[[]string]{
		st: s,
		zeroDep: func() []string {
			return make([]string, 0)
		},
		gateDep: func(rtGate string) []string {
			if rtGate == "" {
				return make([]string, 0)
			}
			return []string{rtGate}
		},
		falsePred: func(name string) ([]string, bool) {
			gates, okFP := s.falsePreds[name]
			if !okFP {
				return nil, false
			}
			return slices.Clone(gates), true
		},
		nilAccessor: func(name string) ([]string, bool) {
			gates, okNA := s.nilAccessors[name]
			if !okNA {
				return nil, false
			}
			return slices.Clone(gates), true
		},
		merge: func(gL, gR []string) []string {
			merged := map[string]bool{}
			for _, g := range gL {
				merged[g] = true
			}
			for _, g := range gR {
				merged[g] = true
			}
			out := sortedKeys(merged)
			if out == nil {
				out = make([]string, 0)
			}
			return out
		},
	}
	return evalOSFalseExpr(env, expr, fn, params)
}

func (s *osInactiveState) checkInactiveHookIf(stmt ast.Stmt, fn *ast.FuncDecl) ([]string, bool) {
	if s == nil || fn == nil {
		return nil, false
	}
	ifs, ok := stmt.(*ast.IfStmt)
	if !ok || ifs.Else != nil {
		return nil, false
	}
	params := map[string]bool{}
	if r := recvVarName(fn); r != "" {
		params[r] = true
	}
	for _, p := range paramNamesFlat(fn.Type.Params) {
		if p != "" && p != "_" {
			params[p] = true
		}
	}
	checkInitHook := func(inner *ast.IfStmt) ([]string, bool) {
		initAs, okA := inner.Init.(*ast.AssignStmt)
		if !okA || initAs.Tok != token.DEFINE || len(initAs.Rhs) != 1 {
			return nil, false
		}
		call, okC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
		if !okC || call.Ellipsis.IsValid() {
			return nil, false
		}
		calleeID, okFun := unwrapParens(call.Fun).(*ast.Ident)
		if !okFun || s.identShadowedInFunc(fn, calleeID.Name) {
			return nil, false
		}
		for _, arg := range call.Args {
			if !s.isPureArg(arg, fn, params) {
				return nil, false
			}
		}
		if len(initAs.Lhs) == 1 && len(call.Args) == 1 {
			vID, okV := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
			if !okV || vID.Name == "" || vID.Name == "_" || vID.Name == "nil" || s.pkgDeclCounts["nil"] != 0 || s.identShadowedInFunc(fn, "nil") || condChecksNonZeroErr(inner.Cond) != vID.Name {
				return nil, false
			}
			if gates, okNA := s.nilAccessors[calleeID.Name]; okNA {
				return slices.Clone(gates), true
			}
			return nil, false
		}
		if len(initAs.Lhs) >= 2 {
			cID, okCond := unwrapParens(inner.Cond).(*ast.Ident)
			if !okCond || cID.Name == "" || cID.Name == "_" {
				return nil, false
			}
			boolIdx := -1
			for idx, lhs := range initAs.Lhs {
				lID, okL := unwrapParens(lhs).(*ast.Ident)
				if !okL || lID.Name == "" {
					return nil, false
				}
				if lID.Name == cID.Name {
					if boolIdx >= 0 {
						return nil, false
					}
					boolIdx = idx
				}
			}
			if boolIdx >= 0 {
				if gates, okH := s.falseHandledHelpers[osFalseHelperKey{name: calleeID.Name, arity: len(initAs.Lhs), boolIdx: boolIdx}]; okH {
					return slices.Clone(gates), true
				}
			}
		}
		return nil, false
	}
	if ifs.Init != nil {
		return checkInitHook(ifs)
	}
	if gates, okF := s.evalFalseCond(ifs.Cond, fn, params); okF {
		return gates, true
	}
	condID, okCID := unwrapParens(ifs.Cond).(*ast.Ident)
	if !okCID || (!s.trueConsts[condID.Name] && !(condID.Name == "true" && s.pkgDeclCounts["true"] == 0)) || s.identShadowedInFunc(fn, condID.Name) || len(ifs.Body.List) != 1 {
		return nil, false
	}
	inner, okIn := ifs.Body.List[0].(*ast.IfStmt)
	if !okIn || inner.Else != nil {
		return nil, false
	}
	if inner.Init == nil {
		return s.evalFalseCond(inner.Cond, fn, params)
	}
	return checkInitHook(inner)
}

func exprReferencesDiscard(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.Ident:
			if x.Name == "Discard" {
				found = true
				return false
			}
		case *ast.SelectorExpr:
			if x.Sel.Name == "Discard" {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func walkNonSelectorPropIdents(root ast.Node, fn func(*ast.Ident)) {
	var walk func(n ast.Node)
	walk = func(n ast.Node) {
		if n == nil {
			return
		}
		switch node := n.(type) {
		case *ast.SelectorExpr:
			walk(node.X)
		case *ast.KeyValueExpr:
			walk(node.Value)
		case *ast.StructType:
			if node.Fields != nil {
				for _, field := range node.Fields.List {
					walk(field.Type)
				}
			}
		case *ast.InterfaceType:
			if node.Methods != nil {
				for _, field := range node.Methods.List {
					walk(field.Type)
				}
			}
		case *ast.Ident:
			fn(node)
		default:
			ast.Inspect(node, func(ch ast.Node) bool {
				if ch == node {
					return true
				}
				walk(ch)
				return false
			})
		}
	}
	walk(root)
}

func isIdentNamed(expr ast.Expr, name string) (*ast.Ident, bool) {
	id, ok := unwrapParens(expr).(*ast.Ident)
	return id, ok && id.Name == name
}

func isSelectorBaseField(expr ast.Expr, base, field string) (*ast.Ident, bool) {
	sel, ok := unwrapParens(expr).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != field {
		return nil, false
	}
	id, ok := isIdentNamed(sel.X, base)
	return id, ok
}

func isZeroArgMethodCallOnSelector(expr ast.Expr, base, field, method string) (*ast.Ident, bool) {
	call, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 0 {
		return nil, false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != method {
		return nil, false
	}
	return isSelectorBaseField(sel.X, base, field)
}

func isZeroArgMethodCallOnIdent(expr ast.Expr, base, method string) (*ast.Ident, bool) {
	call, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 0 {
		return nil, false
	}
	return isSelectorBaseField(call.Fun, base, method)
}

func verifyBufioWriterAST(files []*ast.File) error {
	reserved := map[string]bool{
		"io": true, "copy": true, "len": true, "make": true,
		"byte": true, "int": true, "string": true, "error": true,
		"nil": true, "true": true, "false": true,
	}
	var writerSpecs []*ast.TypeSpec
	constPosInt := map[string]bool{}
	topFuncs := map[string]*ast.FuncDecl{}
	dupTopFuncs := map[string]bool{}
	writerMethods := map[string]*ast.FuncDecl{}
	dupWriterMethods := false

	for _, f := range files {
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			if imp.Name != nil && (imp.Name.Name == "." || reserved[imp.Name.Name]) {
				return fmt.Errorf("bufio: shadowing or dot import %q", imp.Name.Name)
			}
			if path == "io" && imp.Name != nil {
				return fmt.Errorf("bufio: aliased import of io forbidden")
			}
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.TypeSpec:
						if sp.Name != nil && reserved[sp.Name.Name] {
							return fmt.Errorf("bufio: type shadows %s", sp.Name.Name)
						}
						if sp.Name != nil && sp.Name.Name == "Writer" {
							writerSpecs = append(writerSpecs, sp)
						}
					case *ast.ValueSpec:
						for i, id := range sp.Names {
							if reserved[id.Name] {
								return fmt.Errorf("bufio: declaration shadows %s", id.Name)
							}
							if d.Tok == token.CONST && i < len(sp.Values) && isPositiveIntLit(sp.Values[i]) {
								constPosInt[id.Name] = true
							}
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil {
					if reserved[d.Name.Name] {
						return fmt.Errorf("bufio: function shadows %s", d.Name.Name)
					}
					if d.Name.Name != "init" && d.Name.Name != "_" {
						if _, dup := topFuncs[d.Name.Name]; dup {
							dupTopFuncs[d.Name.Name] = true
						}
						topFuncs[d.Name.Name] = d
					}
				} else if len(d.Recv.List) == 1 && recvTypeName(d.Recv.List[0].Type) == "Writer" {
					if _, dup := writerMethods[d.Name.Name]; dup {
						dupWriterMethods = true
					}
					writerMethods[d.Name.Name] = d
				}
			}
		}
	}
	if len(writerSpecs) != 1 || dupWriterMethods {
		return fmt.Errorf("bufio: missing or duplicate Writer type/methods")
	}
	for dup := range dupTopFuncs {
		delete(topFuncs, dup)
	}

	ws := writerSpecs[0]
	if ws.Assign.IsValid() || ws.TypeParams != nil {
		return fmt.Errorf("bufio: invalid Writer type declaration")
	}
	wst, ok := unwrapParens(ws.Type).(*ast.StructType)
	if !ok || wst.Fields == nil {
		return fmt.Errorf("bufio: Writer is not a struct")
	}
	fieldTypes := map[string]ast.Expr{}
	for _, fld := range wst.Fields.List {
		if len(fld.Names) == 0 {
			return fmt.Errorf("bufio: embedded field on Writer")
		}
		for _, id := range fld.Names {
			fieldTypes[id.Name] = fld.Type
		}
	}
	if len(fieldTypes) != 4 {
		return fmt.Errorf("bufio: unexpected Writer field set")
	}
	if _, ok := isIdentNamed(fieldTypes["err"], "error"); !ok {
		return fmt.Errorf("bufio: Writer.err is not error")
	}
	if !isByteSliceType(fieldTypes["buf"]) {
		return fmt.Errorf("bufio: Writer.buf is not []byte")
	}
	if _, ok := isIdentNamed(fieldTypes["n"], "int"); !ok {
		return fmt.Errorf("bufio: Writer.n is not int")
	}
	if _, ok := isSelectorBaseField(fieldTypes["wr"], "io", "Writer"); !ok {
		return fmt.Errorf("bufio: Writer.wr is not io.Writer")
	}

	// Verify NewWriter and NewWriterSize construct a Writer bound to w with positive buffer capacity.
	nw := topFuncs["NewWriter"]
	nws := topFuncs["NewWriterSize"]
	if nw == nil || nw.Body == nil || nws == nil || nws.Body == nil || funcShadowsAnyIdent(nw, reserved) || funcShadowsAnyIdent(nws, reserved) {
		return fmt.Errorf("bufio: missing NewWriter or NewWriterSize")
	}
	nwParams := paramNamesFlat(nw.Type.Params)
	if len(nwParams) != 1 || nwParams[0] == "" || nwParams[0] == "_" || len(nw.Body.List) != 1 {
		return fmt.Errorf("bufio: unexpected NewWriter shape")
	}
	nwRet, ok := nw.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(nwRet.Results) != 1 {
		return fmt.Errorf("bufio: unexpected NewWriter return")
	}
	nwCall, ok := unwrapParens(nwRet.Results[0]).(*ast.CallExpr)
	if !ok || nwCall.Ellipsis.IsValid() || len(nwCall.Args) != 2 {
		return fmt.Errorf("bufio: unexpected NewWriter delegation")
	}
	if _, ok := isIdentNamed(nwCall.Fun, "NewWriterSize"); !ok {
		return fmt.Errorf("bufio: NewWriter does not call NewWriterSize")
	}
	if _, ok := isIdentNamed(nwCall.Args[0], nwParams[0]); !ok {
		return fmt.Errorf("bufio: NewWriter does not forward w")
	}
	if !isPositiveIntLit(nwCall.Args[1]) {
		if cID, ok := unwrapParens(nwCall.Args[1]).(*ast.Ident); !ok || !constPosInt[cID.Name] {
			return fmt.Errorf("bufio: NewWriter size argument is not a positive constant")
		}
	}

	nwsParams := paramNamesFlat(nws.Type.Params)
	if len(nwsParams) != 2 || nwsParams[0] == "" || nwsParams[0] == "_" || nwsParams[1] == "" || nwsParams[1] == "_" || len(nws.Body.List) < 2 {
		return fmt.Errorf("bufio: unexpected NewWriterSize shape")
	}
	wParam, sizeParam := nwsParams[0], nwsParams[1]
	if bodyMutatesOrTakesAddrOfAny(nws.Body, map[string]bool{wParam: true}) {
		return fmt.Errorf("bufio: NewWriterSize mutates w")
	}
	nwsPos := 0
	if len(nws.Body.List) == 4 {
		// Optional pass-through: b, ok := w.(*Writer); if ok && len(b.buf) >= size { return b }
		taAssign, ok1 := nws.Body.List[0].(*ast.AssignStmt)
		taIf, ok2 := nws.Body.List[1].(*ast.IfStmt)
		if !ok1 || !ok2 || taAssign.Tok != token.DEFINE || len(taAssign.Lhs) != 2 || len(taAssign.Rhs) != 1 || taIf.Init != nil || taIf.Else != nil || len(taIf.Body.List) != 1 {
			return fmt.Errorf("bufio: NewWriterSize invalid Writer pass-through")
		}
		bID, okB := unwrapParens(taAssign.Lhs[0]).(*ast.Ident)
		okID, okOK := unwrapParens(taAssign.Lhs[1]).(*ast.Ident)
		ta, okTA := unwrapParens(taAssign.Rhs[0]).(*ast.TypeAssertExpr)
		if !okB || !okOK || !okTA || bID.Name == "" || bID.Name == "_" || okID.Name == "" || okID.Name == "_" || ta.Type == nil {
			return fmt.Errorf("bufio: NewWriterSize invalid Writer type assertion")
		}
		if _, ok := isIdentNamed(ta.X, wParam); !ok {
			return fmt.Errorf("bufio: NewWriterSize type assertion not on w")
		}
		starW, ok := unwrapParens(ta.Type).(*ast.StarExpr)
		if !ok {
			return fmt.Errorf("bufio: NewWriterSize type assertion not *Writer")
		}
		if _, ok := isIdentNamed(starW.X, "Writer"); !ok {
			return fmt.Errorf("bufio: NewWriterSize type assertion target not Writer")
		}
		andCond, ok := unwrapParens(taIf.Cond).(*ast.BinaryExpr)
		if !ok || andCond.Op != token.LAND {
			return fmt.Errorf("bufio: NewWriterSize pass-through condition not &&")
		}
		if _, ok := isIdentNamed(andCond.X, okID.Name); !ok {
			return fmt.Errorf("bufio: NewWriterSize pass-through LHS not ok")
		}
		geqCond, ok := unwrapParens(andCond.Y).(*ast.BinaryExpr)
		if !ok || geqCond.Op != token.GEQ {
			return fmt.Errorf("bufio: NewWriterSize pass-through capacity check not >=")
		}
		lenCall, ok := unwrapParens(geqCond.X).(*ast.CallExpr)
		if !ok || lenCall.Ellipsis.IsValid() || len(lenCall.Args) != 1 {
			return fmt.Errorf("bufio: NewWriterSize pass-through missing len(b.buf)")
		}
		if _, ok := isIdentNamed(lenCall.Fun, "len"); !ok {
			return fmt.Errorf("bufio: NewWriterSize pass-through not calling len")
		}
		if _, ok := isSelectorBaseField(lenCall.Args[0], bID.Name, "buf"); !ok {
			return fmt.Errorf("bufio: NewWriterSize pass-through len arg not b.buf")
		}
		if _, ok := isIdentNamed(geqCond.Y, sizeParam); !ok {
			return fmt.Errorf("bufio: NewWriterSize pass-through RHS not size")
		}
		ptRet, ok := taIf.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ptRet.Results) != 1 {
			return fmt.Errorf("bufio: NewWriterSize pass-through invalid return")
		}
		if _, ok := isIdentNamed(ptRet.Results[0], bID.Name); !ok {
			return fmt.Errorf("bufio: NewWriterSize pass-through does not return b")
		}
		nwsPos = 2
	} else if len(nws.Body.List) != 2 {
		return fmt.Errorf("bufio: NewWriterSize unexpected statement count")
	}
	// Mandatory size clamp: if size <= 0 { size = <posConstOrLit> }
	if sizeIf, ok := nws.Body.List[nwsPos].(*ast.IfStmt); !ok || sizeIf.Init != nil || sizeIf.Else != nil || len(sizeIf.Body.List) != 1 {
		return fmt.Errorf("bufio: NewWriterSize missing size <= 0 clamp")
	} else {
		leCond, ok := unwrapParens(sizeIf.Cond).(*ast.BinaryExpr)
		if !ok || leCond.Op != token.LEQ || !isZeroIntLit(leCond.Y) {
			return fmt.Errorf("bufio: NewWriterSize size clamp condition invalid")
		}
		if _, ok := isIdentNamed(leCond.X, sizeParam); !ok {
			return fmt.Errorf("bufio: NewWriterSize size clamp LHS not size")
		}
		clampAs, ok := sizeIf.Body.List[0].(*ast.AssignStmt)
		if !ok || clampAs.Tok != token.ASSIGN || len(clampAs.Lhs) != 1 || len(clampAs.Rhs) != 1 {
			return fmt.Errorf("bufio: NewWriterSize size clamp assignment invalid")
		}
		if _, ok := isIdentNamed(clampAs.Lhs[0], sizeParam); !ok {
			return fmt.Errorf("bufio: NewWriterSize size clamp target not size")
		}
		if !isPositiveIntLit(clampAs.Rhs[0]) {
			if cID, ok := unwrapParens(clampAs.Rhs[0]).(*ast.Ident); !ok || !constPosInt[cID.Name] {
				return fmt.Errorf("bufio: NewWriterSize default size is not positive")
			}
		}
	}
	nwsRet, ok := nws.Body.List[nwsPos+1].(*ast.ReturnStmt)
	if !ok || len(nwsRet.Results) != 1 {
		return fmt.Errorf("bufio: NewWriterSize missing final return")
	}
	lit, litName := compositeWriterLit(nwsRet.Results[0])
	if lit == nil || litName != "Writer" || len(lit.Elts) != 2 {
		return fmt.Errorf("bufio: NewWriterSize final return is not &Writer{buf, wr}")
	}
	var sawBufMake, sawWrBind bool
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return fmt.Errorf("bufio: NewWriterSize unkeyed Writer literal")
		}
		kID, ok := unwrapParens(kv.Key).(*ast.Ident)
		if !ok {
			return fmt.Errorf("bufio: NewWriterSize invalid key")
		}
		switch kID.Name {
		case "wr":
			if _, ok := isIdentNamed(kv.Value, wParam); !ok {
				return fmt.Errorf("bufio: NewWriterSize wr does not bind w")
			}
			sawWrBind = true
		case "buf":
			mc, ok := unwrapParens(kv.Value).(*ast.CallExpr)
			if !ok || mc.Ellipsis.IsValid() || len(mc.Args) != 2 || !isByteSliceType(mc.Args[0]) {
				return fmt.Errorf("bufio: NewWriterSize buf is not make([]byte, size)")
			}
			if _, ok := isIdentNamed(mc.Fun, "make"); !ok {
				return fmt.Errorf("bufio: NewWriterSize buf is not make")
			}
			if _, ok := isIdentNamed(mc.Args[1], sizeParam); !ok {
				return fmt.Errorf("bufio: NewWriterSize buf size mismatch")
			}
			sawBufMake = true
		}
	}
	if !sawBufMake || !sawWrBind {
		return fmt.Errorf("bufio: NewWriterSize incomplete Writer initialization")
	}

	// Verify Available() and Buffered().
	availFn := writerMethods["Available"]
	bufdFn := writerMethods["Buffered"]
	if availFn == nil || availFn.Body == nil || len(availFn.Body.List) != 1 || bufdFn == nil || bufdFn.Body == nil || len(bufdFn.Body.List) != 1 {
		return fmt.Errorf("bufio: missing Available or Buffered")
	}
	if avRecv := recvVarName(availFn); avRecv == "" {
		return fmt.Errorf("bufio: unnamed Available receiver")
	} else {
		ret, ok := availFn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return fmt.Errorf("bufio: invalid Available return")
		}
		bin, ok := unwrapParens(ret.Results[0]).(*ast.BinaryExpr)
		if !ok || bin.Op != token.SUB {
			return fmt.Errorf("bufio: Available does not compute len(buf) - n")
		}
		lc, ok := unwrapParens(bin.X).(*ast.CallExpr)
		if !ok || len(lc.Args) != 1 || lc.Ellipsis.IsValid() {
			return fmt.Errorf("bufio: Available invalid len call")
		}
		if _, ok := isIdentNamed(lc.Fun, "len"); !ok {
			return fmt.Errorf("bufio: Available not calling len")
		}
		if _, ok := isSelectorBaseField(lc.Args[0], avRecv, "buf"); !ok {
			return fmt.Errorf("bufio: Available len target not b.buf")
		}
		if _, ok := isSelectorBaseField(bin.Y, avRecv, "n"); !ok {
			return fmt.Errorf("bufio: Available subtrahend not b.n")
		}
	}
	if bfRecv := recvVarName(bufdFn); bfRecv == "" {
		return fmt.Errorf("bufio: unnamed Buffered receiver")
	} else {
		ret, ok := bufdFn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return fmt.Errorf("bufio: invalid Buffered return")
		}
		if _, ok := isSelectorBaseField(ret.Results[0], bfRecv, "n"); !ok {
			return fmt.Errorf("bufio: Buffered does not return b.n")
		}
	}

	// Verify (*Writer).Flush() dereferences receiver without nil guard, writes b.buf[0:b.n] to b.wr,
	// checks short writes, and latches + returns any error.
	flushFn := writerMethods["Flush"]
	if flushFn == nil || flushFn.Body == nil || funcShadowsAnyIdent(flushFn, reserved) || !funcReturnsErrorLast(flushFn.Type) {
		return fmt.Errorf("bufio: missing or invalid (*Writer).Flush")
	}
	fRecv := recvVarName(flushFn)
	if fRecv == "" || len(flushFn.Body.List) != 7 {
		return fmt.Errorf("bufio: (*Writer).Flush has unexpected statement structure")
	}
	// Stmt 0: if b.err != nil { return b.err }
	if s0, ok := flushFn.Body.List[0].(*ast.IfStmt); !ok || s0.Init != nil || s0.Else != nil || len(s0.Body.List) != 1 {
		return fmt.Errorf("bufio: Flush missing sticky error guard")
	} else {
		cond, ok := unwrapParens(s0.Cond).(*ast.BinaryExpr)
		if !ok || cond.Op != token.NEQ {
			return fmt.Errorf("bufio: Flush sticky error guard condition invalid")
		}
		if _, ok1 := isSelectorBaseField(cond.X, fRecv, "err"); !ok1 {
			return fmt.Errorf("bufio: Flush sticky error guard LHS not b.err")
		}
		if _, ok2 := isIdentNamed(cond.Y, "nil"); !ok2 {
			return fmt.Errorf("bufio: Flush sticky error guard RHS not nil")
		}
		ret, ok := s0.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return fmt.Errorf("bufio: Flush sticky error return invalid")
		}
		if _, ok := isSelectorBaseField(ret.Results[0], fRecv, "err"); !ok {
			return fmt.Errorf("bufio: Flush does not return b.err")
		}
	}
	// Stmt 1: if b.n == 0 { return nil }
	if s1, ok := flushFn.Body.List[1].(*ast.IfStmt); !ok || s1.Init != nil || s1.Else != nil || len(s1.Body.List) != 1 {
		return fmt.Errorf("bufio: Flush missing empty-buffer check")
	} else {
		cond, ok := unwrapParens(s1.Cond).(*ast.BinaryExpr)
		if !ok || cond.Op != token.EQL || !isZeroIntLit(cond.Y) {
			return fmt.Errorf("bufio: Flush empty-buffer condition invalid")
		}
		if _, ok := isSelectorBaseField(cond.X, fRecv, "n"); !ok {
			return fmt.Errorf("bufio: Flush empty-buffer LHS not b.n")
		}
		ret, ok := s1.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return fmt.Errorf("bufio: Flush empty-buffer return invalid")
		}
		if _, ok := isIdentNamed(ret.Results[0], "nil"); !ok {
			return fmt.Errorf("bufio: Flush empty-buffer check does not return nil")
		}
	}
	// Stmt 2: n, err := b.wr.Write(b.buf[0:b.n])
	var flushNVar, flushErrVar string
	if s2, ok := flushFn.Body.List[2].(*ast.AssignStmt); !ok || s2.Tok != token.DEFINE || len(s2.Lhs) != 2 || len(s2.Rhs) != 1 {
		return fmt.Errorf("bufio: Flush missing b.wr.Write assignment")
	} else {
		nID, ok1 := unwrapParens(s2.Lhs[0]).(*ast.Ident)
		eID, ok2 := unwrapParens(s2.Lhs[1]).(*ast.Ident)
		wCall, ok3 := unwrapParens(s2.Rhs[0]).(*ast.CallExpr)
		if !ok1 || !ok2 || !ok3 || nID.Name == "" || nID.Name == "_" || eID.Name == "" || eID.Name == "_" || wCall.Ellipsis.IsValid() || len(wCall.Args) != 1 {
			return fmt.Errorf("bufio: Flush invalid b.wr.Write call")
		}
		flushNVar, flushErrVar = nID.Name, eID.Name
		wSel, ok := unwrapParens(wCall.Fun).(*ast.SelectorExpr)
		if !ok || wSel.Sel.Name != "Write" {
			return fmt.Errorf("bufio: Flush does not call Write")
		}
		if _, ok := isSelectorBaseField(wSel.X, fRecv, "wr"); !ok {
			return fmt.Errorf("bufio: Flush Write receiver not b.wr")
		}
		sl, ok := unwrapParens(wCall.Args[0]).(*ast.SliceExpr)
		if !ok || sl.Slice3 || sl.High == nil || (sl.Low != nil && !isZeroIntLit(sl.Low)) {
			return fmt.Errorf("bufio: Flush slice arg not b.buf[0:b.n]")
		}
		if _, ok := isSelectorBaseField(sl.X, fRecv, "buf"); !ok {
			return fmt.Errorf("bufio: Flush slice base not b.buf")
		}
		if _, ok := isSelectorBaseField(sl.High, fRecv, "n"); !ok {
			return fmt.Errorf("bufio: Flush slice high not b.n")
		}
	}
	// Stmt 3: if n < b.n && err == nil { err = io.ErrShortWrite }
	if s3, ok := flushFn.Body.List[3].(*ast.IfStmt); !ok || s3.Init != nil || s3.Else != nil || len(s3.Body.List) != 1 {
		return fmt.Errorf("bufio: Flush missing short-write check")
	} else {
		andExpr, ok := unwrapParens(s3.Cond).(*ast.BinaryExpr)
		if !ok || andExpr.Op != token.LAND || !condChecksEqErr(andExpr.Y, flushErrVar) {
			return fmt.Errorf("bufio: Flush short-write condition invalid")
		}
		ltExpr, ok := unwrapParens(andExpr.X).(*ast.BinaryExpr)
		if !ok || ltExpr.Op != token.LSS {
			return fmt.Errorf("bufio: Flush short-write comparison invalid")
		}
		if _, ok1 := isIdentNamed(ltExpr.X, flushNVar); !ok1 {
			return fmt.Errorf("bufio: Flush short-write LHS not n")
		}
		if _, ok2 := isSelectorBaseField(ltExpr.Y, fRecv, "n"); !ok2 {
			return fmt.Errorf("bufio: Flush short-write RHS not b.n")
		}
		as, ok := s3.Body.List[0].(*ast.AssignStmt)
		if !ok || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return fmt.Errorf("bufio: Flush short-write assignment invalid")
		}
		if _, ok1 := isIdentNamed(as.Lhs[0], flushErrVar); !ok1 {
			return fmt.Errorf("bufio: Flush short-write LHS not err")
		}
		if _, ok2 := isSelectorBaseField(as.Rhs[0], "io", "ErrShortWrite"); !ok2 {
			return fmt.Errorf("bufio: Flush short-write RHS not io.ErrShortWrite")
		}
	}
	// Stmt 4: if err != nil { ...; b.err = err; return err }
	if s4, ok := flushFn.Body.List[4].(*ast.IfStmt); !ok || s4.Init != nil || s4.Else != nil || condChecksNonZeroErr(s4.Cond) != flushErrVar || len(s4.Body.List) < 2 {
		return fmt.Errorf("bufio: Flush missing error return branch")
	} else {
		if bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: s4.Body.List[:len(s4.Body.List)-1]}, map[string]bool{flushErrVar: true}) {
			return fmt.Errorf("bufio: Flush mutates err before returning")
		}
		latchStmt, ok1 := s4.Body.List[len(s4.Body.List)-2].(*ast.AssignStmt)
		retStmt, ok2 := s4.Body.List[len(s4.Body.List)-1].(*ast.ReturnStmt)
		if !ok1 || !ok2 || latchStmt.Tok != token.ASSIGN || len(latchStmt.Lhs) != 1 || len(latchStmt.Rhs) != 1 || len(retStmt.Results) != 1 {
			return fmt.Errorf("bufio: Flush error branch missing b.err = err; return err")
		}
		if _, ok := isSelectorBaseField(latchStmt.Lhs[0], fRecv, "err"); !ok {
			return fmt.Errorf("bufio: Flush does not latch b.err")
		}
		if _, ok := isIdentNamed(latchStmt.Rhs[0], flushErrVar); !ok {
			return fmt.Errorf("bufio: Flush latches wrong error")
		}
		if _, ok := isIdentNamed(retStmt.Results[0], flushErrVar); !ok {
			return fmt.Errorf("bufio: Flush returns wrong error")
		}
	}
	// Stmt 5 & 6: b.n = 0; return nil
	if s5, ok := flushFn.Body.List[5].(*ast.AssignStmt); !ok || s5.Tok != token.ASSIGN || len(s5.Lhs) != 1 || len(s5.Rhs) != 1 || !isZeroIntLit(s5.Rhs[0]) {
		return fmt.Errorf("bufio: Flush missing b.n = 0")
	} else if _, ok := isSelectorBaseField(s5.Lhs[0], fRecv, "n"); !ok {
		return fmt.Errorf("bufio: Flush reset target not b.n")
	}
	if s6, ok := flushFn.Body.List[6].(*ast.ReturnStmt); !ok || len(s6.Results) != 1 {
		return fmt.Errorf("bufio: Flush missing final return nil")
	} else if _, ok := isIdentNamed(s6.Results[0], "nil"); !ok {
		return fmt.Errorf("bufio: Flush final return not nil")
	}

	// Verify (*Writer).WriteByte and (*Writer).WriteString preserve bytes and sticky b.err.
	wbFn := writerMethods["WriteByte"]
	wsFn := writerMethods["WriteString"]
	if wbFn == nil || wbFn.Body == nil || funcShadowsAnyIdent(wbFn, reserved) || wsFn == nil || wsFn.Body == nil || funcShadowsAnyIdent(wsFn, reserved) {
		return fmt.Errorf("bufio: missing WriteByte or WriteString")
	}
	wbRecv := recvVarName(wbFn)
	wbParams := paramNamesFlat(wbFn.Type.Params)
	if wbRecv == "" || len(wbParams) != 1 || wbParams[0] == "" || wbParams[0] == "_" || len(wbFn.Body.List) != 5 {
		return fmt.Errorf("bufio: unexpected WriteByte shape")
	}
	// WriteByte[0]: if b.err != nil { return b.err }
	if wb0, ok := wbFn.Body.List[0].(*ast.IfStmt); !ok || wb0.Init != nil || wb0.Else != nil || len(wb0.Body.List) != 1 {
		return fmt.Errorf("bufio: WriteByte missing sticky b.err guard")
	} else {
		cond, ok := unwrapParens(wb0.Cond).(*ast.BinaryExpr)
		if !ok || cond.Op != token.NEQ {
			return fmt.Errorf("bufio: WriteByte sticky b.err condition invalid")
		}
		if _, ok1 := isSelectorBaseField(cond.X, wbRecv, "err"); !ok1 {
			return fmt.Errorf("bufio: WriteByte sticky guard LHS not b.err")
		}
		if _, ok2 := isIdentNamed(cond.Y, "nil"); !ok2 {
			return fmt.Errorf("bufio: WriteByte sticky guard RHS not nil")
		}
		ret, ok := wb0.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return fmt.Errorf("bufio: WriteByte sticky guard return invalid")
		}
		if _, ok := isSelectorBaseField(ret.Results[0], wbRecv, "err"); !ok {
			return fmt.Errorf("bufio: WriteByte sticky guard does not return b.err")
		}
	}
	// WriteByte[1]: if b.Available() <= 0 && b.Flush() != nil { return b.err }
	if wb1, ok := wbFn.Body.List[1].(*ast.IfStmt); !ok || wb1.Init != nil || wb1.Else != nil || len(wb1.Body.List) != 1 {
		return fmt.Errorf("bufio: WriteByte missing Available/Flush guard")
	} else {
		andC, ok := unwrapParens(wb1.Cond).(*ast.BinaryExpr)
		if !ok || andC.Op != token.LAND {
			return fmt.Errorf("bufio: WriteByte Available/Flush guard not &&")
		}
		leC, ok1 := unwrapParens(andC.X).(*ast.BinaryExpr)
		neqC, ok2 := unwrapParens(andC.Y).(*ast.BinaryExpr)
		if !ok1 || !ok2 || leC.Op != token.LEQ || !isZeroIntLit(leC.Y) || neqC.Op != token.NEQ {
			return fmt.Errorf("bufio: WriteByte Available/Flush comparisons invalid")
		}
		if _, ok := isZeroArgMethodCallOnIdent(leC.X, wbRecv, "Available"); !ok {
			return fmt.Errorf("bufio: WriteByte does not check b.Available() <= 0")
		}
		if _, ok := isZeroArgMethodCallOnIdent(neqC.X, wbRecv, "Flush"); !ok {
			return fmt.Errorf("bufio: WriteByte does not call b.Flush()")
		}
		if _, ok := isIdentNamed(neqC.Y, "nil"); !ok {
			return fmt.Errorf("bufio: WriteByte Flush comparison RHS not nil")
		}
		ret, ok := wb1.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return fmt.Errorf("bufio: WriteByte Flush guard return invalid")
		}
		if _, ok := isSelectorBaseField(ret.Results[0], wbRecv, "err"); !ok {
			return fmt.Errorf("bufio: WriteByte Flush guard does not return b.err")
		}
	}
	if as, ok := wbFn.Body.List[2].(*ast.AssignStmt); !ok || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
		return fmt.Errorf("bufio: WriteByte missing b.buf[b.n] = c")
	} else {
		idx, ok1 := unwrapParens(as.Lhs[0]).(*ast.IndexExpr)
		_, ok2 := isIdentNamed(as.Rhs[0], wbParams[0])
		if !ok1 || !ok2 {
			return fmt.Errorf("bufio: WriteByte assignment mismatch")
		}
		if _, ok := isSelectorBaseField(idx.X, wbRecv, "buf"); !ok {
			return fmt.Errorf("bufio: WriteByte target not b.buf")
		}
		if _, ok := isSelectorBaseField(idx.Index, wbRecv, "n"); !ok {
			return fmt.Errorf("bufio: WriteByte index not b.n")
		}
	}
	if inc, ok := wbFn.Body.List[3].(*ast.IncDecStmt); !ok || inc.Tok != token.INC {
		return fmt.Errorf("bufio: WriteByte missing b.n++")
	} else if _, ok := isSelectorBaseField(inc.X, wbRecv, "n"); !ok {
		return fmt.Errorf("bufio: WriteByte increment target not b.n")
	}
	if wb4, ok := wbFn.Body.List[4].(*ast.ReturnStmt); !ok || len(wb4.Results) != 1 {
		return fmt.Errorf("bufio: WriteByte missing final return nil")
	} else if _, ok := isIdentNamed(wb4.Results[0], "nil"); !ok {
		return fmt.Errorf("bufio: WriteByte final return not nil")
	}

	wsRecv := recvVarName(wsFn)
	wsParams := paramNamesFlat(wsFn.Type.Params)
	if wsRecv == "" || len(wsParams) != 1 || wsParams[0] == "" || wsParams[0] == "_" || len(wsFn.Body.List) != 9 {
		return fmt.Errorf("bufio: unexpected WriteString shape")
	}
	sParam := wsParams[0]
	if bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: wsFn.Body.List[4:]}, map[string]bool{sParam: true}) {
		return fmt.Errorf("bufio: WriteString mutates s after loop")
	}
	// Stmt 0: var sw io.StringWriter; Stmt 1: tryStringWriter := true; Stmt 2: nn := 0
	var swVar, trySWVar, nnVar string
	if ds0, ok := wsFn.Body.List[0].(*ast.DeclStmt); !ok {
		return fmt.Errorf("bufio: WriteString missing var sw io.StringWriter")
	} else {
		gd, ok := ds0.Decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR || len(gd.Specs) != 1 {
			return fmt.Errorf("bufio: WriteString invalid sw declaration")
		}
		vs, ok := gd.Specs[0].(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || len(vs.Values) != 0 || vs.Names[0].Name == "" || vs.Names[0].Name == "_" {
			return fmt.Errorf("bufio: WriteString invalid sw ValueSpec")
		}
		if _, ok := isSelectorBaseField(vs.Type, "io", "StringWriter"); !ok {
			return fmt.Errorf("bufio: WriteString sw type not io.StringWriter")
		}
		swVar = vs.Names[0].Name
	}
	if as1, ok := wsFn.Body.List[1].(*ast.AssignStmt); !ok || as1.Tok != token.DEFINE || len(as1.Lhs) != 1 || len(as1.Rhs) != 1 {
		return fmt.Errorf("bufio: WriteString missing tryStringWriter := true")
	} else {
		id, ok1 := unwrapParens(as1.Lhs[0]).(*ast.Ident)
		_, ok2 := isIdentNamed(as1.Rhs[0], "true")
		if !ok1 || !ok2 || id.Name == "" || id.Name == "_" {
			return fmt.Errorf("bufio: WriteString invalid tryStringWriter init")
		}
		trySWVar = id.Name
	}
	if as2, ok := wsFn.Body.List[2].(*ast.AssignStmt); !ok || as2.Tok != token.DEFINE || len(as2.Lhs) != 1 || len(as2.Rhs) != 1 || !isZeroIntLit(as2.Rhs[0]) {
		return fmt.Errorf("bufio: WriteString missing nn := 0")
	} else {
		id, ok := unwrapParens(as2.Lhs[0]).(*ast.Ident)
		if !ok || id.Name == "" || id.Name == "_" {
			return fmt.Errorf("bufio: WriteString invalid nn init")
		}
		nnVar = id.Name
	}
	// Stmt 3: for len(s) > b.Available() && b.err == nil { ... }
	if fs3, ok := wsFn.Body.List[3].(*ast.ForStmt); !ok || fs3.Init != nil || fs3.Post != nil || len(fs3.Body.List) != 5 {
		return fmt.Errorf("bufio: WriteString missing overflow loop")
	} else {
		andC, ok := unwrapParens(fs3.Cond).(*ast.BinaryExpr)
		if !ok || andC.Op != token.LAND {
			return fmt.Errorf("bufio: WriteString loop condition not &&")
		}
		gtC, ok1 := unwrapParens(andC.X).(*ast.BinaryExpr)
		eqC, ok2 := unwrapParens(andC.Y).(*ast.BinaryExpr)
		if !ok1 || !ok2 || gtC.Op != token.GTR || !isLenOfIdentCall(gtC.X, sParam) || eqC.Op != token.EQL {
			return fmt.Errorf("bufio: WriteString loop comparisons invalid")
		}
		if _, ok := isZeroArgMethodCallOnIdent(gtC.Y, wsRecv, "Available"); !ok {
			return fmt.Errorf("bufio: WriteString loop RHS not b.Available()")
		}
		if _, ok := isSelectorBaseField(eqC.X, wsRecv, "err"); !ok {
			return fmt.Errorf("bufio: WriteString loop err check LHS not b.err")
		}
		if _, ok := isIdentNamed(eqC.Y, "nil"); !ok {
			return fmt.Errorf("bufio: WriteString loop err check RHS not nil")
		}
		// Loop[0]: var n int
		var loopNVar string
		if lds0, ok := fs3.Body.List[0].(*ast.DeclStmt); !ok {
			return fmt.Errorf("bufio: WriteString loop missing var n int")
		} else {
			gd, ok := lds0.Decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR || len(gd.Specs) != 1 {
				return fmt.Errorf("bufio: WriteString loop invalid var n int")
			}
			vs, ok := gd.Specs[0].(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 0 || vs.Names[0].Name == "" || vs.Names[0].Name == "_" {
				return fmt.Errorf("bufio: WriteString loop invalid n spec")
			}
			if _, ok := isIdentNamed(vs.Type, "int"); !ok {
				return fmt.Errorf("bufio: WriteString loop n not int")
			}
			loopNVar = vs.Names[0].Name
		}
		// Loop[1]: if b.Buffered() == 0 && sw == nil && tryStringWriter { sw, tryStringWriter = b.wr.(io.StringWriter) }
		if lif1, ok := fs3.Body.List[1].(*ast.IfStmt); !ok || lif1.Init != nil || lif1.Else != nil || len(lif1.Body.List) != 1 {
			return fmt.Errorf("bufio: WriteString loop missing StringWriter probe")
		} else {
			outerAnd, okAnd := unwrapParens(lif1.Cond).(*ast.BinaryExpr)
			if !okAnd || outerAnd.Op != token.LAND {
				return fmt.Errorf("bufio: WriteString StringWriter probe outer condition invalid")
			}
			if _, okTry := isIdentNamed(outerAnd.Y, trySWVar); !okTry {
				return fmt.Errorf("bufio: WriteString StringWriter probe missing tryStringWriter guard")
			}
			innerAnd, okIn := unwrapParens(outerAnd.X).(*ast.BinaryExpr)
			if !okIn || innerAnd.Op != token.LAND {
				return fmt.Errorf("bufio: WriteString StringWriter probe inner condition invalid")
			}
			bufEq, okBE := unwrapParens(innerAnd.X).(*ast.BinaryExpr)
			var okBufCall bool
			if okBE {
				_, okBufCall = isZeroArgMethodCallOnIdent(bufEq.X, wsRecv, "Buffered")
			}
			if !okBE || bufEq.Op != token.EQL || !okBufCall || !isZeroIntLit(bufEq.Y) {
				return fmt.Errorf("bufio: WriteString StringWriter probe missing b.Buffered() == 0 guard")
			}
			swEq, okSE := unwrapParens(innerAnd.Y).(*ast.BinaryExpr)
			if !okSE || swEq.Op != token.EQL {
				return fmt.Errorf("bufio: WriteString StringWriter probe missing sw == nil guard")
			}
			_, okSW := isIdentNamed(swEq.X, swVar)
			_, okNil := isIdentNamed(swEq.Y, "nil")
			if !okSW || !okNil {
				return fmt.Errorf("bufio: WriteString StringWriter probe sw == nil operands invalid")
			}
			as, ok := lif1.Body.List[0].(*ast.AssignStmt)
			if !ok || as.Tok != token.ASSIGN || len(as.Lhs) != 2 || len(as.Rhs) != 1 {
				return fmt.Errorf("bufio: WriteString StringWriter probe assign invalid")
			}
			_, ok1 := isIdentNamed(as.Lhs[0], swVar)
			_, ok2 := isIdentNamed(as.Lhs[1], trySWVar)
			ta, ok3 := unwrapParens(as.Rhs[0]).(*ast.TypeAssertExpr)
			if !ok1 || !ok2 || !ok3 || ta.Type == nil {
				return fmt.Errorf("bufio: WriteString StringWriter type assertion invalid")
			}
			if _, ok := isSelectorBaseField(ta.X, wsRecv, "wr"); !ok {
				return fmt.Errorf("bufio: WriteString StringWriter assertion not on b.wr")
			}
			if _, ok := isSelectorBaseField(ta.Type, "io", "StringWriter"); !ok {
				return fmt.Errorf("bufio: WriteString assertion type not io.StringWriter")
			}
		}
		// Loop[2]: if b.Buffered() == 0 && tryStringWriter { n, b.err = sw.WriteString(s) } else { n = copy(b.buf[b.n:], s); b.n += n; b.Flush() }
		if lif2, ok := fs3.Body.List[2].(*ast.IfStmt); !ok || lif2.Init != nil || lif2.Else == nil || len(lif2.Body.List) != 1 {
			return fmt.Errorf("bufio: WriteString loop missing StringWriter/copy dispatch")
		} else {
			and2, ok := unwrapParens(lif2.Cond).(*ast.BinaryExpr)
			if !ok || and2.Op != token.LAND {
				return fmt.Errorf("bufio: WriteString dispatch cond not &&")
			}
			bufEq, ok1 := unwrapParens(and2.X).(*ast.BinaryExpr)
			_, ok2 := isIdentNamed(and2.Y, trySWVar)
			if !ok1 || !ok2 || bufEq.Op != token.EQL || !isZeroIntLit(bufEq.Y) {
				return fmt.Errorf("bufio: WriteString dispatch Buffered() == 0 cond invalid")
			}
			if _, ok := isZeroArgMethodCallOnIdent(bufEq.X, wsRecv, "Buffered"); !ok {
				return fmt.Errorf("bufio: WriteString dispatch does not check b.Buffered()")
			}
			swAs, ok := lif2.Body.List[0].(*ast.AssignStmt)
			if !ok || swAs.Tok != token.ASSIGN || len(swAs.Lhs) != 2 || len(swAs.Rhs) != 1 {
				return fmt.Errorf("bufio: WriteString sw.WriteString assign invalid")
			}
			_, okN := isIdentNamed(swAs.Lhs[0], loopNVar)
			_, okErr := isSelectorBaseField(swAs.Lhs[1], wsRecv, "err")
			swCall, okC := unwrapParens(swAs.Rhs[0]).(*ast.CallExpr)
			if !okN || !okErr || !okC || swCall.Ellipsis.IsValid() || len(swCall.Args) != 1 {
				return fmt.Errorf("bufio: WriteString sw.WriteString call invalid")
			}
			if _, ok := isSelectorBaseField(swCall.Fun, swVar, "WriteString"); !ok {
				return fmt.Errorf("bufio: WriteString does not call sw.WriteString")
			}
			if _, ok := isIdentNamed(swCall.Args[0], sParam); !ok {
				return fmt.Errorf("bufio: WriteString sw.WriteString arg not s")
			}
			elseBlk, ok := lif2.Else.(*ast.BlockStmt)
			if !ok || len(elseBlk.List) != 3 {
				return fmt.Errorf("bufio: WriteString else branch unexpected shape")
			}
			cpAs, ok1 := elseBlk.List[0].(*ast.AssignStmt)
			addAs, ok2 := elseBlk.List[1].(*ast.AssignStmt)
			flES, ok3 := elseBlk.List[2].(*ast.ExprStmt)
			if !ok1 || !ok2 || !ok3 || cpAs.Tok != token.ASSIGN || len(cpAs.Lhs) != 1 || len(cpAs.Rhs) != 1 || addAs.Tok != token.ADD_ASSIGN || len(addAs.Lhs) != 1 || len(addAs.Rhs) != 1 {
				return fmt.Errorf("bufio: WriteString else copy/add/Flush invalid")
			}
			if _, ok := isIdentNamed(cpAs.Lhs[0], loopNVar); !ok {
				return fmt.Errorf("bufio: WriteString else copy LHS not n")
			}
			cpCall, ok := unwrapParens(cpAs.Rhs[0]).(*ast.CallExpr)
			if !ok || cpCall.Ellipsis.IsValid() || len(cpCall.Args) != 2 {
				return fmt.Errorf("bufio: WriteString else copy call invalid")
			}
			if _, ok := isIdentNamed(cpCall.Fun, "copy"); !ok {
				return fmt.Errorf("bufio: WriteString else call not copy")
			}
			sl, ok := unwrapParens(cpCall.Args[0]).(*ast.SliceExpr)
			if !ok || sl.Slice3 || sl.High != nil || sl.Low == nil {
				return fmt.Errorf("bufio: WriteString else copy dst slice invalid")
			}
			if _, ok1 := isSelectorBaseField(sl.X, wsRecv, "buf"); !ok1 {
				return fmt.Errorf("bufio: WriteString else copy dst not b.buf")
			}
			if _, ok2 := isSelectorBaseField(sl.Low, wsRecv, "n"); !ok2 {
				return fmt.Errorf("bufio: WriteString else copy low not b.n")
			}
			if _, ok := isIdentNamed(cpCall.Args[1], sParam); !ok {
				return fmt.Errorf("bufio: WriteString else copy src not s")
			}
			if _, ok1 := isSelectorBaseField(addAs.Lhs[0], wsRecv, "n"); !ok1 {
				return fmt.Errorf("bufio: WriteString else add LHS not b.n")
			}
			if _, ok2 := isIdentNamed(addAs.Rhs[0], loopNVar); !ok2 {
				return fmt.Errorf("bufio: WriteString else add RHS not n")
			}
			if _, ok := isZeroArgMethodCallOnIdent(flES.X, wsRecv, "Flush"); !ok {
				return fmt.Errorf("bufio: WriteString else missing b.Flush()")
			}
		}
		// Loop[3]: nn += n; Loop[4]: s = s[n:]
		if las3, ok := fs3.Body.List[3].(*ast.AssignStmt); !ok || las3.Tok != token.ADD_ASSIGN || len(las3.Lhs) != 1 || len(las3.Rhs) != 1 {
			return fmt.Errorf("bufio: WriteString loop missing nn += n")
		} else {
			_, ok1 := isIdentNamed(las3.Lhs[0], nnVar)
			_, ok2 := isIdentNamed(las3.Rhs[0], loopNVar)
			if !ok1 || !ok2 {
				return fmt.Errorf("bufio: WriteString loop nn += n mismatch")
			}
		}
		if las4, ok := fs3.Body.List[4].(*ast.AssignStmt); !ok || !isCountAdvanceSliceAssign(las4, sParam, map[string]bool{loopNVar: true}) {
			return fmt.Errorf("bufio: WriteString loop missing s = s[n:]")
		}
	}
	// Stmt 4: if b.err != nil { return nn, b.err }
	if s4, ok := wsFn.Body.List[4].(*ast.IfStmt); !ok || s4.Init != nil || s4.Else != nil || len(s4.Body.List) != 1 {
		return fmt.Errorf("bufio: WriteString missing post-loop b.err check")
	} else {
		cond, ok := unwrapParens(s4.Cond).(*ast.BinaryExpr)
		if !ok || cond.Op != token.NEQ {
			return fmt.Errorf("bufio: WriteString post-loop condition invalid")
		}
		if _, ok := isSelectorBaseField(cond.X, wsRecv, "err"); !ok {
			return fmt.Errorf("bufio: WriteString post-loop LHS not b.err")
		}
		if _, ok := isIdentNamed(cond.Y, "nil"); !ok {
			return fmt.Errorf("bufio: WriteString post-loop RHS not nil")
		}
		ret4, ok := s4.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret4.Results) != 2 {
			return fmt.Errorf("bufio: WriteString post-loop return invalid")
		}
		_, ok1 := isIdentNamed(ret4.Results[0], nnVar)
		_, ok2 := isSelectorBaseField(ret4.Results[1], wsRecv, "err")
		if !ok1 || !ok2 {
			return fmt.Errorf("bufio: WriteString post-loop return not nn, b.err")
		}
	}
	// Stmt 5: n := copy(b.buf[b.n:], s); Stmt 6: b.n += n; Stmt 7: nn += n; Stmt 8: return nn, nil
	var tailNVar string
	if s5, ok := wsFn.Body.List[5].(*ast.AssignStmt); !ok || s5.Tok != token.DEFINE || len(s5.Lhs) != 1 || len(s5.Rhs) != 1 {
		return fmt.Errorf("bufio: WriteString missing tail copy")
	} else {
		nID, ok1 := unwrapParens(s5.Lhs[0]).(*ast.Ident)
		cpCall, ok2 := unwrapParens(s5.Rhs[0]).(*ast.CallExpr)
		if !ok1 || !ok2 || nID.Name == "" || nID.Name == "_" || cpCall.Ellipsis.IsValid() || len(cpCall.Args) != 2 {
			return fmt.Errorf("bufio: WriteString invalid tail copy")
		}
		tailNVar = nID.Name
		if _, ok := isIdentNamed(cpCall.Fun, "copy"); !ok {
			return fmt.Errorf("bufio: WriteString tail call not copy")
		}
		sl, ok := unwrapParens(cpCall.Args[0]).(*ast.SliceExpr)
		if !ok || sl.Slice3 || sl.High != nil || sl.Low == nil {
			return fmt.Errorf("bufio: WriteString tail copy dst slice invalid")
		}
		if _, ok := isSelectorBaseField(sl.X, wsRecv, "buf"); !ok {
			return fmt.Errorf("bufio: WriteString tail copy dst not b.buf")
		}
		if _, ok := isSelectorBaseField(sl.Low, wsRecv, "n"); !ok {
			return fmt.Errorf("bufio: WriteString tail copy low not b.n")
		}
		if _, ok := isIdentNamed(cpCall.Args[1], sParam); !ok {
			return fmt.Errorf("bufio: WriteString tail copy src not s")
		}
		s6, ok := wsFn.Body.List[6].(*ast.AssignStmt)
		if !ok || s6.Tok != token.ADD_ASSIGN || len(s6.Lhs) != 1 || len(s6.Rhs) != 1 {
			return fmt.Errorf("bufio: WriteString missing b.n += n")
		}
		if _, ok := isSelectorBaseField(s6.Lhs[0], wsRecv, "n"); !ok {
			return fmt.Errorf("bufio: WriteString tail add target not b.n")
		}
		if _, ok := isIdentNamed(s6.Rhs[0], tailNVar); !ok {
			return fmt.Errorf("bufio: WriteString tail add RHS not n")
		}
	}
	if s7, ok := wsFn.Body.List[7].(*ast.AssignStmt); !ok || s7.Tok != token.ADD_ASSIGN || len(s7.Lhs) != 1 || len(s7.Rhs) != 1 {
		return fmt.Errorf("bufio: WriteString missing tail nn += n")
	} else {
		_, ok1 := isIdentNamed(s7.Lhs[0], nnVar)
		_, ok2 := isIdentNamed(s7.Rhs[0], tailNVar)
		if !ok1 || !ok2 {
			return fmt.Errorf("bufio: WriteString tail nn += n mismatch")
		}
	}
	if s8, ok := wsFn.Body.List[8].(*ast.ReturnStmt); !ok || len(s8.Results) != 2 {
		return fmt.Errorf("bufio: WriteString missing final return")
	} else {
		_, ok1 := isIdentNamed(s8.Results[0], nnVar)
		_, ok2 := isIdentNamed(s8.Results[1], "nil")
		if !ok1 || !ok2 {
			return fmt.Errorf("bufio: WriteString final return not nn, nil")
		}
	}
	return nil
}

func verifyInternalTestlogPackageAST(files []*ast.File) error {
	reserved := map[string]bool{
		"atomic": true, "Interface": true, "logger": true,
		"SetLogger": true, "Logger": true, "Getenv": true, "Open": true, "Stat": true,
		"panic": true, "nil": true, "string": true,
	}
	var ifaceSpecs []*ast.TypeSpec
	var loggerVarIdents []*ast.Ident
	topFuncs := map[string]*ast.FuncDecl{}
	dupTopFuncs := false

	for _, f := range files {
		var fileImportsAtomic bool
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			switch path {
			case "sync/atomic":
				if imp.Name != nil {
					return fmt.Errorf("internal/testlog: aliased import of sync/atomic forbidden")
				}
				fileImportsAtomic = true
			case "sync":
				if imp.Name != nil {
					return fmt.Errorf("internal/testlog: aliased import of sync forbidden")
				}
			case "unsafe":
				if imp.Name == nil || imp.Name.Name != "_" {
					return fmt.Errorf("internal/testlog: non-blank import of unsafe forbidden")
				}
			default:
				return fmt.Errorf("internal/testlog: unapproved import %q", path)
			}
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.TypeSpec:
						if sp.Name != nil && sp.Name.Name == "Interface" {
							ifaceSpecs = append(ifaceSpecs, sp)
						} else if sp.Name != nil && reserved[sp.Name.Name] {
							return fmt.Errorf("internal/testlog: type shadows %s", sp.Name.Name)
						}
					case *ast.ValueSpec:
						for _, id := range sp.Names {
							if id.Name == "logger" {
								if d.Tok != token.VAR || len(sp.Names) != 1 || len(sp.Values) != 0 || !fileImportsAtomic {
									return fmt.Errorf("internal/testlog: invalid logger variable declaration")
								}
								idxExpr, ok := unwrapParens(sp.Type).(*ast.IndexExpr)
								if !ok {
									return fmt.Errorf("internal/testlog: logger is not atomic.Pointer[Interface]")
								}
								if _, ok := isSelectorBaseField(idxExpr.X, "atomic", "Pointer"); !ok {
									return fmt.Errorf("internal/testlog: logger base type is not atomic.Pointer")
								}
								if _, ok := isIdentNamed(idxExpr.Index, "Interface"); !ok {
									return fmt.Errorf("internal/testlog: logger type arg is not Interface")
								}
								loggerVarIdents = append(loggerVarIdents, id)
							} else if reserved[id.Name] {
								return fmt.Errorf("internal/testlog: declaration shadows %s", id.Name)
							}
						}
					}
				}
			case *ast.FuncDecl:
				if d.Body == nil {
					return fmt.Errorf("internal/testlog: bodyless function %s forbidden", d.Name.Name)
				}
				if d.Recv != nil {
					return fmt.Errorf("internal/testlog: method declaration %s forbidden", d.Name.Name)
				}
				if d.Name.Name == "init" {
					return fmt.Errorf("internal/testlog: init function forbidden")
				}
				if _, dup := topFuncs[d.Name.Name]; dup {
					dupTopFuncs = true
				}
				topFuncs[d.Name.Name] = d
			}
		}
	}
	if dupTopFuncs || len(ifaceSpecs) != 1 || len(loggerVarIdents) != 1 {
		return fmt.Errorf("internal/testlog: missing or duplicate Interface/logger declarations")
	}

	// Verify Interface declares exact 4 methods Getenv, Stat, Open, Chdir(string).
	is := ifaceSpecs[0]
	if is.Assign.IsValid() || is.TypeParams != nil {
		return fmt.Errorf("internal/testlog: invalid Interface type declaration")
	}
	it, ok := unwrapParens(is.Type).(*ast.InterfaceType)
	if !ok || it.Methods == nil {
		return fmt.Errorf("internal/testlog: Interface is not an interface")
	}
	wantMethods := map[string]bool{"Getenv": true, "Stat": true, "Open": true, "Chdir": true}
	seenMethods := map[string]bool{}
	for _, m := range it.Methods.List {
		if len(m.Names) != 1 || !wantMethods[m.Names[0].Name] || seenMethods[m.Names[0].Name] {
			return fmt.Errorf("internal/testlog: unexpected method in Interface")
		}
		ft, ok := m.Type.(*ast.FuncType)
		if !ok || ft.TypeParams != nil || ft.Params == nil || ft.Params.NumFields() != 1 || len(ft.Params.List) != 1 || (ft.Results != nil && ft.Results.NumFields() != 0) {
			return fmt.Errorf("internal/testlog: unexpected signature for Interface.%s", m.Names[0].Name)
		}
		if _, ok := isIdentNamed(ft.Params.List[0].Type, "string"); !ok {
			return fmt.Errorf("internal/testlog: Interface.%s parameter is not string", m.Names[0].Name)
		}
		seenMethods[m.Names[0].Name] = true
	}
	if len(seenMethods) != len(wantMethods) {
		return fmt.Errorf("internal/testlog: incomplete Interface method set")
	}

	allowedLoggerIdents := map[*ast.Ident]bool{loggerVarIdents[0]: true}

	// Verify SetLogger(impl Interface): if !logger.CompareAndSwap(nil, &impl) { panic("...") }
	setFn := topFuncs["SetLogger"]
	if setFn == nil || setFn.Type.TypeParams != nil || setFn.Type.Params == nil || setFn.Type.Params.NumFields() != 1 || len(setFn.Type.Params.List) != 1 || (setFn.Type.Results != nil && setFn.Type.Results.NumFields() != 0) || len(setFn.Body.List) != 1 {
		return fmt.Errorf("internal/testlog: invalid SetLogger signature or body")
	}
	setParams := paramNamesFlat(setFn.Type.Params)
	if len(setParams) != 1 || setParams[0] == "" || setParams[0] == "_" || reserved[setParams[0]] || funcShadowsAnyIdent(setFn, reserved) {
		return fmt.Errorf("internal/testlog: invalid SetLogger parameter")
	}
	if _, ok := isIdentNamed(setFn.Type.Params.List[0].Type, "Interface"); !ok {
		return fmt.Errorf("internal/testlog: SetLogger parameter is not Interface")
	}
	setIf, ok := setFn.Body.List[0].(*ast.IfStmt)
	if !ok || setIf.Init != nil || setIf.Else != nil || len(setIf.Body.List) != 1 {
		return fmt.Errorf("internal/testlog: SetLogger body is not single CAS guard")
	}
	notExpr, ok := unwrapParens(setIf.Cond).(*ast.UnaryExpr)
	if !ok || notExpr.Op != token.NOT {
		return fmt.Errorf("internal/testlog: SetLogger missing negated CAS condition")
	}
	casCall, ok := unwrapParens(notExpr.X).(*ast.CallExpr)
	if !ok || casCall.Ellipsis.IsValid() || len(casCall.Args) != 2 {
		return fmt.Errorf("internal/testlog: SetLogger invalid CompareAndSwap call")
	}
	casSel, ok := unwrapParens(casCall.Fun).(*ast.SelectorExpr)
	if !ok || casSel.Sel.Name != "CompareAndSwap" {
		return fmt.Errorf("internal/testlog: SetLogger does not call CompareAndSwap")
	}
	casLogID, ok := isIdentNamed(casSel.X, "logger")
	if !ok {
		return fmt.Errorf("internal/testlog: SetLogger CompareAndSwap receiver is not logger")
	}
	allowedLoggerIdents[casLogID] = true
	if _, ok := isIdentNamed(casCall.Args[0], "nil"); !ok {
		return fmt.Errorf("internal/testlog: SetLogger CAS old value is not nil")
	}
	ampImpl, ok := unwrapParens(casCall.Args[1]).(*ast.UnaryExpr)
	if !ok || ampImpl.Op != token.AND {
		return fmt.Errorf("internal/testlog: SetLogger CAS new value is not &impl")
	}
	if _, ok := isIdentNamed(ampImpl.X, setParams[0]); !ok {
		return fmt.Errorf("internal/testlog: SetLogger CAS new value does not bind impl")
	}
	if !isFailureForcingExitOrPanicStmt(setIf.Body.List[0], "", false) {
		return fmt.Errorf("internal/testlog: SetLogger duplicate call does not panic")
	}

	// Verify Logger() Interface: impl := logger.Load(); if impl == nil { return nil }; return *impl
	getFn := topFuncs["Logger"]
	if getFn == nil || getFn.Type.TypeParams != nil || (getFn.Type.Params != nil && getFn.Type.Params.NumFields() != 0) || getFn.Type.Results == nil || getFn.Type.Results.NumFields() != 1 || len(getFn.Type.Results.List) != 1 || len(getFn.Type.Results.List[0].Names) != 0 || len(getFn.Body.List) != 3 || funcShadowsAnyIdent(getFn, reserved) {
		return fmt.Errorf("internal/testlog: invalid Logger signature or body")
	}
	if _, ok := isIdentNamed(getFn.Type.Results.List[0].Type, "Interface"); !ok {
		return fmt.Errorf("internal/testlog: Logger result is not Interface")
	}
	loadAs, ok := getFn.Body.List[0].(*ast.AssignStmt)
	if !ok || loadAs.Tok != token.DEFINE || len(loadAs.Lhs) != 1 || len(loadAs.Rhs) != 1 {
		return fmt.Errorf("internal/testlog: Logger missing logger.Load() assignment")
	}
	ptrID, ok := unwrapParens(loadAs.Lhs[0]).(*ast.Ident)
	if !ok || ptrID.Name == "" || ptrID.Name == "_" || reserved[ptrID.Name] {
		return fmt.Errorf("internal/testlog: Logger invalid local pointer name")
	}
	loadLogID, ok := isZeroArgMethodCallOnSelectorOrIdent(loadAs.Rhs[0], "logger", "Load")
	if !ok {
		return fmt.Errorf("internal/testlog: Logger does not call logger.Load()")
	}
	allowedLoggerIdents[loadLogID] = true
	nilIf, ok := getFn.Body.List[1].(*ast.IfStmt)
	if !ok || nilIf.Init != nil || nilIf.Else != nil || !condChecksEqErr(nilIf.Cond, ptrID.Name) || len(nilIf.Body.List) != 1 {
		return fmt.Errorf("internal/testlog: Logger missing nil check")
	}
	if nilRet, ok := nilIf.Body.List[0].(*ast.ReturnStmt); !ok || len(nilRet.Results) != 1 {
		return fmt.Errorf("internal/testlog: Logger invalid nil return")
	} else if _, ok := isIdentNamed(nilRet.Results[0], "nil"); !ok {
		return fmt.Errorf("internal/testlog: Logger nil branch does not return nil")
	}
	derefRet, ok := getFn.Body.List[2].(*ast.ReturnStmt)
	if !ok || len(derefRet.Results) != 1 {
		return fmt.Errorf("internal/testlog: Logger missing dereference return")
	}
	starExpr, ok := unwrapParens(derefRet.Results[0]).(*ast.StarExpr)
	if !ok {
		return fmt.Errorf("internal/testlog: Logger does not dereference loaded pointer")
	}
	if _, ok := isIdentNamed(starExpr.X, ptrID.Name); !ok {
		return fmt.Errorf("internal/testlog: Logger dereferences wrong identifier")
	}

	// Verify Getenv, Open, Stat (and Chdir if declared as a package function).
	verifyDispatch := func(op string) bool {
		fn := topFuncs[op]
		if fn == nil || fn.Type.TypeParams != nil || fn.Type.Params == nil || fn.Type.Params.NumFields() != 1 || len(fn.Type.Params.List) != 1 || (fn.Type.Results != nil && fn.Type.Results.NumFields() != 0) || len(fn.Body.List) != 1 || funcShadowsAnyIdent(fn, reserved) {
			return false
		}
		if _, ok := isIdentNamed(fn.Type.Params.List[0].Type, "string"); !ok {
			return false
		}
		pNames := paramNamesFlat(fn.Type.Params)
		if len(pNames) != 1 || pNames[0] == "" || pNames[0] == "_" || reserved[pNames[0]] || bodyDeclaresAnyIdent(fn.Body, map[string]bool{pNames[0]: true}) {
			return false
		}
		ifs, ok := fn.Body.List[0].(*ast.IfStmt)
		if !ok || ifs.Init == nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
			return false
		}
		initAs, ok := ifs.Init.(*ast.AssignStmt)
		if !ok || initAs.Tok != token.DEFINE || len(initAs.Lhs) != 1 || len(initAs.Rhs) != 1 {
			return false
		}
		lID, ok := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
		if !ok || lID.Name == "" || lID.Name == "_" || lID.Name == pNames[0] || reserved[lID.Name] {
			return false
		}
		lCall, ok := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
		if !ok || lCall.Ellipsis.IsValid() || len(lCall.Args) != 0 {
			return false
		}
		if _, ok := isIdentNamed(lCall.Fun, "Logger"); !ok {
			return false
		}
		if condChecksNonZeroErr(ifs.Cond) != lID.Name {
			return false
		}
		es, ok := ifs.Body.List[0].(*ast.ExprStmt)
		if !ok {
			return false
		}
		opCall, ok := unwrapParens(es.X).(*ast.CallExpr)
		if !ok || opCall.Ellipsis.IsValid() || len(opCall.Args) != 1 {
			return false
		}
		if _, ok := isSelectorBaseField(opCall.Fun, lID.Name, op); !ok {
			return false
		}
		_, ok = isIdentNamed(opCall.Args[0], pNames[0])
		return ok
	}
	for _, op := range []string{"Getenv", "Open", "Stat"} {
		if !verifyDispatch(op) {
			return fmt.Errorf("internal/testlog: missing or invalid %s hook dispatcher", op)
		}
	}
	if topFuncs["Chdir"] != nil && !verifyDispatch("Chdir") {
		return fmt.Errorf("internal/testlog: invalid Chdir hook dispatcher")
	}

	// Ensure logger is never referenced anywhere else in internal/testlog.
	var leakedLogger bool
	for _, f := range files {
		walkNonSelectorPropIdents(f, func(id *ast.Ident) {
			if id.Name == "logger" && !allowedLoggerIdents[id] {
				leakedLogger = true
			}
		})
		if leakedLogger {
			return fmt.Errorf("internal/testlog: unexpected reference to logger outside SetLogger/Logger")
		}
	}
	return nil
}

func isZeroArgMethodCallOnSelectorOrIdent(expr ast.Expr, base, method string) (*ast.Ident, bool) {
	call, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 0 {
		return nil, false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != method {
		return nil, false
	}
	return isIdentNamed(sel.X, base)
}

func isSetLoggerTargetForBase(expr ast.Expr, base string) (*ast.Ident, bool) {
	if base == "" {
		return nil, false
	}
	u, ok := unwrapParens(expr).(*ast.UnaryExpr)
	if !ok || u.Op != token.AND {
		return nil, false
	}
	return isIdentNamed(u.X, base)
}

func negatedFieldOnBase(cond ast.Expr) (baseID *ast.Ident, field string, ok bool) {
	u, isNot := unwrapParens(cond).(*ast.UnaryExpr)
	if !isNot || u.Op != token.NOT {
		return nil, "", false
	}
	sel, isSel := unwrapParens(u.X).(*ast.SelectorExpr)
	if !isSel || sel.Sel.Name == "" {
		return nil, "", false
	}
	id, isID := unwrapParens(sel.X).(*ast.Ident)
	if !isID || id.Name == "" {
		return nil, "", false
	}
	return id, sel.Sel.Name, true
}

func isBufioNewWriterForW(expr ast.Expr, wSet map[string]bool) bool {
	call, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() {
		return false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if _, ok := isIdentNamed(sel.X, "bufio"); !ok {
		return false
	}
	switch sel.Sel.Name {
	case "NewWriter":
		if len(call.Args) != 1 {
			return false
		}
		wID, ok := unwrapParens(call.Args[0]).(*ast.Ident)
		return ok && wSet[wID.Name]
	case "NewWriterSize":
		if len(call.Args) != 2 || !isPositiveIntLit(call.Args[1]) {
			return false
		}
		wID, ok := unwrapParens(call.Args[0]).(*ast.Ident)
		return ok && wSet[wID.Name]
	default:
		return false
	}
}

func isCommentHeaderWriteCall(call *ast.CallExpr, base, field string) (*ast.Ident, bool) {
	if call == nil || call.Ellipsis.IsValid() || len(call.Args) != 1 {
		return nil, false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "WriteString" {
		return nil, false
	}
	baseID, ok := isSelectorBaseField(sel.X, base, field)
	if !ok {
		return nil, false
	}
	lit, ok := unwrapParens(call.Args[0]).(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return nil, false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil || !strings.HasPrefix(s, "#") || !strings.HasSuffix(s, "\n") || strings.Contains(s[:len(s)-1], "\n") {
		return nil, false
	}
	return baseID, true
}

func verifyTestdepsStartFunc(fn *ast.FuncDecl, fileImportsTestlog, fileImportsBufio bool) (boundBase, boundField, muField, setField string, allowedBaseIdents map[*ast.Ident]bool, ok bool) {
	if !fileImportsTestlog || !fileImportsBufio || fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || fn.Recv == nil || len(fn.Recv.List) != 1 || recvTypeName(fn.Recv.List[0].Type) != "TestDeps" {
		return "", "", "", "", nil, false
	}
	if fn.Type.Params == nil || fn.Type.Params.NumFields() != 1 || (fn.Type.Results != nil && fn.Type.Results.NumFields() != 0) {
		return "", "", "", "", nil, false
	}
	reserved := map[string]bool{"testlog": true, "bufio": true, "true": true, "false": true, "nil": true}
	if funcShadowsAnyIdent(fn, reserved) {
		return "", "", "", "", nil, false
	}
	paramNames := fn.Type.Params.List[0].Names
	if len(paramNames) != 1 || paramNames[0].Name == "" || paramNames[0].Name == "_" || reserved[paramNames[0].Name] {
		return "", "", "", "", nil, false
	}
	wName := paramNames[0].Name
	wSet := map[string]bool{wName: true}
	localDefs := map[string]bool{wName: true}
	if recv := recvVarName(fn); recv != "" {
		localDefs[recv] = true
	}

	allowedBaseIdents = map[*ast.Ident]bool{}
	allowedWIdents := map[*ast.Ident]bool{paramNames[0]: true}
	var hasSetLoggerCall, bindsWriter, sawGuard bool

	recordMu := func(bID *ast.Ident, fName string) bool {
		if bID == nil || fName == "" || (boundBase != "" && bID.Name != boundBase) || (boundField != "" && fName == boundField) || (setField != "" && fName == setField) {
			return false
		}
		if muField != "" && muField != fName {
			return false
		}
		if boundBase == "" {
			if localDefs[bID.Name] {
				return false
			}
			boundBase = bID.Name
		}
		muField = fName
		allowedBaseIdents[bID] = true
		return true
	}

	var walkStmts func(stmts []ast.Stmt, inGuard bool) bool
	walkStmts = func(stmts []ast.Stmt, inGuard bool) bool {
		for idx, stmt := range stmts {
			switch s := stmt.(type) {
			case *ast.EmptyStmt:
				continue
			case *ast.ReturnStmt:
				if inGuard || len(s.Results) != 0 || idx != len(stmts)-1 {
					return false
				}
			case *ast.DeferStmt:
				sel, ok := unwrapParens(s.Call.Fun).(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Unlock" || s.Call.Ellipsis.IsValid() || len(s.Call.Args) != 0 {
					return false
				}
				muSel, ok := unwrapParens(sel.X).(*ast.SelectorExpr)
				if !ok {
					return false
				}
				bID, ok := unwrapParens(muSel.X).(*ast.Ident)
				if !ok || !recordMu(bID, muSel.Sel.Name) {
					return false
				}
			case *ast.DeclStmt:
				gd, ok := s.Decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					return false
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || (len(vs.Values) != 0 && len(vs.Values) != len(vs.Names)) {
						return false
					}
					for i, nameID := range vs.Names {
						if nameID.Name == "" || nameID.Name == "_" || wSet[nameID.Name] || (boundBase != "" && nameID.Name == boundBase) {
							return false
						}
						if i < len(vs.Values) {
							if exprReferencesDiscard(vs.Values[i]) {
								return false
							}
							if rhsID, ok := unwrapParens(vs.Values[i]).(*ast.Ident); ok && wSet[rhsID.Name] {
								if inGuard {
									return false
								}
								allowedWIdents[nameID] = true
								allowedWIdents[rhsID] = true
								wSet[nameID.Name] = true
							} else if exprReferencesAnyIdent(vs.Values[i], wSet) {
								return false
							}
						}
						localDefs[nameID.Name] = true
					}
				}
			case *ast.AssignStmt:
				if len(s.Lhs) != 1 || len(s.Rhs) != 1 || exprReferencesDiscard(s.Rhs[0]) {
					return false
				}
				switch s.Tok {
				case token.DEFINE:
					id, ok := unwrapParens(s.Lhs[0]).(*ast.Ident)
					if !ok || id.Name == "" || id.Name == "_" || wSet[id.Name] || (boundBase != "" && id.Name == boundBase) {
						return false
					}
					if rhsID, ok := unwrapParens(s.Rhs[0]).(*ast.Ident); ok && wSet[rhsID.Name] {
						if inGuard {
							return false
						}
						allowedWIdents[id] = true
						allowedWIdents[rhsID] = true
						wSet[id.Name] = true
					} else if exprReferencesAnyIdent(s.Rhs[0], wSet) {
						return false
					}
					localDefs[id.Name] = true
				case token.ASSIGN:
					sel, ok := unwrapParens(s.Lhs[0]).(*ast.SelectorExpr)
					if !ok || sel.Sel.Name == "" {
						return false
					}
					baseID, ok := unwrapParens(sel.X).(*ast.Ident)
					if !ok || baseID.Name == "" || baseID.Name == "_" || localDefs[baseID.Name] {
						return false
					}
					if inGuard {
						if !bindsWriter || setField == "" || baseID.Name != boundBase || sel.Sel.Name != setField {
							return false
						}
						if _, ok := isIdentNamed(s.Rhs[0], "true"); !ok {
							return false
						}
						allowedBaseIdents[baseID] = true
						continue
					}
					if bindsWriter || !isBufioNewWriterForW(s.Rhs[0], wSet) {
						return false
					}
					if (boundBase != "" && baseID.Name != boundBase) || (muField != "" && sel.Sel.Name == muField) {
						return false
					}
					call := unwrapParens(s.Rhs[0]).(*ast.CallExpr)
					allowedWIdents[unwrapParens(call.Args[0]).(*ast.Ident)] = true
					boundBase = baseID.Name
					boundField = sel.Sel.Name
					bindsWriter = true
					allowedBaseIdents[baseID] = true
				default:
					return false
				}
			case *ast.ExprStmt:
				call, ok := unwrapParens(s.X).(*ast.CallExpr)
				if !ok {
					return false
				}
				sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
				if !ok {
					return false
				}
				if sel.Sel.Name == "SetLogger" {
					if _, ok := isIdentNamed(sel.X, "testlog"); !ok || call.Ellipsis.IsValid() || len(call.Args) != 1 || !bindsWriter || hasSetLoggerCall {
						return false
					}
					bID, ok := isSetLoggerTargetForBase(call.Args[0], boundBase)
					if !ok {
						return false
					}
					allowedBaseIdents[bID] = true
					hasSetLoggerCall = true
					continue
				}
				if (sel.Sel.Name == "Lock" || sel.Sel.Name == "Unlock") && !inGuard && !call.Ellipsis.IsValid() && len(call.Args) == 0 {
					muSel, ok := unwrapParens(sel.X).(*ast.SelectorExpr)
					if !ok {
						return false
					}
					bID, ok := unwrapParens(muSel.X).(*ast.Ident)
					if !ok || !recordMu(bID, muSel.Sel.Name) {
						return false
					}
					continue
				}
				if bID, ok := isCommentHeaderWriteCall(call, boundBase, boundField); ok && bindsWriter {
					allowedBaseIdents[bID] = true
					continue
				}
				return false
			case *ast.IfStmt:
				if inGuard || sawGuard || !bindsWriter || s.Init != nil || s.Else != nil {
					return false
				}
				gBaseID, gField, ok := negatedFieldOnBase(s.Cond)
				if !ok || gBaseID.Name != boundBase || gField == boundField || (muField != "" && gField == muField) {
					return false
				}
				setField = gField
				sawGuard = true
				allowedBaseIdents[gBaseID] = true
				if !walkStmts(s.Body.List, true) {
					return false
				}
			case *ast.BlockStmt:
				if !walkStmts(s.List, inGuard) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}

	if !walkStmts(fn.Body.List, false) || !bindsWriter || !hasSetLoggerCall || boundBase == "" || boundField == "" {
		return "", "", "", "", nil, false
	}

	var invalid bool
	walkNonSelectorPropIdents(fn.Body, func(id *ast.Ident) {
		if wSet[id.Name] && !allowedWIdents[id] {
			invalid = true
		}
		if id.Name == boundBase && !allowedBaseIdents[id] {
			invalid = true
		}
	})
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if invalid || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.FuncLit, *ast.GoStmt, *ast.LabeledStmt, *ast.BranchStmt:
			invalid = true
			return false
		case *ast.UnaryExpr:
			if node.Op == token.AND {
				if id, ok := unwrapParens(node.X).(*ast.Ident); ok && wSet[id.Name] {
					invalid = true
					return false
				}
			}
		}
		return true
	})
	if invalid {
		return "", "", "", "", nil, false
	}
	return boundBase, boundField, muField, setField, allowedBaseIdents, true
}

func isTargetSinkFlushCall(expr ast.Expr, boundBase, boundField string) (*ast.Ident, bool) {
	if boundBase == "" || boundField == "" {
		return nil, false
	}
	return isZeroArgMethodCallOnSelector(expr, boundBase, boundField, "Flush")
}

func verifyTestdepsStopFunc(fn *ast.FuncDecl, boundBase, boundField, muField string) (map[*ast.Ident]bool, bool) {
	if boundBase == "" || boundField == "" || fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || fn.Recv == nil || len(fn.Recv.List) != 1 || recvTypeName(fn.Recv.List[0].Type) != "TestDeps" {
		return nil, false
	}
	if (fn.Type.Params != nil && fn.Type.Params.NumFields() != 0) || fn.Type.Results == nil || fn.Type.Results.NumFields() != 1 || !funcReturnsErrorLast(fn.Type) {
		return nil, false
	}
	if funcShadowsAnyIdent(fn, map[string]bool{boundBase: true, "nil": true, "error": true}) || !blockAlwaysReturns(fn.Body.List) {
		return nil, false
	}
	namedErr := lastNamedResultIdent(fn.Type.Results)
	type stopPathState struct {
		flushed     bool
		clearedNil  bool
		flushErrVar string
	}
	allFlushErrVars := map[string]bool{}
	allowedBaseIdents := map[*ast.Ident]bool{}
	var sawPropagatedReturn bool

	checkMuLockUnlock := func(call *ast.CallExpr, allowLock bool) bool {
		if muField == "" || call == nil || call.Ellipsis.IsValid() || len(call.Args) != 0 {
			return false
		}
		sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Unlock" && (!allowLock || sel.Sel.Name != "Lock")) {
			return false
		}
		bID, ok := isSelectorBaseField(sel.X, boundBase, muField)
		if !ok {
			return false
		}
		allowedBaseIdents[bID] = true
		return true
	}

	var walkStmts func(stmts []ast.Stmt, st stopPathState) (stopPathState, bool)
	walkStmts = func(stmts []ast.Stmt, st stopPathState) (stopPathState, bool) {
		for idx, stmt := range stmts {
			if idx != len(stmts)-1 && blockAlwaysReturns([]ast.Stmt{stmt}) {
				return st, false
			}
			switch s := stmt.(type) {
			case *ast.EmptyStmt:
				continue
			case *ast.ExprStmt:
				call, ok := unwrapParens(s.X).(*ast.CallExpr)
				if !ok || !checkMuLockUnlock(call, true) {
					return st, false
				}
			case *ast.DeferStmt:
				if !checkMuLockUnlock(s.Call, false) {
					return st, false
				}
			case *ast.AssignStmt:
				if len(s.Lhs) != 1 || len(s.Rhs) != 1 {
					return st, false
				}
				if bID, ok := isTargetSinkFlushCall(s.Rhs[0], boundBase, boundField); ok {
					if st.flushed || (s.Tok != token.DEFINE && s.Tok != token.ASSIGN) {
						return st, false
					}
					id, ok := unwrapParens(s.Lhs[0]).(*ast.Ident)
					if !ok || id.Name == "" || id.Name == "_" || id.Name == boundBase || (allFlushErrVars[id.Name] && id.Name != namedErr) {
						return st, false
					}
					allowedBaseIdents[bID] = true
					allFlushErrVars[id.Name] = true
					st.flushed = true
					st.flushErrVar = id.Name
					continue
				}
				// Require `log.w = nil` AFTER `log.w.Flush()` has already run on this path.
				if st.flushed && !st.clearedNil && s.Tok == token.ASSIGN {
					if bID, ok := isSelectorBaseField(s.Lhs[0], boundBase, boundField); ok {
						if _, isNil := isIdentNamed(s.Rhs[0], "nil"); isNil {
							allowedBaseIdents[bID] = true
							st.clearedNil = true
							continue
						}
					}
				}
				return st, false
			case *ast.DeclStmt:
				gd, ok := s.Decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					return st, false
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						return st, false
					}
					if len(vs.Values) == 1 {
						if bID, ok := isTargetSinkFlushCall(vs.Values[0], boundBase, boundField); ok {
							if st.flushed || len(vs.Names) != 1 || vs.Names[0].Name == "" || vs.Names[0].Name == "_" || vs.Names[0].Name == boundBase || allFlushErrVars[vs.Names[0].Name] || (namedErr != "" && vs.Names[0].Name == namedErr) {
								return st, false
							}
							allowedBaseIdents[bID] = true
							allFlushErrVars[vs.Names[0].Name] = true
							st.flushed = true
							st.flushErrVar = vs.Names[0].Name
							continue
						}
					}
					if len(vs.Values) != 0 {
						return st, false
					}
					for _, id := range vs.Names {
						if id.Name == boundBase || allFlushErrVars[id.Name] || (st.flushErrVar != "" && id.Name == st.flushErrVar) || (namedErr != "" && id.Name == namedErr) {
							return st, false
						}
					}
				}
			case *ast.BlockStmt:
				var ok bool
				st, ok = walkStmts(s.List, st)
				if !ok {
					return st, false
				}
			case *ast.ReturnStmt:
				if !st.flushed || !st.clearedNil {
					return st, false
				}
				if len(s.Results) == 0 {
					if namedErr == "" || st.flushErrVar != namedErr {
						return st, false
					}
					sawPropagatedReturn = true
					continue
				}
				if len(s.Results) != 1 {
					return st, false
				}
				res := unwrapParens(s.Results[0])
				if id, ok := res.(*ast.Ident); ok && st.flushErrVar != "" && id.Name == st.flushErrVar {
					sawPropagatedReturn = true
					continue
				}
				return st, false
			default:
				return st, false
			}
		}
		return st, true
	}

	if _, ok := walkStmts(fn.Body.List, stopPathState{}); !ok || !sawPropagatedReturn {
		return nil, false
	}

	protectedErrs := map[string]bool{boundBase: true}
	if namedErr != "" {
		protectedErrs[namedErr] = true
	}
	for k := range allFlushErrVars {
		protectedErrs[k] = true
	}
	var bad bool
	walkNonSelectorPropIdents(fn.Body, func(id *ast.Ident) {
		if id.Name == boundBase && !allowedBaseIdents[id] {
			bad = true
		}
	})
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if bad || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.FuncLit, *ast.GoStmt, *ast.LabeledStmt, *ast.BranchStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
			bad = true
			return false
		case *ast.UnaryExpr:
			if node.Op == token.AND {
				if id, ok := unwrapParens(node.X).(*ast.Ident); ok && protectedErrs[id.Name] {
					bad = true
					return false
				}
			}
		case *ast.IncDecStmt:
			if id, ok := unwrapParens(node.X).(*ast.Ident); ok && protectedErrs[id.Name] {
				bad = true
				return false
			}
		}
		return true
	})
	if bad {
		return nil, false
	}
	return allowedBaseIdents, true
}

func verifyTestdepsLoggerMethods(loggerType, boundField, muField string, methods map[string]*ast.FuncDecl, methodFiles map[*ast.FuncDecl]*ast.File, fileImportsStrings map[*ast.File]bool) bool {
	if len(methods) != 5 {
		return false
	}
	reserved := map[string]bool{"strings": true, "nil": true, "string": true}
	wantOps := map[string]string{
		"Getenv": "getenv",
		"Open":   "open",
		"Stat":   "stat",
		"Chdir":  "chdir",
	}
	for mName, wantOp := range wantOps {
		fn := methods[mName]
		if fn == nil || fn.Body == nil || fn.Type.TypeParams != nil || fn.Recv == nil || len(fn.Recv.List) != 1 || (fn.Type.Results != nil && fn.Type.Results.NumFields() != 0) || len(fn.Body.List) != 1 || funcShadowsAnyIdent(fn, reserved) {
			return false
		}
		star, ok := unwrapParens(fn.Recv.List[0].Type).(*ast.StarExpr)
		if !ok {
			return false
		}
		if _, ok := isIdentNamed(star.X, loggerType); !ok {
			return false
		}
		recv := recvVarName(fn)
		pNames := paramNamesFlat(fn.Type.Params)
		if recv == "" || len(pNames) != 1 || pNames[0] == "" || pNames[0] == "_" || pNames[0] == recv || len(fn.Type.Params.List) != 1 {
			return false
		}
		if _, ok := isIdentNamed(fn.Type.Params.List[0].Type, "string"); !ok {
			return false
		}
		es, ok := fn.Body.List[0].(*ast.ExprStmt)
		if !ok {
			return false
		}
		call, ok := unwrapParens(es.X).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) != 2 {
			return false
		}
		if _, ok := isSelectorBaseField(call.Fun, recv, "add"); !ok {
			return false
		}
		lit, ok := unwrapParens(call.Args[0]).(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return false
		}
		if s, err := strconv.Unquote(lit.Value); err != nil || s != wantOp {
			return false
		}
		if _, ok := isIdentNamed(call.Args[1], pNames[0]); !ok {
			return false
		}
	}

	// Verify (l *testLog) add(op, name string)
	addFn := methods["add"]
	if addFn == nil || addFn.Body == nil || !fileImportsStrings[methodFiles[addFn]] || addFn.Type.TypeParams != nil || addFn.Recv == nil || len(addFn.Recv.List) != 1 || (addFn.Type.Results != nil && addFn.Type.Results.NumFields() != 0) || funcShadowsAnyIdent(addFn, reserved) {
		return false
	}
	star, ok := unwrapParens(addFn.Recv.List[0].Type).(*ast.StarExpr)
	if !ok {
		return false
	}
	if _, ok := isIdentNamed(star.X, loggerType); !ok {
		return false
	}
	recv := recvVarName(addFn)
	pNames := paramNamesFlat(addFn.Type.Params)
	if recv == "" || len(pNames) != 2 || pNames[0] == "" || pNames[0] == "_" || pNames[1] == "" || pNames[1] == "_" || pNames[0] == pNames[1] || pNames[0] == recv || pNames[1] == recv {
		return false
	}
	for _, fld := range addFn.Type.Params.List {
		if _, ok := isIdentNamed(fld.Type, "string"); !ok {
			return false
		}
	}
	opParam, nameParam := pNames[0], pNames[1]
	if bodyDeclaresAnyIdent(addFn.Body, map[string]bool{recv: true, opParam: true, nameParam: true}) {
		return false
	}

	stmts := addFn.Body.List
	if len(stmts) < 6 {
		return false
	}
	// Stmt 0: if strings.Contains(name, "\n") || name == "" { return }
	isContainsNewline := func(e ast.Expr) bool {
		c, ok := unwrapParens(e).(*ast.CallExpr)
		if !ok || c.Ellipsis.IsValid() || len(c.Args) != 2 {
			return false
		}
		if _, ok := isSelectorBaseField(c.Fun, "strings", "Contains"); !ok {
			return false
		}
		if _, ok := isIdentNamed(c.Args[0], nameParam); !ok {
			return false
		}
		lit, ok := unwrapParens(c.Args[1]).(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return false
		}
		v, err := strconv.Unquote(lit.Value)
		return err == nil && v == "\n"
	}
	isEmptyNameEq := func(e ast.Expr) bool {
		b, ok := unwrapParens(e).(*ast.BinaryExpr)
		if !ok || b.Op != token.EQL {
			return false
		}
		check := func(x, y ast.Expr) bool {
			if _, ok := isIdentNamed(x, nameParam); !ok {
				return false
			}
			lit, ok := unwrapParens(y).(*ast.BasicLit)
			return ok && lit.Kind == token.STRING && (lit.Value == `""` || lit.Value == "``")
		}
		return check(b.X, b.Y) || check(b.Y, b.X)
	}
	isEmptyReturnIf := func(s ast.Stmt) (*ast.IfStmt, bool) {
		ifs, ok := s.(*ast.IfStmt)
		if !ok || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
			return nil, false
		}
		ret, ok := ifs.Body.List[0].(*ast.ReturnStmt)
		return ifs, ok && len(ret.Results) == 0
	}

	s0If, ok := isEmptyReturnIf(stmts[0])
	if !ok {
		return false
	}
	orCond, ok := unwrapParens(s0If.Cond).(*ast.BinaryExpr)
	if !ok || orCond.Op != token.LOR || !((isContainsNewline(orCond.X) && isEmptyNameEq(orCond.Y)) || (isEmptyNameEq(orCond.X) && isContainsNewline(orCond.Y))) {
		return false
	}

	pos := 1
	if muField != "" {
		if pos+2 > len(stmts) {
			return false
		}
		lockES, ok1 := stmts[pos].(*ast.ExprStmt)
		deferUnlock, ok2 := stmts[pos+1].(*ast.DeferStmt)
		if !ok1 || !ok2 {
			return false
		}
		if _, ok := isZeroArgMethodCallOnSelector(lockES.X, recv, muField, "Lock"); !ok {
			return false
		}
		if _, ok := isZeroArgMethodCallOnSelector(deferUnlock.Call, recv, muField, "Unlock"); !ok {
			return false
		}
		pos += 2
	}
	if len(stmts)-pos != 5 {
		return false
	}
	// if l.w == nil { return }
	nilIf, ok := isEmptyReturnIf(stmts[pos])
	if !ok {
		return false
	}
	eqCond, ok := unwrapParens(nilIf.Cond).(*ast.BinaryExpr)
	if !ok || eqCond.Op != token.EQL {
		return false
	}
	checkNilWriter := func(x, y ast.Expr) bool {
		_, ok1 := isSelectorBaseField(x, recv, boundField)
		_, ok2 := isIdentNamed(y, "nil")
		return ok1 && ok2
	}
	if !checkNilWriter(eqCond.X, eqCond.Y) && !checkNilWriter(eqCond.Y, eqCond.X) {
		return false
	}
	pos++

	checkWriteIdent := func(s ast.Stmt, wantIdent string) bool {
		es, ok := s.(*ast.ExprStmt)
		if !ok {
			return false
		}
		c, ok := unwrapParens(es.X).(*ast.CallExpr)
		if !ok || c.Ellipsis.IsValid() || len(c.Args) != 1 {
			return false
		}
		sel, ok := unwrapParens(c.Fun).(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "WriteString" {
			return false
		}
		if _, ok := isSelectorBaseField(sel.X, recv, boundField); !ok {
			return false
		}
		_, ok = isIdentNamed(c.Args[0], wantIdent)
		return ok
	}
	checkWriteConstByte := func(s ast.Stmt, want byte) bool {
		es, ok := s.(*ast.ExprStmt)
		if !ok {
			return false
		}
		c, ok := unwrapParens(es.X).(*ast.CallExpr)
		if !ok || c.Ellipsis.IsValid() || len(c.Args) != 1 {
			return false
		}
		sel, ok := unwrapParens(c.Fun).(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if _, ok := isSelectorBaseField(sel.X, recv, boundField); !ok {
			return false
		}
		lit, ok := unwrapParens(c.Args[0]).(*ast.BasicLit)
		if !ok {
			return false
		}
		switch sel.Sel.Name {
		case "WriteByte":
			if lit.Kind != token.CHAR {
				return false
			}
			v, _, tail, err := strconv.UnquoteChar(strings.Trim(lit.Value, "'"), '\'')
			return err == nil && tail == "" && v == rune(want)
		case "WriteString":
			if lit.Kind != token.STRING {
				return false
			}
			v, err := strconv.Unquote(lit.Value)
			return err == nil && len(v) == 1 && v[0] == want
		default:
			return false
		}
	}

	return checkWriteIdent(stmts[pos], opParam) &&
		checkWriteConstByte(stmts[pos+1], ' ') &&
		checkWriteIdent(stmts[pos+2], nameParam) &&
		checkWriteConstByte(stmts[pos+3], '\n')
}

func verifyTestdepsPackageAST(files []*ast.File) error {
	reserved := map[string]bool{
		"testlog": true, "bufio": true, "strings": true, "sync": true,
		"panic": true, "recover": true, "nil": true, "true": true, "false": true,
	}
	fileImportsTestlog := map[*ast.File]bool{}
	fileImportsBufio := map[*ast.File]bool{}
	fileImportsStrings := map[*ast.File]bool{}
	fileImportsSync := map[*ast.File]bool{}
	typeSpecs := map[string][]*ast.TypeSpec{}
	typeSpecFiles := map[*ast.TypeSpec]*ast.File{}
	typeMethods := map[string]map[string]*ast.FuncDecl{}
	methodFiles := map[*ast.FuncDecl]*ast.File{}
	var dupMethods, hasInitOrBodyless bool
	var startFns, stopFns []*ast.FuncDecl
	fnFile := map[*ast.FuncDecl]*ast.File{}

	for _, f := range files {
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			if imp.Name != nil && (imp.Name.Name == "." || reserved[imp.Name.Name]) {
				return fmt.Errorf("testing/internal/testdeps: forbidden or shadowing import alias %q", imp.Name.Name)
			}
			switch path {
			case "internal/testlog":
				if imp.Name != nil {
					return fmt.Errorf("testing/internal/testdeps: aliased import of internal/testlog forbidden")
				}
				fileImportsTestlog[f] = true
			case "bufio":
				if imp.Name != nil {
					return fmt.Errorf("testing/internal/testdeps: aliased import of bufio forbidden")
				}
				fileImportsBufio[f] = true
			case "strings":
				if imp.Name != nil {
					return fmt.Errorf("testing/internal/testdeps: aliased import of strings forbidden")
				}
				fileImportsStrings[f] = true
			case "sync":
				if imp.Name != nil {
					return fmt.Errorf("testing/internal/testdeps: aliased import of sync forbidden")
				}
				fileImportsSync[f] = true
			}
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.TypeSpec:
						if sp.Name != nil {
							if reserved[sp.Name.Name] {
								return fmt.Errorf("testing/internal/testdeps: type shadows %s", sp.Name.Name)
							}
							typeSpecs[sp.Name.Name] = append(typeSpecs[sp.Name.Name], sp)
							typeSpecFiles[sp] = f
						}
					case *ast.ValueSpec:
						for _, id := range sp.Names {
							if reserved[id.Name] {
								return fmt.Errorf("testing/internal/testdeps: declaration shadows %s", id.Name)
							}
						}
					}
				}
			case *ast.FuncDecl:
				if d.Body == nil || (d.Recv == nil && d.Name.Name == "init") {
					hasInitOrBodyless = true
				}
				if d.Recv == nil && reserved[d.Name.Name] {
					return fmt.Errorf("testing/internal/testdeps: function shadows %s", d.Name.Name)
				}
				if d.Recv != nil && len(d.Recv.List) == 1 {
					if rType := recvTypeName(d.Recv.List[0].Type); rType != "" {
						if typeMethods[rType] == nil {
							typeMethods[rType] = map[string]*ast.FuncDecl{}
						}
						if _, dup := typeMethods[rType][d.Name.Name]; dup {
							dupMethods = true
						}
						typeMethods[rType][d.Name.Name] = d
						methodFiles[d] = f
					}
				}
				switch d.Name.Name {
				case "StartTestLog":
					startFns = append(startFns, d)
					fnFile[d] = f
				case "StopTestLog":
					stopFns = append(stopFns, d)
					fnFile[d] = f
				}
			}
		}
	}
	if hasInitOrBodyless || dupMethods || len(fileImportsTestlog) == 0 || len(startFns) != 1 || len(stopFns) != 1 {
		return fmt.Errorf("testing/internal/testdeps: incomplete or duplicate testlog harness declarations")
	}

	// Verify TestDeps is an empty struct.
	tdSpecs := typeSpecs["TestDeps"]
	if len(tdSpecs) != 1 || tdSpecs[0].Assign.IsValid() || tdSpecs[0].TypeParams != nil {
		return fmt.Errorf("testing/internal/testdeps: missing or invalid TestDeps type")
	}
	if tdStruct, ok := unwrapParens(tdSpecs[0].Type).(*ast.StructType); !ok || (tdStruct.Fields != nil && len(tdStruct.Fields.List) != 0) {
		return fmt.Errorf("testing/internal/testdeps: TestDeps must be an empty struct")
	}

	startFn, stopFn := startFns[0], stopFns[0]
	boundBase, boundField, muField, setField, startAllowedBase, ok := verifyTestdepsStartFunc(startFn, fileImportsTestlog[fnFile[startFn]], fileImportsBufio[fnFile[startFn]])
	if !ok {
		return fmt.Errorf("testing/internal/testdeps: StartTestLog does not wire bufio.NewWriter and testlog.SetLogger")
	}
	stopAllowedBase, ok := verifyTestdepsStopFunc(stopFn, boundBase, boundField, muField)
	if !ok {
		return fmt.Errorf("testing/internal/testdeps: StopTestLog does not flush %s.%s and propagate error", boundBase, boundField)
	}

	allowedBaseIdents := map[*ast.Ident]bool{}
	for id := range startAllowedBase {
		allowedBaseIdents[id] = true
	}
	for id := range stopAllowedBase {
		allowedBaseIdents[id] = true
	}

	// Locate zero-initialized `var <boundBase> <loggerType>` and verify <loggerType>.
	var loggerType string
	var varDeclCount int
	allowedLoggerTypeIdents := map[*ast.Ident]bool{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, id := range vs.Names {
					if id.Name != boundBase {
						continue
					}
					varDeclCount++
					if len(vs.Names) != 1 || len(vs.Values) != 0 {
						return fmt.Errorf("testing/internal/testdeps: %s must be a zero-initialized package variable", boundBase)
					}
					tID, ok := unwrapParens(vs.Type).(*ast.Ident)
					if !ok || tID.Name == "" || ast.IsExported(tID.Name) {
						return fmt.Errorf("testing/internal/testdeps: %s must have an unexported named logger struct type", boundBase)
					}
					loggerType = tID.Name
					allowedBaseIdents[id] = true
					allowedLoggerTypeIdents[tID] = true
				}
			}
		}
	}
	if varDeclCount != 1 || loggerType == "" {
		return fmt.Errorf("testing/internal/testdeps: missing unique var %s declaration", boundBase)
	}

	lSpecs := typeSpecs[loggerType]
	if len(lSpecs) != 1 || lSpecs[0].Assign.IsValid() || lSpecs[0].TypeParams != nil {
		return fmt.Errorf("testing/internal/testdeps: invalid logger struct %s", loggerType)
	}
	allowedLoggerTypeIdents[lSpecs[0].Name] = true
	lFile := typeSpecFiles[lSpecs[0]]
	lStruct, ok := unwrapParens(lSpecs[0].Type).(*ast.StructType)
	if !ok || lStruct.Fields == nil {
		return fmt.Errorf("testing/internal/testdeps: %s is not a struct", loggerType)
	}
	lFields := map[string]ast.Expr{}
	for _, fld := range lStruct.Fields.List {
		if len(fld.Names) == 0 {
			return fmt.Errorf("testing/internal/testdeps: embedded field on %s forbidden", loggerType)
		}
		for _, id := range fld.Names {
			lFields[id.Name] = fld.Type
		}
	}
	// Verify boundField is *bufio.Writer, muField (if used) is sync.Mutex, setField (if used) is bool.
	wStar, ok := unwrapParens(lFields[boundField]).(*ast.StarExpr)
	if !ok || !fileImportsBufio[lFile] {
		return fmt.Errorf("testing/internal/testdeps: %s.%s is not *bufio.Writer", loggerType, boundField)
	}
	if _, ok := isSelectorBaseField(wStar.X, "bufio", "Writer"); !ok {
		return fmt.Errorf("testing/internal/testdeps: %s.%s is not *bufio.Writer", loggerType, boundField)
	}
	if muField != "" {
		if !fileImportsSync[lFile] {
			return fmt.Errorf("testing/internal/testdeps: missing sync import for %s.%s", loggerType, muField)
		}
		if _, ok := isSelectorBaseField(lFields[muField], "sync", "Mutex"); !ok {
			return fmt.Errorf("testing/internal/testdeps: %s.%s is not sync.Mutex", loggerType, muField)
		}
	}
	if setField != "" {
		if _, ok := isIdentNamed(lFields[setField], "bool"); !ok {
			return fmt.Errorf("testing/internal/testdeps: %s.%s is not bool", loggerType, setField)
		}
	}

	lMethods := typeMethods[loggerType]
	for _, m := range lMethods {
		if rID := recvTypeIdent(m.Recv.List[0].Type); rID != nil && rID.Name == loggerType {
			allowedLoggerTypeIdents[rID] = true
		}
	}
	if !verifyTestdepsLoggerMethods(loggerType, boundField, muField, lMethods, methodFiles, fileImportsStrings) {
		return fmt.Errorf("testing/internal/testdeps: %s methods do not faithfully format testlog records", loggerType)
	}

	// Ensure neither <boundBase> nor <loggerType> is referenced anywhere else in testing/internal/testdeps.
	var escaped bool
	for _, f := range files {
		walkNonSelectorPropIdents(f, func(id *ast.Ident) {
			if id.Name == boundBase && !allowedBaseIdents[id] {
				escaped = true
			}
			if id.Name == loggerType && !allowedLoggerTypeIdents[id] {
				escaped = true
			}
		})
		if escaped {
			return fmt.Errorf("testing/internal/testdeps: %s or %s referenced outside StartTestLog/StopTestLog", boundBase, loggerType)
		}
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

func unwrapParens(expr ast.Expr) ast.Expr {
	for {
		p, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = p.X
	}
}

func recvTypeName(expr ast.Expr) string {
	expr = unwrapParens(expr)
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = unwrapParens(star.X)
	}
	if id, ok := expr.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func recvVarName(fn *ast.FuncDecl) string {
	if fn == nil || fn.Recv == nil || len(fn.Recv.List) != 1 {
		return ""
	}
	names := fn.Recv.List[0].Names
	if len(names) != 1 || names[0].Name == "_" {
		return ""
	}
	return names[0].Name
}

func compositeWriterLit(expr ast.Expr) (*ast.CompositeLit, string) {
	expr = unwrapParens(expr)
	if u, ok := expr.(*ast.UnaryExpr); ok && u.Op == token.AND {
		expr = unwrapParens(u.X)
	}
	lit, ok := expr.(*ast.CompositeLit)
	if !ok || lit.Type == nil {
		return nil, ""
	}
	id, ok := unwrapParens(lit.Type).(*ast.Ident)
	if !ok {
		return nil, ""
	}
	return lit, id.Name
}

func funcReturnsErrorLast(ft *ast.FuncType) bool {
	if ft == nil || ft.Results == nil || len(ft.Results.List) == 0 {
		return false
	}
	last := ft.Results.List[len(ft.Results.List)-1]
	id, ok := unwrapParens(last.Type).(*ast.Ident)
	return ok && id.Name == "error"
}

func lastNamedResultIdent(results *ast.FieldList) string {
	if results == nil || len(results.List) == 0 {
		return ""
	}
	last := results.List[len(results.List)-1]
	if len(last.Names) == 0 {
		return ""
	}
	name := last.Names[len(last.Names)-1].Name
	if name == "_" {
		return ""
	}
	return name
}

func paramNamesFlat(params *ast.FieldList) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, field := range params.List {
		if len(field.Names) == 0 {
			out = append(out, "")
			continue
		}
		for _, n := range field.Names {
			out = append(out, n.Name)
		}
	}
	return out
}

func syscallWriteSinkKind(call *ast.CallExpr) string {
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	id, ok := unwrapParens(sel.X).(*ast.Ident)
	if !ok || id.Name != "syscall" {
		return ""
	}
	switch sel.Sel.Name {
	case "Write":
		return "write2"
	case "Syscall", "RawSyscall", "Syscall6":
		return "raw3"
	default:
		return ""
	}
}

func isSysWriteConstExpr(expr ast.Expr) bool {
	sel, ok := unwrapParens(expr).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "SYS_WRITE" {
		return false
	}
	id, ok := unwrapParens(sel.X).(*ast.Ident)
	return ok && id.Name == "syscall"
}

func exprReferencesAnyIdent(expr ast.Node, names map[string]bool) bool {
	if expr == nil || len(names) == 0 {
		return false
	}
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		if kv, ok := n.(*ast.KeyValueExpr); ok {
			if exprReferencesAnyIdent(kv.Value, names) {
				found = true
			}
			return false
		}
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if exprReferencesAnyIdent(sel.X, names) {
				found = true
			}
			return false
		}
		if id, ok := n.(*ast.Ident); ok && names[id.Name] {
			found = true
			return false
		}
		return true
	})
	return found
}

type testingWriterBinding struct {
	fileFields map[string]bool
	fdFields   map[string]bool
	fileVars   map[string]bool
	fdVars     map[string]bool
	emptyVars  map[string]bool
	sliceVar   string
}

func isOneArgLenIdentCall(call *ast.CallExpr) bool {
	if call == nil || call.Ellipsis.IsValid() || len(call.Args) != 1 {
		return false
	}
	funID, ok := unwrapParens(call.Fun).(*ast.Ident)
	if !ok || funID.Name != "len" {
		return false
	}
	_, ok = unwrapParens(call.Args[0]).(*ast.Ident)
	return ok
}

func exprRefsIdentOutsideLen(expr ast.Expr, names map[string]bool) bool {
	if expr == nil || len(names) == 0 {
		return false
	}
	found := false
	var walk func(n ast.Node)
	walk = func(n ast.Node) {
		if found || n == nil {
			return
		}
		if call, isCall := n.(*ast.CallExpr); isCall && isOneArgLenIdentCall(call) {
			return
		}
		switch node := n.(type) {
		case *ast.SelectorExpr:
			walk(node.X)
		case *ast.KeyValueExpr:
			walk(node.Value)
		case *ast.Ident:
			if names[node.Name] {
				found = true
			}
		default:
			ast.Inspect(node, func(ch ast.Node) bool {
				if ch == node {
					return true
				}
				walk(ch)
				return false
			})
		}
	}
	walk(expr)
	return found
}

func isProvablyEmptyByteSliceArg(expr ast.Expr, binding testingWriterBinding) bool {
	switch e := unwrapParens(expr).(type) {
	case *ast.Ident:
		return e.Name == "nil" || binding.emptyVars[e.Name]
	case *ast.BasicLit:
		return e.Kind == token.STRING && (e.Value == `""` || e.Value == "``")
	case *ast.CompositeLit:
		return len(e.Elts) == 0 && e.Type != nil && isByteSliceType(e.Type)
	case *ast.CallExpr:
		if e.Ellipsis.IsValid() || len(e.Args) != 1 || !isByteSliceType(e.Fun) {
			return false
		}
		switch a := unwrapParens(e.Args[0]).(type) {
		case *ast.Ident:
			return a.Name == "nil"
		case *ast.BasicLit:
			return a.Kind == token.STRING && (a.Value == `""` || a.Value == "``")
		default:
			return false
		}
	default:
		return false
	}
}

func isByteSliceType(expr ast.Expr) bool {
	arr, ok := unwrapParens(expr).(*ast.ArrayType)
	if !ok || arr.Len != nil {
		return false
	}
	elt, ok := unwrapParens(arr.Elt).(*ast.Ident)
	return ok && elt.Name == "byte"
}

func byteSliceParamIdents(params *ast.FieldList) map[string]bool {
	out := map[string]bool{}
	if params == nil {
		return out
	}
	for _, field := range params.List {
		if !isByteSliceType(field.Type) {
			continue
		}
		for _, n := range field.Names {
			if n.Name != "" && n.Name != "_" {
				out[n.Name] = true
			}
		}
	}
	return out
}

func singleByteSliceParamIdent(params *ast.FieldList) string {
	if params == nil || params.NumFields() != 1 || len(params.List) != 1 || len(params.List[0].Names) != 1 {
		return ""
	}
	if !isByteSliceType(params.List[0].Type) {
		return ""
	}
	name := params.List[0].Names[0].Name
	if name == "" || name == "_" {
		return ""
	}
	return name
}

func firstResultIsInt(results *ast.FieldList) bool {
	if results == nil || len(results.List) == 0 {
		return false
	}
	first := results.List[0]
	id, ok := unwrapParens(first.Type).(*ast.Ident)
	return ok && id.Name == "int"
}

func firstNamedIntResultIdent(results *ast.FieldList) string {
	if results == nil || results.NumFields() != 2 || !firstResultIsInt(results) {
		return ""
	}
	first := results.List[0]
	if len(first.Names) == 0 {
		return ""
	}
	name := first.Names[0].Name
	if name == "_" {
		return ""
	}
	return name
}

func isZeroIntLit(expr ast.Expr) bool {
	lit, ok := unwrapParens(expr).(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == "0"
}

func isLenOfIdentCall(expr ast.Expr, identName string) bool {
	if identName == "" {
		return false
	}
	call, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || call.Ellipsis.IsValid() {
		return false
	}
	funID, ok := unwrapParens(call.Fun).(*ast.Ident)
	if !ok || funID.Name != "len" {
		return false
	}
	argID, ok := unwrapParens(call.Args[0]).(*ast.Ident)
	return ok && argID.Name == identName
}

func isSliceLenZeroCond(cond ast.Expr, sliceName string) bool {
	if sliceName == "" {
		return false
	}
	bin, ok := unwrapParens(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL {
		return false
	}
	return (isLenOfIdentCall(bin.X, sliceName) && isZeroIntLit(bin.Y)) ||
		(isZeroIntLit(bin.X) && isLenOfIdentCall(bin.Y, sliceName))
}

func isSliceZeroElemUintptrExpr(expr ast.Expr, sliceName string) (*ast.UnaryExpr, []*ast.CallExpr, bool) {
	if sliceName == "" {
		return nil, nil, false
	}
	uptrCall, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || len(uptrCall.Args) != 1 || uptrCall.Ellipsis.IsValid() {
		return nil, nil, false
	}
	uptrID, ok := unwrapParens(uptrCall.Fun).(*ast.Ident)
	if !ok || uptrID.Name != "uintptr" {
		return nil, nil, false
	}
	ptrCall, ok := unwrapParens(uptrCall.Args[0]).(*ast.CallExpr)
	if !ok || len(ptrCall.Args) != 1 || ptrCall.Ellipsis.IsValid() {
		return nil, nil, false
	}
	ptrSel, ok := unwrapParens(ptrCall.Fun).(*ast.SelectorExpr)
	if !ok || ptrSel.Sel.Name != "Pointer" {
		return nil, nil, false
	}
	unsafeID, ok := unwrapParens(ptrSel.X).(*ast.Ident)
	if !ok || unsafeID.Name != "unsafe" {
		return nil, nil, false
	}
	inner := unwrapParens(ptrCall.Args[0])
	if amp, ok := inner.(*ast.UnaryExpr); ok && amp.Op == token.AND {
		idx, ok := unwrapParens(amp.X).(*ast.IndexExpr)
		if !ok || !isZeroIntLit(idx.Index) {
			return nil, nil, false
		}
		sID, ok := unwrapParens(idx.X).(*ast.Ident)
		if !ok || sID.Name != sliceName {
			return nil, nil, false
		}
		return amp, []*ast.CallExpr{uptrCall, ptrCall}, true
	}
	if sdCall, ok := inner.(*ast.CallExpr); ok && len(sdCall.Args) == 1 && !sdCall.Ellipsis.IsValid() {
		sdSel, ok := unwrapParens(sdCall.Fun).(*ast.SelectorExpr)
		if !ok || sdSel.Sel.Name != "SliceData" {
			return nil, nil, false
		}
		uID, ok := unwrapParens(sdSel.X).(*ast.Ident)
		if !ok || uID.Name != "unsafe" {
			return nil, nil, false
		}
		sID, ok := unwrapParens(sdCall.Args[0]).(*ast.Ident)
		if !ok || sID.Name != sliceName {
			return nil, nil, false
		}
		return nil, []*ast.CallExpr{uptrCall, ptrCall, sdCall}, true
	}
	return nil, nil, false
}

func isSliceLenUintptrExpr(expr ast.Expr, sliceName string) bool {
	uptrCall, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || len(uptrCall.Args) != 1 || uptrCall.Ellipsis.IsValid() {
		return false
	}
	uptrID, ok := unwrapParens(uptrCall.Fun).(*ast.Ident)
	if !ok || uptrID.Name != "uintptr" {
		return false
	}
	return isLenOfIdentCall(uptrCall.Args[0], sliceName)
}

func isFdMethodCallOnSource(expr ast.Expr, isFileSource func(ast.Expr) bool) bool {
	expr = unwrapParens(expr)
	if conv, ok := expr.(*ast.CallExpr); ok && len(conv.Args) == 1 {
		if cid, ok := unwrapParens(conv.Fun).(*ast.Ident); ok && (cid.Name == "int" || cid.Name == "uintptr") {
			expr = unwrapParens(conv.Args[0])
		}
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Fd" && isFileSource(sel.X)
}

func extractCompositeWriterBinding(lit *ast.CompositeLit, isFileSource func(ast.Expr) bool) (testingWriterBinding, bool) {
	if lit == nil || len(lit.Elts) == 0 {
		return testingWriterBinding{}, false
	}
	b := testingWriterBinding{
		fileFields: map[string]bool{},
		fdFields:   map[string]bool{},
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return testingWriterBinding{}, false
		}
		keyID, ok := unwrapParens(kv.Key).(*ast.Ident)
		if !ok || keyID.Name == "" {
			return testingWriterBinding{}, false
		}
		val := unwrapParens(kv.Value)
		if isFileSource(val) {
			b.fileFields[keyID.Name] = true
		} else if isFdMethodCallOnSource(val, isFileSource) {
			b.fdFields[keyID.Name] = true
		}
	}
	if len(b.fileFields) == 0 && len(b.fdFields) == 0 {
		return testingWriterBinding{}, false
	}
	return b, true
}

func isBoundFileTargetExpr(fn *ast.FuncDecl, expr ast.Expr, binding testingWriterBinding) bool {
	expr = unwrapParens(expr)
	switch e := expr.(type) {
	case *ast.Ident:
		return binding.fileVars[e.Name]
	case *ast.SelectorExpr:
		recv := recvVarName(fn)
		if recv != "" {
			if id, ok := unwrapParens(e.X).(*ast.Ident); ok && id.Name == recv {
				return binding.fileFields[e.Sel.Name]
			}
		}
	}
	return false
}

func isBoundFdTargetExpr(fn *ast.FuncDecl, expr ast.Expr, binding testingWriterBinding) bool {
	expr = unwrapParens(expr)
	if conv, ok := expr.(*ast.CallExpr); ok && len(conv.Args) == 1 {
		if cid, ok := unwrapParens(conv.Fun).(*ast.Ident); ok && (cid.Name == "int" || cid.Name == "uintptr") {
			expr = unwrapParens(conv.Args[0])
		}
	}
	switch e := expr.(type) {
	case *ast.Ident:
		return binding.fdVars[e.Name]
	case *ast.SelectorExpr:
		recv := recvVarName(fn)
		if recv != "" {
			if id, ok := unwrapParens(e.X).(*ast.Ident); ok && id.Name == recv {
				return binding.fdFields[e.Sel.Name]
			}
		}
	case *ast.CallExpr:
		return isFdMethodCallOnSource(e, func(src ast.Expr) bool {
			return isBoundFileTargetExpr(fn, src, binding)
		})
	}
	return false
}

func isUnderlyingBoundWriteCall(fn *ast.FuncDecl, call *ast.CallExpr, binding testingWriterBinding) bool {
	if call.Ellipsis.IsValid() {
		return false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Write" || len(call.Args) != 1 {
		return false
	}
	return isBoundFileTargetExpr(fn, sel.X, binding)
}

func isBoundSyscallWriteCall(fn *ast.FuncDecl, call *ast.CallExpr, binding testingWriterBinding) string {
	if call.Ellipsis.IsValid() {
		return ""
	}
	kind := syscallWriteSinkKind(call)
	switch kind {
	case "write2":
		if len(call.Args) == 2 && isBoundFdTargetExpr(fn, call.Args[0], binding) {
			return "write2"
		}
	case "raw3":
		sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		validArity := (sel.Sel.Name == "Syscall" || sel.Sel.Name == "RawSyscall") && len(call.Args) == 4
		if sel.Sel.Name == "Syscall6" && len(call.Args) == 6 && isZeroIntLit(call.Args[4]) && isZeroIntLit(call.Args[5]) {
			validArity = true
		}
		if validArity && isSysWriteConstExpr(call.Args[0]) && isBoundFdTargetExpr(fn, call.Args[1], binding) {
			return "raw3"
		}
	}
	return ""
}

func deriveCalleeBinding(callerFn *ast.FuncDecl, callerRecv string, callerBinding testingWriterBinding, callerPayloadProtected map[string]bool, call *ast.CallExpr, helperRecv string, helperDecl *ast.FuncDecl, sinkArgSource func(ast.Expr) (string, bool)) (testingWriterBinding, string, bool) {
	if call.Ellipsis.IsValid() {
		return testingWriterBinding{}, "", false
	}
	callee := testingWriterBinding{
		fileVars:  map[string]bool{},
		fdVars:    map[string]bool{},
		emptyVars: map[string]bool{},
	}
	if helperRecv != "" && helperRecv == callerRecv {
		callee.fileFields = callerBinding.fileFields
		callee.fdFields = callerBinding.fdFields
	}
	pNames := paramNamesFlat(helperDecl.Type.Params)
	if len(call.Args) != len(pNames) {
		return testingWriterBinding{}, "", false
	}
	byteSliceParams := byteSliceParamIdents(helperDecl.Type.Params)
	var matchedChunk string
	for i, arg := range call.Args {
		pName := pNames[i]
		if pName != "" && pName != "_" {
			if isBoundFileTargetExpr(callerFn, arg, callerBinding) && !exprRefsIdentOutsideLen(arg, callerPayloadProtected) {
				callee.fileVars[pName] = true
				continue
			}
			if isBoundFdTargetExpr(callerFn, arg, callerBinding) && !exprRefsIdentOutsideLen(arg, callerPayloadProtected) {
				callee.fdVars[pName] = true
				continue
			}
			if byteSliceParams[pName] {
				if srcChunk, ok := sinkArgSource(arg); ok {
					if callee.sliceVar != "" {
						return testingWriterBinding{}, "", false
					}
					callee.sliceVar = pName
					matchedChunk = srcChunk
					continue
				}
				if isProvablyEmptyByteSliceArg(arg, callerBinding) && !bodyDeclaresAnyIdent(helperDecl.Body, map[string]bool{pName: true}) && !bodyMutatesOrTakesAddrOfAny(helperDecl.Body, map[string]bool{pName: true}) {
					callee.emptyVars[pName] = true
					continue
				}
			}
		}
		if exprHasCallOrFuncLit(arg) || exprRefsIdentOutsideLen(arg, callerPayloadProtected) {
			return testingWriterBinding{}, "", false
		}
	}
	if callee.sliceVar == "" {
		return testingWriterBinding{}, "", false
	}
	return callee, matchedChunk, true
}

func resolveLocalHelper(recvType string, fn *ast.FuncDecl, call *ast.CallExpr, topFuncs map[string]*ast.FuncDecl, typeMethods map[string]map[string]*ast.FuncDecl) (string, *ast.FuncDecl, bool) {
	switch fun := unwrapParens(call.Fun).(type) {
	case *ast.Ident:
		if decl, ok := topFuncs[fun.Name]; ok {
			return "", decl, true
		}
	case *ast.SelectorExpr:
		recv := recvVarName(fn)
		if recv != "" && recvType != "" {
			if id, ok := unwrapParens(fun.X).(*ast.Ident); ok && id.Name == recv {
				if decl, ok := typeMethods[recvType][fun.Sel.Name]; ok {
					return recvType, decl, true
				}
			}
		}
	}
	return "", nil, false
}

func isWrappedErrStructPtr(expr ast.Expr, errName string) bool {
	u, ok := unwrapParens(expr).(*ast.UnaryExpr)
	if !ok || u.Op != token.AND {
		return false
	}
	lit, ok := unwrapParens(u.X).(*ast.CompositeLit)
	if !ok || lit.Type == nil {
		return false
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if id, ok := unwrapParens(kv.Value).(*ast.Ident); ok && id.Name == errName {
			return true
		}
	}
	return false
}

func exprIsUntaintedErrResult(expr ast.Expr, errName string) bool {
	expr = unwrapParens(expr)
	if id, ok := expr.(*ast.Ident); ok && id.Name == errName {
		return true
	}
	return isWrappedErrStructPtr(expr, errName)
}

func condChecksNonZeroErr(cond ast.Expr) string {
	bin, ok := unwrapParens(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return ""
	}
	lhs, rhs := unwrapParens(bin.X), unwrapParens(bin.Y)
	if id, ok := lhs.(*ast.Ident); ok {
		if rID, ok := rhs.(*ast.Ident); ok && rID.Name == "nil" {
			return id.Name
		}
		if lit, ok := rhs.(*ast.BasicLit); ok && lit.Kind == token.INT && lit.Value == "0" {
			return id.Name
		}
	}
	if id, ok := rhs.(*ast.Ident); ok {
		if lID, ok := lhs.(*ast.Ident); ok && lID.Name == "nil" {
			return id.Name
		}
		if lit, ok := lhs.(*ast.BasicLit); ok && lit.Kind == token.INT && lit.Value == "0" {
			return id.Name
		}
	}
	return ""
}

func condChecksEqErr(cond ast.Expr, wantIdent string) bool {
	bin, ok := unwrapParens(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL {
		return false
	}
	lhs, rhs := unwrapParens(bin.X), unwrapParens(bin.Y)
	if id, ok := lhs.(*ast.Ident); ok && id.Name == wantIdent {
		if rID, ok := rhs.(*ast.Ident); ok && rID.Name == "nil" {
			return true
		}
	}
	if id, ok := rhs.(*ast.Ident); ok && id.Name == wantIdent {
		if lID, ok := lhs.(*ast.Ident); ok && lID.Name == "nil" {
			return true
		}
	}
	return false
}

func isTransientErrnoEq(expr ast.Expr, errName string) bool {
	bin, ok := unwrapParens(expr).(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL {
		return false
	}
	id, ok := unwrapParens(bin.X).(*ast.Ident)
	if !ok || id.Name != errName {
		return false
	}
	sel, ok := unwrapParens(bin.Y).(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "EINTR" && sel.Sel.Name != "EAGAIN") {
		return false
	}
	pkgID, ok := unwrapParens(sel.X).(*ast.Ident)
	return ok && pkgID.Name == "syscall"
}

func isTransientErrnoRetryIf(s *ast.IfStmt, errName string) bool {
	if s.Init != nil || s.Else != nil || len(s.Body.List) != 1 {
		return false
	}
	br, ok := s.Body.List[0].(*ast.BranchStmt)
	if !ok || br.Tok != token.CONTINUE {
		return false
	}
	cond := unwrapParens(s.Cond)
	if isTransientErrnoEq(cond, errName) {
		return true
	}
	bin, ok := cond.(*ast.BinaryExpr)
	return ok && bin.Op == token.LOR && isTransientErrnoEq(bin.X, errName) && isTransientErrnoEq(bin.Y, errName)
}

func isLenSlicePositiveCond(cond ast.Expr, sliceName string) bool {
	if sliceName == "" {
		return false
	}
	bin, ok := unwrapParens(cond).(*ast.BinaryExpr)
	if !ok || (bin.Op != token.GTR && bin.Op != token.NEQ) {
		return false
	}
	return isLenOfIdentCall(bin.X, sliceName) && isZeroIntLit(bin.Y)
}

func isCountPositiveCond(cond ast.Expr, countAliases map[string]bool) bool {
	bin, ok := unwrapParens(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.GTR {
		return false
	}
	id, ok := unwrapParens(bin.X).(*ast.Ident)
	return ok && countAliases[id.Name] && isZeroIntLit(bin.Y)
}

func isCountAdvanceSliceAssign(s *ast.AssignStmt, sliceName string, countAliases map[string]bool) bool {
	if s.Tok != token.ASSIGN || len(s.Lhs) != 1 || len(s.Rhs) != 1 {
		return false
	}
	lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident)
	if !ok || lhsID.Name != sliceName {
		return false
	}
	sl, ok := unwrapParens(s.Rhs[0]).(*ast.SliceExpr)
	if !ok || sl.Slice3 || sl.High != nil || sl.Low == nil {
		return false
	}
	baseID, ok := unwrapParens(sl.X).(*ast.Ident)
	if !ok || baseID.Name != sliceName {
		return false
	}
	low := unwrapParens(sl.Low)
	if conv, isCall := low.(*ast.CallExpr); isCall && len(conv.Args) == 1 && !conv.Ellipsis.IsValid() {
		if cid, ok := unwrapParens(conv.Fun).(*ast.Ident); ok && (cid.Name == "int" || cid.Name == "uintptr") {
			low = unwrapParens(conv.Args[0])
		}
	}
	advID, ok := low.(*ast.Ident)
	return ok && countAliases[advID.Name]
}

func isChunkAdvanceSliceAssign(s *ast.AssignStmt, sliceName, activeChunk string) bool {
	if activeChunk == "" || s.Tok != token.ASSIGN || len(s.Lhs) != 1 || len(s.Rhs) != 1 {
		return false
	}
	lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident)
	if !ok || lhsID.Name != sliceName {
		return false
	}
	sl, ok := unwrapParens(s.Rhs[0]).(*ast.SliceExpr)
	if !ok || sl.Slice3 || sl.High != nil || sl.Low == nil {
		return false
	}
	baseID, ok := unwrapParens(sl.X).(*ast.Ident)
	return ok && baseID.Name == sliceName && isLenOfIdentCall(sl.Low, activeChunk)
}

func isMonotonicLatchIf(s *ast.IfStmt, chunkErrVar, accumErrVar, namedCountResult, activeChunk string, requireCountUpdate bool) (updatedCount bool, ok bool) {
	checkArm := func(arm *ast.IfStmt) bool {
		if arm == nil || arm.Init != nil || arm.Else != nil || len(arm.Body.List) != 1 {
			return false
		}
		bin, ok := unwrapParens(arm.Cond).(*ast.BinaryExpr)
		if !ok || bin.Op != token.LAND {
			return false
		}
		if condChecksNonZeroErr(bin.X) != chunkErrVar || !condChecksEqErr(bin.Y, accumErrVar) {
			return false
		}
		assign, ok := arm.Body.List[0].(*ast.AssignStmt)
		if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return false
		}
		lhsID, ok := unwrapParens(assign.Lhs[0]).(*ast.Ident)
		rhsID, ok2 := unwrapParens(assign.Rhs[0]).(*ast.Ident)
		return ok && ok2 && lhsID.Name == accumErrVar && rhsID.Name == chunkErrVar
	}
	if checkArm(s) {
		if requireCountUpdate {
			return false, false
		}
		return false, true
	}
	if s.Init != nil || s.Else == nil {
		return false, false
	}
	condRequiresNilBoth := false
	if bin, ok := unwrapParens(s.Cond).(*ast.BinaryExpr); ok && bin.Op == token.LAND {
		condRequiresNilBoth = (condChecksEqErr(bin.X, chunkErrVar) && condChecksEqErr(bin.Y, accumErrVar)) ||
			(condChecksEqErr(bin.Y, chunkErrVar) && condChecksEqErr(bin.X, accumErrVar))
	}
	if !condRequiresNilBoth {
		return false, false
	}
	elseIf, ok := s.Else.(*ast.IfStmt)
	if !ok || !checkArm(elseIf) {
		return false, false
	}
	if requireCountUpdate {
		if namedCountResult == "" || activeChunk == "" || len(s.Body.List) != 1 {
			return false, false
		}
		addStmt, ok := s.Body.List[0].(*ast.AssignStmt)
		if !ok || addStmt.Tok != token.ADD_ASSIGN || len(addStmt.Lhs) != 1 || len(addStmt.Rhs) != 1 {
			return false, false
		}
		lhsID, ok := unwrapParens(addStmt.Lhs[0]).(*ast.Ident)
		if !ok || lhsID.Name != namedCountResult || !isLenOfIdentCall(addStmt.Rhs[0], activeChunk) {
			return false, false
		}
		return true, true
	}
	if len(s.Body.List) != 0 {
		return false, false
	}
	return false, true
}

func bodyMutatesOrTakesAddrOfAny(body *ast.BlockStmt, protected map[string]bool) bool {
	if body == nil || len(protected) == 0 {
		return false
	}
	bad := false
	ast.Inspect(body, func(n ast.Node) bool {
		if bad || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if id, ok := unwrapParens(lhs).(*ast.Ident); ok && protected[id.Name] {
					bad = true
					return false
				}
			}
		case *ast.RangeStmt:
			for _, lhs := range []ast.Expr{node.Key, node.Value} {
				if lhs != nil {
					if id, ok := unwrapParens(lhs).(*ast.Ident); ok && protected[id.Name] {
						bad = true
						return false
					}
				}
			}
		case *ast.IncDecStmt:
			if id, ok := unwrapParens(node.X).(*ast.Ident); ok && protected[id.Name] {
				bad = true
				return false
			}
		case *ast.UnaryExpr:
			if node.Op == token.AND {
				if id, ok := unwrapParens(node.X).(*ast.Ident); ok && protected[id.Name] {
					bad = true
					return false
				}
			}
		}
		return true
	})
	return bad
}

func blockOnlySelectsOnIdent(body *ast.BlockStmt, ident string) bool {
	if body == nil || ident == "" {
		return true
	}
	var shadowed, escaped bool
	var walk func(n ast.Node)
	walk = func(n ast.Node) {
		if shadowed || escaped || n == nil {
			return
		}
		switch node := n.(type) {
		case *ast.ValueSpec:
			for _, nameID := range node.Names {
				if nameID.Name == ident {
					shadowed = true
					return
				}
			}
			if node.Type != nil {
				walk(node.Type)
			}
			for _, v := range node.Values {
				walk(v)
			}
		case *ast.AssignStmt:
			if node.Tok == token.DEFINE {
				for _, lhs := range node.Lhs {
					if id, ok := unwrapParens(lhs).(*ast.Ident); ok && id.Name == ident {
						shadowed = true
						return
					}
				}
			}
			for _, lhs := range node.Lhs {
				walk(lhs)
			}
			for _, rhs := range node.Rhs {
				walk(rhs)
			}
		case *ast.SelectorExpr:
			if id, ok := unwrapParens(node.X).(*ast.Ident); ok && id.Name == ident {
				return
			}
			walk(node.X)
		case *ast.Ident:
			if node.Name == ident {
				escaped = true
			}
		default:
			ast.Inspect(node, func(ch ast.Node) bool {
				if ch == node {
					return true
				}
				walk(ch)
				return false
			})
		}
	}
	walk(body)
	return !shadowed && !escaped
}

func blockAlwaysReturns(stmts []ast.Stmt) bool {
	if len(stmts) == 0 {
		return false
	}
	switch last := stmts[len(stmts)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BlockStmt:
		return blockAlwaysReturns(last.List)
	case *ast.IfStmt:
		if last.Else == nil || !blockAlwaysReturns(last.Body.List) {
			return false
		}
		switch el := last.Else.(type) {
		case *ast.BlockStmt:
			return blockAlwaysReturns(el.List)
		case *ast.IfStmt:
			return blockAlwaysReturns([]ast.Stmt{el})
		default:
			return false
		}
	case *ast.ForStmt:
		if last.Init != nil || last.Cond != nil || last.Post != nil {
			return false
		}
		var hasBreak, hasReturn bool
		ast.Inspect(last.Body, func(n ast.Node) bool {
			if hasBreak || n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.ReturnStmt:
				hasReturn = true
				return false
			case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
				// Unlabeled break inside an inner loop/switch breaks the inner statement,
				// whereas labeled break or any nested return still counts.
				ast.Inspect(node, func(in ast.Node) bool {
					if hasBreak || in == nil {
						return false
					}
					switch inner := in.(type) {
					case *ast.FuncLit:
						return false
					case *ast.ReturnStmt:
						hasReturn = true
						return false
					case *ast.BranchStmt:
						if inner.Tok == token.BREAK && inner.Label != nil {
							hasBreak = true
							return false
						}
					}
					return true
				})
				return false
			case *ast.BranchStmt:
				if node.Tok == token.BREAK {
					hasBreak = true
					return false
				}
			}
			return true
		})
		return hasReturn && !hasBreak
	}
	return false
}

type writerBlockMode int

const (
	writerBlockPlain writerBlockMode = iota
	writerBlockSliceLoop
	writerBlockChunkLoop
)

type writerPathState struct {
	liveErr                        string
	lastChunk                      string
	lastSinkResultArity            int
	activeChunk                    string
	liveCountVar                   string
	sliceParamMutated              bool
	sliceAdvancedInLoop            bool
	chunkAdvancedInLoop            bool
	sawSinkInLoop                  bool
	dischargedLoop                 bool
	dischargedFullSlice1ResultSink bool
	discharged2ResultSink          bool
	latchedSink                    bool
	latchedCount                   bool
}

func verifyTestingWriterFunc(recvType string, fn *ast.FuncDecl, binding testingWriterBinding, topFuncs map[string]*ast.FuncDecl, typeMethods map[string]map[string]*ast.FuncDecl, visiting map[string]bool) bool {
	if fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.Results == nil || binding.sliceVar == "" {
		return false
	}
	writerReserved := map[string]bool{
		"len": true, "append": true, "make": true, "copy": true, "clear": true,
		"uintptr": true, "int": true, "byte": true, "nil": true, "error": true,
		"unsafe": true, "syscall": true, "os": true,
	}
	if funcShadowsAnyIdent(fn, writerReserved) {
		return false
	}
	numResults := fn.Type.Results.NumFields()
	if (numResults != 1 && (numResults != 2 || !firstResultIsInt(fn.Type.Results))) || !funcReturnsErrorLast(fn.Type) {
		return false
	}
	if !blockAlwaysReturns(fn.Body.List) {
		return false
	}
	visitKey := recvType + "." + fn.Name.Name + fmt.Sprintf("|%s|%v|%v|%v|%v|%v", binding.sliceVar, sortedKeys(binding.fileFields), sortedKeys(binding.fdFields), sortedKeys(binding.fileVars), sortedKeys(binding.fdVars), sortedKeys(binding.emptyVars))
	if visiting[visitKey] {
		return false
	}
	visiting[visitKey] = true
	defer delete(visiting, visitKey)

	protectedSinks := map[string]bool{}
	for k := range binding.fileVars {
		protectedSinks[k] = true
	}
	for k := range binding.fdVars {
		protectedSinks[k] = true
	}
	for k := range binding.emptyVars {
		protectedSinks[k] = true
	}
	if recv := recvVarName(fn); recv != "" {
		protectedSinks[recv] = true
		if !blockOnlySelectsOnIdent(fn.Body, recv) {
			return false
		}
	}
	if bodyMutatesOrTakesAddrOfAny(fn.Body, protectedSinks) {
		return false
	}

	sliceParam := binding.sliceVar
	namedErrResult := lastNamedResultIdent(fn.Type.Results)
	namedCountResult := firstNamedIntResultIdent(fn.Type.Results)

	localClosures := map[string]*ast.FuncType{}
	verifiedClosureLits := map[*ast.FuncLit]bool{}
	allowedSliceZeroAmps := map[*ast.UnaryExpr]bool{}
	allowedPayloadCalls := map[*ast.CallExpr]bool{}
	allowedPayloadAssigns := map[*ast.AssignStmt]bool{}
	allowedPayloadValueSpecs := map[*ast.ValueSpec]bool{}
	allErrNames := map[string]bool{}
	allCountNames := map[string]bool{}
	allLoopCountNames := map[string]bool{}
	allChunkNames := map[string]bool{}
	allBufNames := map[string]bool{}
	currentPayloadProtected := func() map[string]bool {
		m := map[string]bool{sliceParam: true}
		for k := range allChunkNames {
			m[k] = true
		}
		for k := range allBufNames {
			m[k] = true
		}
		for k := range binding.emptyVars {
			m[k] = true
		}
		return m
	}
	var namedErrBoundDirectly, everLatched bool
	if namedErrResult != "" {
		allErrNames[namedErrResult] = true
	}
	if namedCountResult != "" {
		allCountNames[namedCountResult] = true
	}

	// Per-loop auxiliary name tables, active only inside their respective loop walks.
	var loopCountAliases map[string]bool
	var sawLenZeroExitReturn bool
	var chunkVars map[string]bool
	var freshBufVars map[string]bool
	var bufChunkSource map[string]string

	isProtectedIdent := func(name string) bool {
		return localClosures[name] != nil || allErrNames[name] || allCountNames[name] || allLoopCountNames[name] || allChunkNames[name] || allBufNames[name] || protectedSinks[name]
	}

	bindFreshErrIdent := func(expr ast.Expr) (string, bool) {
		id, ok := unwrapParens(expr).(*ast.Ident)
		if !ok || id.Name == "" || id.Name == "_" || id.Name == sliceParam || localClosures[id.Name] != nil || allCountNames[id.Name] || allLoopCountNames[id.Name] || allChunkNames[id.Name] || allBufNames[id.Name] || protectedSinks[id.Name] {
			return "", false
		}
		if id.Name == namedErrResult {
			if namedErrBoundDirectly || everLatched {
				return "", false
			}
			namedErrBoundDirectly = true
			return id.Name, true
		}
		if allErrNames[id.Name] {
			return "", false
		}
		allErrNames[id.Name] = true
		return id.Name, true
	}

	sinkSliceSource := func(expr ast.Expr, st writerPathState, mode writerBlockMode) (string, bool) {
		id, ok := unwrapParens(expr).(*ast.Ident)
		if !ok || id.Name == "" {
			return "", false
		}
		switch mode {
		case writerBlockPlain:
			if id.Name == sliceParam && !st.sliceParamMutated {
				return sliceParam, true
			}
		case writerBlockSliceLoop:
			if id.Name == sliceParam && !st.sliceAdvancedInLoop {
				return sliceParam, true
			}
		case writerBlockChunkLoop:
			if st.chunkAdvancedInLoop {
				return "", false
			}
			if id.Name == sliceParam {
				return sliceParam, true
			}
			if chunkVars[id.Name] {
				return id.Name, true
			}
			if srcChunk, ok := bufChunkSource[id.Name]; ok && srcChunk != "" {
				return srcChunk, true
			}
		}
		return "", false
	}

	isValidTailSinkCall := func(call *ast.CallExpr, wantResults int, st writerPathState, mode writerBlockMode) bool {
		if mode != writerBlockPlain || call.Ellipsis.IsValid() {
			return false
		}
		if id, isID := unwrapParens(call.Fun).(*ast.Ident); isID {
			if cType := localClosures[id.Name]; cType != nil && cType.Results.NumFields() == wantResults && len(call.Args) == 1 {
				if _, ok := sinkSliceSource(call.Args[0], st, mode); ok {
					allowedPayloadCalls[call] = true
					return true
				}
				return false
			}
		}
		if wantResults == 2 && isUnderlyingBoundWriteCall(fn, call, binding) {
			if _, ok := sinkSliceSource(call.Args[0], st, mode); ok {
				allowedPayloadCalls[call] = true
				return true
			}
			return false
		}
		helperRecv, helperDecl, isLocal := resolveLocalHelper(recvType, fn, call, topFuncs, typeMethods)
		if !isLocal || helperDecl.Type == nil || helperDecl.Type.Results == nil || helperDecl.Type.Results.NumFields() != wantResults || !funcReturnsErrorLast(helperDecl.Type) {
			return false
		}
		if wantResults == 2 && !firstResultIsInt(helperDecl.Type.Results) {
			return false
		}
		calleeBinding, _, boundOK := deriveCalleeBinding(fn, recvType, binding, currentPayloadProtected(), call, helperRecv, helperDecl, func(arg ast.Expr) (string, bool) {
			return sinkSliceSource(arg, st, mode)
		})
		if boundOK && verifyTestingWriterFunc(helperRecv, helperDecl, calleeBinding, topFuncs, typeMethods, visiting) {
			allowedPayloadCalls[call] = true
			return true
		}
		return false
	}

	classifySinkAssignCall := func(lhsLen int, call *ast.CallExpr, st writerPathState, mode writerBlockMode) (isSink bool, chunkUsed string, ok bool) {
		if id, isID := unwrapParens(call.Fun).(*ast.Ident); isID {
			if cType, isClosure := localClosures[id.Name]; isClosure {
				if call.Ellipsis.IsValid() || len(call.Args) != 1 || lhsLen != cType.Results.NumFields() {
					return true, "", false
				}
				srcChunk, argOK := sinkSliceSource(call.Args[0], st, mode)
				if argOK {
					allowedPayloadCalls[call] = true
				}
				return true, srcChunk, argOK
			}
		}
		if helperRecv, helperDecl, isLocal := resolveLocalHelper(recvType, fn, call, topFuncs, typeMethods); isLocal {
			if helperDecl.Type == nil || helperDecl.Type.Results == nil || helperDecl.Type.Results.NumFields() == 0 {
				return false, "", false
			}
			if !funcReturnsErrorLast(helperDecl.Type) {
				return false, "", true
			}
			if lhsLen != helperDecl.Type.Results.NumFields() || (lhsLen == 2 && !firstResultIsInt(helperDecl.Type.Results)) {
				return true, "", false
			}
			calleeBinding, srcChunk, boundOK := deriveCalleeBinding(fn, recvType, binding, currentPayloadProtected(), call, helperRecv, helperDecl, func(arg ast.Expr) (string, bool) {
				return sinkSliceSource(arg, st, mode)
			})
			if !boundOK {
				return true, "", false
			}
			if !verifyTestingWriterFunc(helperRecv, helperDecl, calleeBinding, topFuncs, typeMethods, visiting) {
				return true, "", false
			}
			allowedPayloadCalls[call] = true
			return true, srcChunk, true
		}
		switch isBoundSyscallWriteCall(fn, call, binding) {
		case "write2":
			if mode != writerBlockSliceLoop || lhsLen != 2 {
				return true, "", false
			}
			srcChunk, argOK := sinkSliceSource(call.Args[1], st, mode)
			if !argOK || srcChunk != sliceParam {
				return true, "", false
			}
			allowedPayloadCalls[call] = true
			return true, srcChunk, true
		case "raw3":
			if mode != writerBlockSliceLoop || lhsLen != 3 || st.sliceAdvancedInLoop {
				return true, "", false
			}
			amp, innerCalls, ptrOK := isSliceZeroElemUintptrExpr(call.Args[2], sliceParam)
			if !ptrOK || !isSliceLenUintptrExpr(call.Args[3], sliceParam) {
				return true, "", false
			}
			if amp != nil {
				allowedSliceZeroAmps[amp] = true
			}
			allowedPayloadCalls[call] = true
			for _, ic := range innerCalls {
				allowedPayloadCalls[ic] = true
			}
			return true, sliceParam, true
		}
		if syscallWriteSinkKind(call) != "" {
			return true, "", false
		}
		if isUnderlyingBoundWriteCall(fn, call, binding) {
			if lhsLen != 2 {
				return true, "", false
			}
			srcChunk, argOK := sinkSliceSource(call.Args[0], st, mode)
			if argOK {
				allowedPayloadCalls[call] = true
			}
			return true, srcChunk, argOK
		}
		if sel, isSel := unwrapParens(call.Fun).(*ast.SelectorExpr); isSel && sel.Sel.Name == "Write" {
			return true, "", false
		}
		return false, "", true
	}

	verifySinkClosureLit := func(name string, lit *ast.FuncLit, mode writerBlockMode, inBranch bool) bool {
		if mode != writerBlockPlain || inBranch || lit == nil || lit.Type == nil || lit.Type.Results == nil || !funcReturnsErrorLast(lit.Type) {
			return false
		}
		cRes := lit.Type.Results.NumFields()
		if cRes != 1 && (cRes != 2 || !firstResultIsInt(lit.Type.Results)) {
			return false
		}
		cSlice := singleByteSliceParamIdent(lit.Type.Params)
		if cSlice == "" || name == "" || name == "_" || isProtectedIdent(name) || name == sliceParam {
			return false
		}
		closureEmpty := map[string]bool{}
		for k := range binding.emptyVars {
			if k != cSlice && !bodyDeclaresAnyIdent(lit.Body, map[string]bool{k: true}) && !bodyMutatesOrTakesAddrOfAny(lit.Body, map[string]bool{k: true}) {
				closureEmpty[k] = true
			}
		}
		closureBinding := testingWriterBinding{
			fileFields: binding.fileFields,
			fdFields:   binding.fdFields,
			fileVars:   binding.fileVars,
			fdVars:     binding.fdVars,
			emptyVars:  closureEmpty,
			sliceVar:   cSlice,
		}
		synth := &ast.FuncDecl{Name: &ast.Ident{Name: name}, Type: lit.Type, Body: lit.Body}
		if !verifyTestingWriterFunc(recvType, synth, closureBinding, topFuncs, typeMethods, visiting) {
			return false
		}
		verifiedClosureLits[lit] = true
		localClosures[name] = lit.Type
		return true
	}

	recordSinkCountLHS := func(lhsExprs []ast.Expr, st *writerPathState, mode writerBlockMode, chunkUsed string) bool {
		switch len(lhsExprs) {
		case 1:
			if mode == writerBlockSliceLoop {
				return false
			}
			st.liveCountVar = ""
			return true
		case 2, 3:
			countID, ok := unwrapParens(lhsExprs[0]).(*ast.Ident)
			if !ok || countID.Name == "" || countID.Name == sliceParam || localClosures[countID.Name] != nil || allErrNames[countID.Name] || allChunkNames[countID.Name] || allBufNames[countID.Name] || protectedSinks[countID.Name] {
				return false
			}
			if countID.Name == "_" {
				if !(mode == writerBlockPlain && numResults == 1 && len(lhsExprs) == 2) {
					return false
				}
				st.liveCountVar = ""
				return true
			}
			if len(lhsExprs) == 3 {
				r2ID, ok := unwrapParens(lhsExprs[1]).(*ast.Ident)
				if !ok || r2ID.Name == countID.Name || r2ID.Name == sliceParam || isProtectedIdent(r2ID.Name) {
					return false
				}
			}
			switch mode {
			case writerBlockSliceLoop:
				allLoopCountNames[countID.Name] = true
				loopCountAliases[countID.Name] = true
			case writerBlockPlain:
				if chunkUsed != sliceParam {
					return false
				}
				if allCountNames[countID.Name] && countID.Name != namedCountResult {
					return false
				}
				allCountNames[countID.Name] = true
				st.liveCountVar = countID.Name
			case writerBlockChunkLoop:
				if countID.Name == namedCountResult {
					return false
				}
				allCountNames[countID.Name] = true
			}
			return true
		default:
			return false
		}
	}

	checkValidCountReturnExpr := func(expr ast.Expr, st writerPathState) bool {
		expr = unwrapParens(expr)
		if st.liveErr != "" && isZeroIntLit(expr) {
			return true
		}
		if id, ok := expr.(*ast.Ident); ok {
			if st.liveCountVar != "" && id.Name == st.liveCountVar && (st.liveErr != "" || st.discharged2ResultSink) {
				return true
			}
			if namedCountResult != "" && id.Name == namedCountResult && st.latchedCount {
				return true
			}
		}
		if st.liveErr == "" && st.dischargedFullSlice1ResultSink && !st.sliceParamMutated && isLenOfIdentCall(expr, sliceParam) {
			return true
		}
		return false
	}

	checkReturn := func(ret *ast.ReturnStmt, st writerPathState, allowNilFromLoop bool, mode writerBlockMode) bool {
		switch len(ret.Results) {
		case 0:
			if namedErrResult == "" {
				return false
			}
			if numResults == 2 {
				if namedCountResult == "" {
					return false
				}
				if st.liveErr != "" && st.liveErr == namedErrResult && st.liveCountVar == namedCountResult {
					return true
				}
				if st.liveErr == "" && st.latchedSink && st.latchedCount {
					return true
				}
				return false
			}
			if st.liveErr != "" && st.liveErr == namedErrResult {
				return true
			}
			if st.liveErr == "" && st.latchedSink {
				return true
			}
			return false
		case 1:
			if numResults > 1 {
				if st.liveErr != "" {
					return false
				}
				call, ok := unwrapParens(ret.Results[0]).(*ast.CallExpr)
				return ok && isValidTailSinkCall(call, numResults, st, mode)
			}
			fallthrough
		default:
			if len(ret.Results) != numResults {
				return false
			}
			last := unwrapParens(ret.Results[numResults-1])
			if numResults == 1 && st.liveErr == "" {
				if call, ok := last.(*ast.CallExpr); ok && isValidTailSinkCall(call, 1, st, mode) {
					return true
				}
			}
			if numResults == 2 && !checkValidCountReturnExpr(ret.Results[0], st) {
				return false
			}
			if st.liveErr != "" && exprIsUntaintedErrResult(last, st.liveErr) {
				return true
			}
			if st.liveErr == "" {
				if id, ok := last.(*ast.Ident); ok && namedErrResult != "" && id.Name == namedErrResult && st.latchedSink {
					return true
				}
				if id, ok := last.(*ast.Ident); ok && id.Name == "nil" && (allowNilFromLoop || (numResults == 2 && (st.dischargedFullSlice1ResultSink || st.discharged2ResultSink))) {
					return true
				}
			}
			return false
		}
	}

	applySinkAssign := func(lhsExprs []ast.Expr, srcChunk string, st writerPathState, mode writerBlockMode) (writerPathState, bool) {
		if st.liveErr != "" {
			return st, false
		}
		if !recordSinkCountLHS(lhsExprs, &st, mode, srcChunk) {
			return st, false
		}
		errName, bound := bindFreshErrIdent(lhsExprs[len(lhsExprs)-1])
		if !bound {
			return st, false
		}
		st.liveErr = errName
		st.lastChunk = srcChunk
		st.lastSinkResultArity = len(lhsExprs)
		if mode == writerBlockChunkLoop {
			st.activeChunk = srcChunk
		}
		if mode == writerBlockSliceLoop {
			st.sawSinkInLoop = true
		}
		st.dischargedLoop = false
		st.dischargedFullSlice1ResultSink = false
		st.discharged2ResultSink = false
		return st, true
	}

	var walkBlock func(stmts []ast.Stmt, st writerPathState, inErrCheckFor string, mode writerBlockMode, inBranch bool) (writerPathState, bool)
	walkBlock = func(stmts []ast.Stmt, st writerPathState, inErrCheckFor string, mode writerBlockMode, inBranch bool) (writerPathState, bool) {
		for idx, stmt := range stmts {
			if idx != len(stmts)-1 && blockAlwaysReturns([]ast.Stmt{stmt}) {
				return st, false
			}
			switch s := stmt.(type) {
			case *ast.EmptyStmt:
				continue
			case *ast.ExprStmt:
				call, isCall := unwrapParens(s.X).(*ast.CallExpr)
				if isCall {
					if id, isID := unwrapParens(call.Fun).(*ast.Ident); isID && localClosures[id.Name] != nil {
						return st, false
					}
					if _, helperDecl, isLocal := resolveLocalHelper(recvType, fn, call, topFuncs, typeMethods); isLocal && funcReturnsErrorLast(helperDecl.Type) {
						return st, false
					}
					if syscallWriteSinkKind(call) != "" {
						return st, false
					}
					if sel, isSel := unwrapParens(call.Fun).(*ast.SelectorExpr); isSel && sel.Sel.Name == "Write" {
						return st, false
					}
				}
			case *ast.DeferStmt:
				if _, isLit := unwrapParens(s.Call.Fun).(*ast.FuncLit); isLit {
					return st, false
				}
				if _, helperDecl, isLocal := resolveLocalHelper(recvType, fn, s.Call, topFuncs, typeMethods); isLocal && funcReturnsErrorLast(helperDecl.Type) {
					return st, false
				}
			case *ast.DeclStmt:
				gd, isGen := s.Decl.(*ast.GenDecl)
				if !isGen {
					continue
				}
				for _, spec := range gd.Specs {
					vs, isVal := spec.(*ast.ValueSpec)
					if !isVal {
						continue
					}
					if len(vs.Values) == 0 {
						if idType, isID := unwrapParens(vs.Type).(*ast.Ident); isID && idType.Name == "error" {
							for _, n := range vs.Names {
								if n.Name == "" || n.Name == "_" || n.Name == sliceParam || isProtectedIdent(n.Name) {
									return st, false
								}
							}
						} else {
							for _, n := range vs.Names {
								if n.Name == sliceParam || isProtectedIdent(n.Name) {
									return st, false
								}
							}
						}
						continue
					}
					if len(vs.Names) == 1 && len(vs.Values) == 1 {
						if lit, isLit := unwrapParens(vs.Values[0]).(*ast.FuncLit); isLit {
							if !verifySinkClosureLit(vs.Names[0].Name, lit, mode, inBranch) {
								return st, false
							}
							continue
						}
					}
					if len(vs.Values) == 1 {
						if call, isCall := unwrapParens(vs.Values[0]).(*ast.CallExpr); isCall {
							isSink, srcChunk, callOK := classifySinkAssignCall(len(vs.Names), call, st, mode)
							if !callOK {
								return st, false
							}
							if isSink {
								lhsExprs := make([]ast.Expr, len(vs.Names))
								for i, n := range vs.Names {
									lhsExprs[i] = n
								}
								var sinkOK bool
								st, sinkOK = applySinkAssign(lhsExprs, srcChunk, st, mode)
								if !sinkOK {
									return st, false
								}
								allowedPayloadValueSpecs[vs] = true
								continue
							}
						}
					}
					for _, n := range vs.Names {
						if n.Name == sliceParam || isProtectedIdent(n.Name) {
							return st, false
						}
					}
				}
			case *ast.AssignStmt:
				if len(s.Lhs) == 1 && len(s.Rhs) == 1 {
					if lit, isLit := unwrapParens(s.Rhs[0]).(*ast.FuncLit); isLit {
						id, isID := unwrapParens(s.Lhs[0]).(*ast.Ident)
						if !isID || !verifySinkClosureLit(id.Name, lit, mode, inBranch) {
							return st, false
						}
						continue
					}
				}
				if len(s.Rhs) == 1 {
					if call, isCall := unwrapParens(s.Rhs[0]).(*ast.CallExpr); isCall {
						isSink, srcChunk, callOK := classifySinkAssignCall(len(s.Lhs), call, st, mode)
						if !callOK {
							return st, false
						}
						if isSink {
							var sinkOK bool
							st, sinkOK = applySinkAssign(s.Lhs, srcChunk, st, mode)
							if !sinkOK {
								return st, false
							}
							allowedPayloadAssigns[s] = true
							continue
						}
					}
				}
				// Wrapping `err = &os.PathError{..., Err: err}` inside `if err != nil`.
				if s.Tok == token.ASSIGN && len(s.Lhs) == 1 && len(s.Rhs) == 1 && st.liveErr != "" && inErrCheckFor == st.liveErr {
					if id, isID := unwrapParens(s.Lhs[0]).(*ast.Ident); isID && id.Name == st.liveErr && isWrappedErrStructPtr(s.Rhs[0], st.liveErr) {
						continue
					}
				}
				// Slice-draining write loop helpers: `n := int(r1)`, `if errno != 0 { n = 0 }`, and `b = b[n:]` / `b = b[int(r1):]`.
				if mode == writerBlockSliceLoop && len(s.Lhs) == 1 && len(s.Rhs) == 1 {
					if s.Tok == token.DEFINE {
						if lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident); ok && lhsID.Name != "" && lhsID.Name != "_" && lhsID.Name != sliceParam && !isProtectedIdent(lhsID.Name) {
							rhs := unwrapParens(s.Rhs[0])
							if conv, isCall := rhs.(*ast.CallExpr); isCall && len(conv.Args) == 1 && !conv.Ellipsis.IsValid() {
								if cid, ok := unwrapParens(conv.Fun).(*ast.Ident); ok && (cid.Name == "int" || cid.Name == "uintptr") {
									rhs = unwrapParens(conv.Args[0])
								}
							}
							if srcID, ok := rhs.(*ast.Ident); ok && loopCountAliases[srcID.Name] {
								allLoopCountNames[lhsID.Name] = true
								loopCountAliases[lhsID.Name] = true
								continue
							}
						}
					}
					if s.Tok == token.ASSIGN && st.liveErr != "" && inErrCheckFor == st.liveErr {
						if lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident); ok && loopCountAliases[lhsID.Name] && isZeroIntLit(s.Rhs[0]) {
							continue
						}
					}
					if isCountAdvanceSliceAssign(s, sliceParam, loopCountAliases) {
						if st.sliceAdvancedInLoop {
							return st, false
						}
						st.sliceAdvancedInLoop = true
						allowedPayloadAssigns[s] = true
						continue
					}
				}
				// Chunking loop helpers: `chunk := payload`, `chunk = chunk[:cut]`, `buf := make([]byte, 0, ...)`, `buf = append(buf, ...)`, and `payload = payload[len(chunk):]`.
				if mode == writerBlockChunkLoop && len(s.Lhs) == 1 && len(s.Rhs) == 1 {
					if s.Tok == token.DEFINE && !st.chunkAdvancedInLoop && st.activeChunk == "" {
						if lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident); ok && lhsID.Name != "" && lhsID.Name != "_" && lhsID.Name != sliceParam && !isProtectedIdent(lhsID.Name) {
							if rhsID, ok := unwrapParens(s.Rhs[0]).(*ast.Ident); ok && rhsID.Name == sliceParam {
								chunkVars[lhsID.Name] = true
								allChunkNames[lhsID.Name] = true
								allowedPayloadAssigns[s] = true
								continue
							}
							if makeCall, ok := unwrapParens(s.Rhs[0]).(*ast.CallExpr); ok && !makeCall.Ellipsis.IsValid() && len(makeCall.Args) >= 2 && len(makeCall.Args) <= 3 {
								if makeID, ok := unwrapParens(makeCall.Fun).(*ast.Ident); ok && makeID.Name == "make" && isByteSliceType(makeCall.Args[0]) && isZeroIntLit(makeCall.Args[1]) {
									if len(makeCall.Args) == 3 && exprRefsIdentOutsideLen(makeCall.Args[2], currentPayloadProtected()) {
										return st, false
									}
									freshBufVars[lhsID.Name] = true
									allBufNames[lhsID.Name] = true
									allowedPayloadCalls[makeCall] = true
									allowedPayloadAssigns[s] = true
									continue
								}
							}
						}
					}
					if s.Tok == token.ASSIGN && !st.chunkAdvancedInLoop && st.activeChunk == "" {
						if lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident); ok && chunkVars[lhsID.Name] {
							sl, ok := unwrapParens(s.Rhs[0]).(*ast.SliceExpr)
							if !ok || sl.Slice3 || sl.Low != nil || sl.High == nil || isZeroIntLit(sl.High) || exprRefsIdentOutsideLen(sl.High, currentPayloadProtected()) {
								return st, false
							}
							baseID, ok := unwrapParens(sl.X).(*ast.Ident)
							if !ok || baseID.Name != lhsID.Name {
								return st, false
							}
							allowedPayloadAssigns[s] = true
							continue
						}
						if lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident); ok && freshBufVars[lhsID.Name] {
							appCall, ok := unwrapParens(s.Rhs[0]).(*ast.CallExpr)
							if !ok || !appCall.Ellipsis.IsValid() || len(appCall.Args) != 2 {
								return st, false
							}
							appID, ok := unwrapParens(appCall.Fun).(*ast.Ident)
							if !ok || appID.Name != "append" {
								return st, false
							}
							dstID, ok := unwrapParens(appCall.Args[0]).(*ast.Ident)
							if !ok || dstID.Name != lhsID.Name {
								return st, false
							}
							if srcID, ok := unwrapParens(appCall.Args[1]).(*ast.Ident); ok && (srcID.Name == sliceParam || chunkVars[srcID.Name]) {
								if bufChunkSource[lhsID.Name] != "" {
									return st, false
								}
								bufChunkSource[lhsID.Name] = srcID.Name
								allowedPayloadCalls[appCall] = true
								allowedPayloadAssigns[s] = true
								continue
							}
							if bufChunkSource[lhsID.Name] == "" && isProvablyEmptyByteSliceArg(appCall.Args[1], binding) {
								allowedPayloadCalls[appCall] = true
								allowedPayloadAssigns[s] = true
								continue
							}
							return st, false
						}
					}
					if isChunkAdvanceSliceAssign(s, sliceParam, st.activeChunk) {
						if st.chunkAdvancedInLoop || st.liveErr != "" {
							return st, false
						}
						st.chunkAdvancedInLoop = true
						allowedPayloadAssigns[s] = true
						continue
					}
				}
				payloadProtectedNow := currentPayloadProtected()
				for _, lhs := range s.Lhs {
					switch target := unwrapParens(lhs).(type) {
					case *ast.Ident:
						if target.Name == sliceParam || isProtectedIdent(target.Name) {
							return st, false
						}
					case *ast.IndexExpr:
						if exprReferencesAnyIdent(target.X, payloadProtectedNow) {
							return st, false
						}
					case *ast.StarExpr:
						if exprReferencesAnyIdent(target.X, payloadProtectedNow) {
							return st, false
						}
					}
				}
				for _, rhs := range s.Rhs {
					var hasFuncLit bool
					ast.Inspect(rhs, func(n ast.Node) bool {
						if _, ok := n.(*ast.FuncLit); ok {
							hasFuncLit = true
							return false
						}
						return true
					})
					if hasFuncLit {
						return st, false
					}
				}
			case *ast.IfStmt:
				if s.Init != nil {
					return st, false
				}
				// Monotonic latch in chunking loops: `if chunkErr == nil && err == nil { written += len(chunk) } else if chunkErr != nil && err == nil { err = chunkErr }`
				if mode == writerBlockChunkLoop && !inBranch && st.liveErr != "" && namedErrResult != "" && !namedErrBoundDirectly {
					if updatedCount, latchOK := isMonotonicLatchIf(s, st.liveErr, namedErrResult, namedCountResult, st.activeChunk, numResults == 2); latchOK {
						everLatched = true
						st.latchedSink = true
						if updatedCount && namedCountResult != "" {
							st.latchedCount = true
						}
						st.liveErr = ""
						continue
					}
				}
				// Transient EINTR/EAGAIN retry inside a slice-draining write loop.
				if mode == writerBlockSliceLoop && !inBranch && st.liveErr != "" && isTransientErrnoRetryIf(s, st.liveErr) {
					continue
				}
				// Guarded slice advance `if n > 0 { b = b[n:] }` inside a slice-draining write loop.
				if mode == writerBlockSliceLoop && !inBranch && s.Else == nil && len(s.Body.List) == 1 && isCountPositiveCond(s.Cond, loopCountAliases) {
					if as, ok := s.Body.List[0].(*ast.AssignStmt); ok && isCountAdvanceSliceAssign(as, sliceParam, loopCountAliases) {
						if st.sliceAdvancedInLoop {
							return st, false
						}
						st.sliceAdvancedInLoop = true
						allowedPayloadAssigns[as] = true
						continue
					}
				}
				// Chunking loop exit `if len(payload) == 0 { return written, err }` after advancing payload.
				if mode == writerBlockChunkLoop && !inBranch && st.liveErr == "" && st.chunkAdvancedInLoop && s.Else == nil && len(s.Body.List) == 1 && isSliceLenZeroCond(s.Cond, sliceParam) {
					if ret, isRet := s.Body.List[0].(*ast.ReturnStmt); isRet {
						if !checkReturn(ret, st, false, mode) {
							return st, false
						}
						sawLenZeroExitReturn = true
						continue
					}
				}
				entrySt := st
				checkedErr := condChecksNonZeroErr(s.Cond)
				savedAllErrs := make(map[string]bool, len(allErrNames))
				for k, v := range allErrNames {
					savedAllErrs[k] = v
				}
				savedAllCounts := make(map[string]bool, len(allCountNames))
				for k, v := range allCountNames {
					savedAllCounts[k] = v
				}
				thenSt, thenOK := walkBlock(s.Body.List, entrySt, checkedErr, mode, true)
				if !thenOK {
					return st, false
				}
				thenRet := blockAlwaysReturns(s.Body.List)
				dischargeCheckedErr := func(base writerPathState) writerPathState {
					next := base
					if mode == writerBlockPlain && base.lastChunk == sliceParam {
						if base.lastSinkResultArity == 1 {
							next.dischargedFullSlice1ResultSink = true
						} else if base.lastSinkResultArity == 2 {
							next.discharged2ResultSink = true
						}
					}
					next.liveErr = ""
					return next
				}
				if s.Else == nil {
					if thenRet {
						if entrySt.liveErr != "" && checkedErr == entrySt.liveErr {
							st = dischargeCheckedErr(entrySt)
						} else if mode == writerBlockChunkLoop && entrySt.liveErr == "" {
							// Forbid arbitrary early returns from a chunking loop before draining sliceParam.
							return st, false
						} else {
							st = entrySt
						}
					} else {
						if thenSt != entrySt {
							return st, false
						}
						st = entrySt
					}
					continue
				}
				var elseStmts []ast.Stmt
				switch el := s.Else.(type) {
				case *ast.BlockStmt:
					elseStmts = el.List
				case *ast.IfStmt:
					elseStmts = []ast.Stmt{el}
				default:
					return st, false
				}
				if entrySt.liveErr == "" {
					if thenSt.liveErr != "" && !savedAllErrs[thenSt.liveErr] {
						delete(allErrNames, thenSt.liveErr)
					}
					if thenSt.liveCountVar != "" && !savedAllCounts[thenSt.liveCountVar] {
						delete(allCountNames, thenSt.liveCountVar)
					}
				}
				elseEntry := entrySt
				if thenRet && entrySt.liveErr != "" && checkedErr == entrySt.liveErr {
					elseEntry = dischargeCheckedErr(entrySt)
				}
				elseSt, elseOK := walkBlock(elseStmts, elseEntry, "", mode, true)
				if thenSt.liveErr != "" {
					allErrNames[thenSt.liveErr] = true
				}
				if thenSt.liveCountVar != "" {
					allCountNames[thenSt.liveCountVar] = true
				}
				if !elseOK {
					return st, false
				}
				elseRet := blockAlwaysReturns(elseStmts)
				switch {
				case thenRet && elseRet:
					st = writerPathState{}
				case thenRet && !elseRet:
					st = elseSt
				case !thenRet && elseRet:
					st = thenSt
				default:
					if thenSt != elseSt {
						return st, false
					}
					st = thenSt
				}
			case *ast.ForStmt:
				isPureNonSinkLoop := func(loop *ast.ForStmt) bool {
					if loop.Cond == nil {
						return false
					}
					loopPayloadProtected := currentPayloadProtected()
					var bad bool
					ast.Inspect(loop, func(n ast.Node) bool {
						if bad || n == nil {
							return false
						}
						switch node := n.(type) {
						case *ast.ReturnStmt, *ast.FuncLit, *ast.DeferStmt, *ast.GoStmt, *ast.LabeledStmt, *ast.SendStmt:
							bad = true
							return false
						case *ast.BranchStmt:
							if node.Tok == token.GOTO || node.Label != nil {
								bad = true
								return false
							}
						case *ast.CallExpr:
							if syscallWriteSinkKind(node) != "" {
								bad = true
								return false
							}
							if sel, ok := unwrapParens(node.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Write" {
								bad = true
								return false
							}
							if id, ok := unwrapParens(node.Fun).(*ast.Ident); ok && (localClosures[id.Name] != nil || topFuncs[id.Name] != nil) {
								bad = true
								return false
							}
						case *ast.AssignStmt:
							for _, lhs := range node.Lhs {
								switch target := unwrapParens(lhs).(type) {
								case *ast.Ident:
									if target.Name == sliceParam || isProtectedIdent(target.Name) {
										bad = true
										return false
									}
								case *ast.IndexExpr:
									if exprReferencesAnyIdent(target.X, loopPayloadProtected) {
										bad = true
										return false
									}
								case *ast.StarExpr:
									if exprReferencesAnyIdent(target.X, loopPayloadProtected) {
										bad = true
										return false
									}
								}
							}
						case *ast.IncDecStmt:
							id, ok := unwrapParens(node.X).(*ast.Ident)
							if !ok || id.Name == sliceParam || isProtectedIdent(id.Name) || loopPayloadProtected[id.Name] {
								bad = true
								return false
							}
						}
						return true
					})
					return !bad
				}
				if s.Init != nil || s.Post != nil {
					if !isPureNonSinkLoop(s) {
						return st, false
					}
					continue
				}
				if s.Cond != nil {
					if mode == writerBlockPlain && !inBranch && isLenSlicePositiveCond(s.Cond, sliceParam) && !st.sliceParamMutated && st.liveErr == "" {
						var badLoopBranch bool
						for _, ls := range s.Body.List {
							if _, isBr := ls.(*ast.BranchStmt); isBr {
								badLoopBranch = true
								break
							}
							if ifs, isIf := ls.(*ast.IfStmt); isIf {
								ast.Inspect(ifs, func(n ast.Node) bool {
									if badLoopBranch || n == nil {
										return false
									}
									switch bn := n.(type) {
									case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
										return false
									case *ast.BranchStmt:
										if bn.Tok == token.BREAK || bn.Tok == token.GOTO || bn.Label != nil {
											badLoopBranch = true
											return false
										}
										if bn.Tok == token.CONTINUE {
											if n != ifs.Body.List[0] || len(ifs.Body.List) != 1 || ifs.Else != nil {
												badLoopBranch = true
												return false
											}
										}
									}
									return true
								})
							}
						}
						if badLoopBranch {
							return st, false
						}
						loopCountAliases = map[string]bool{}
						loopSt, loopOK := walkBlock(s.Body.List, writerPathState{}, "", writerBlockSliceLoop, false)
						if !loopOK || loopSt.liveErr != "" || !loopSt.sawSinkInLoop || !loopSt.sliceAdvancedInLoop {
							return st, false
						}
						st.sliceParamMutated = true
						st.dischargedLoop = true
						st.dischargedFullSlice1ResultSink = false
						st.discharged2ResultSink = false
						continue
					}
					if !isPureNonSinkLoop(s) {
						return st, false
					}
					continue
				}
				// Unconditional `for { ... }` chunking loop.
				if mode != writerBlockPlain || inBranch || st.liveErr != "" || st.sliceParamMutated {
					return st, false
				}
				var hasOuterBranch bool
				ast.Inspect(s.Body, func(n ast.Node) bool {
					if hasOuterBranch || n == nil {
						return false
					}
					switch bn := n.(type) {
					case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt, *ast.FuncLit:
						return false
					case *ast.BranchStmt:
						if bn.Tok == token.BREAK || bn.Tok == token.CONTINUE || bn.Tok == token.GOTO || bn.Label != nil {
							hasOuterBranch = true
							return false
						}
					}
					return true
				})
				if hasOuterBranch {
					return st, false
				}
				sawLenZeroExitReturn = false
				chunkVars = map[string]bool{}
				freshBufVars = map[string]bool{}
				bufChunkSource = map[string]string{}
				loopSt, loopOK := walkBlock(s.Body.List, writerPathState{}, "", writerBlockChunkLoop, false)
				if !loopOK || loopSt.liveErr != "" || !loopSt.chunkAdvancedInLoop || !sawLenZeroExitReturn {
					return st, false
				}
				st.sliceParamMutated = true
			case *ast.ReturnStmt:
				if mode == writerBlockChunkLoop && st.liveErr == "" {
					// Chunking loop exits when liveErr == "" must go through `if len(sliceParam) == 0 { return ... }` after advancing.
					return st, false
				}
				if !checkReturn(s, st, st.dischargedLoop && inErrCheckFor == "", mode) {
					return st, false
				}
				st.liveErr = ""
			case *ast.IncDecStmt:
				id, ok := unwrapParens(s.X).(*ast.Ident)
				if !ok || id.Name == sliceParam || isProtectedIdent(id.Name) {
					return st, false
				}
			case *ast.BlockStmt:
				var blkOK bool
				st, blkOK = walkBlock(s.List, st, inErrCheckFor, mode, inBranch)
				if !blkOK {
					return st, false
				}
			default:
				return st, false
			}
		}
		return st, true
	}

	endSt, ok := walkBlock(fn.Body.List, writerPathState{}, "", writerBlockPlain, false)
	if !ok || endSt.liveErr != "" {
		return false
	}

	// Whole-body post-check: forbid labels/goto/labeled-branches, taking addresses of
	// protected/slice variables (other than validated `&b[0]` inside `RawSyscall`),
	// unverified closures, closure mutation/aliasing of outer protected variables, ++/-- on
	// protected vars or indexed/dereferenced operands, defers referencing protected vars,
	// and any unapproved payload/chunk/buf/empty-var aliasing, mutation, or call escape.
	payloadProtected := currentPayloadProtected()
	protectedAll := map[string]bool{sliceParam: true}
	for k := range localClosures {
		protectedAll[k] = true
	}
	for k := range allErrNames {
		protectedAll[k] = true
	}
	for k := range allCountNames {
		protectedAll[k] = true
	}
	for k := range allLoopCountNames {
		protectedAll[k] = true
	}
	for k := range allChunkNames {
		protectedAll[k] = true
	}
	for k := range allBufNames {
		protectedAll[k] = true
	}
	for k := range protectedSinks {
		protectedAll[k] = true
	}

	var postCheckBad bool
	var inspectNoNestedClosures func(node ast.Node)
	inspectNoNestedClosures = func(node ast.Node) {
		if postCheckBad || node == nil {
			return
		}
		switch x := node.(type) {
		case *ast.FuncLit:
			if !verifiedClosureLits[x] {
				postCheckBad = true
				return
			}
			// Do not descend into verified sink closures with the outer variable names
			// (the inner closure has already passed its own whole-body post-check);
			// verify the inner closure does not mutate outer protected variables or
			// reference outer non-empty payload/chunk/buf variables.
			outerProtected := map[string]bool{}
			for k := range protectedAll {
				outerProtected[k] = true
			}
			outerPayload := map[string]bool{sliceParam: true}
			for k := range allChunkNames {
				outerPayload[k] = true
			}
			for k := range allBufNames {
				outerPayload[k] = true
			}
			for _, p := range paramNamesFlat(x.Type.Params) {
				delete(outerProtected, p)
				delete(outerPayload, p)
			}
			if bodyMutatesOrTakesAddrOfAny(x.Body, outerProtected) || exprReferencesAnyIdent(x.Body, outerPayload) {
				postCheckBad = true
			}
			return
		case *ast.GoStmt, *ast.LabeledStmt, *ast.SendStmt:
			postCheckBad = true
			return
		case *ast.BranchStmt:
			if x.Tok == token.GOTO || x.Label != nil {
				postCheckBad = true
				return
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND && !allowedSliceZeroAmps[x] {
				if id, ok := unwrapParens(x.X).(*ast.Ident); ok && protectedAll[id.Name] {
					postCheckBad = true
					return
				}
				if exprReferencesAnyIdent(x.X, payloadProtected) {
					postCheckBad = true
					return
				}
			}
		case *ast.IncDecStmt:
			id, ok := unwrapParens(x.X).(*ast.Ident)
			if !ok || protectedAll[id.Name] || payloadProtected[id.Name] {
				postCheckBad = true
				return
			}
		case *ast.DeferStmt:
			if _, isLit := unwrapParens(x.Call.Fun).(*ast.FuncLit); isLit {
				postCheckBad = true
				return
			}
			if exprReferencesAnyIdent(x.Call, protectedAll) || exprReferencesAnyIdent(x.Call, payloadProtected) {
				postCheckBad = true
				return
			}
		case *ast.ValueSpec:
			if !allowedPayloadValueSpecs[x] {
				for _, v := range x.Values {
					if lit, isLit := unwrapParens(v).(*ast.FuncLit); isLit && verifiedClosureLits[lit] {
						continue
					}
					if exprRefsIdentOutsideLen(v, payloadProtected) {
						postCheckBad = true
						return
					}
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				switch target := unwrapParens(lhs).(type) {
				case *ast.IndexExpr:
					if exprReferencesAnyIdent(target.X, payloadProtected) {
						postCheckBad = true
						return
					}
				case *ast.StarExpr:
					if exprReferencesAnyIdent(target.X, payloadProtected) {
						postCheckBad = true
						return
					}
				}
			}
			if !allowedPayloadAssigns[x] {
				for _, rhs := range x.Rhs {
					if lit, isLit := unwrapParens(rhs).(*ast.FuncLit); isLit && verifiedClosureLits[lit] {
						continue
					}
					if exprRefsIdentOutsideLen(rhs, payloadProtected) {
						postCheckBad = true
						return
					}
				}
			}
		case *ast.ReturnStmt:
			for _, res := range x.Results {
				if call, ok := unwrapParens(res).(*ast.CallExpr); ok && (allowedPayloadCalls[call] || isOneArgLenIdentCall(call)) {
					continue
				}
				if exprRefsIdentOutsideLen(res, payloadProtected) {
					postCheckBad = true
					return
				}
			}
		case *ast.CallExpr:
			if !allowedPayloadCalls[x] && !isOneArgLenIdentCall(x) {
				if exprRefsIdentOutsideLen(x.Fun, payloadProtected) {
					postCheckBad = true
					return
				}
				for _, arg := range x.Args {
					if exprRefsIdentOutsideLen(arg, payloadProtected) {
						postCheckBad = true
						return
					}
				}
			}
		}
		ast.Inspect(node, func(ch ast.Node) bool {
			if ch == node {
				return true
			}
			inspectNoNestedClosures(ch)
			return false
		})
	}
	inspectNoNestedClosures(fn.Body)
	return !postCheckBad
}

func recvTypeIdent(expr ast.Expr) *ast.Ident {
	expr = unwrapParens(expr)
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = unwrapParens(star.X)
	}
	id, _ := expr.(*ast.Ident)
	return id
}

func verifyTestingCustomWriter(typeName string, allowedLit *ast.CompositeLit, binding testingWriterBinding, files []*ast.File, topFuncs map[string]*ast.FuncDecl, typeMethods map[string]map[string]*ast.FuncDecl) bool {
	if typeName == "" || ast.IsExported(typeName) || allowedLit == nil || (len(binding.fileFields) == 0 && len(binding.fdFields) == 0) {
		return false
	}
	allBoundFields := map[string]bool{}
	for k := range binding.fileFields {
		allBoundFields[k] = true
	}
	for k := range binding.fdFields {
		allBoundFields[k] = true
	}

	var matchedSpecs []*ast.TypeSpec
	allowedTypeIdents := map[*ast.Ident]bool{}
	if litTypeID, ok := unwrapParens(allowedLit.Type).(*ast.Ident); ok && litTypeID.Name == typeName {
		allowedTypeIdents[litTypeID] = true
	} else {
		return false
	}

	var methodDecls []*ast.FuncDecl
	for _, f := range files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				if d.Tok != token.TYPE {
					continue
				}
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if ok && ts.Name.Name == typeName {
						matchedSpecs = append(matchedSpecs, ts)
						allowedTypeIdents[ts.Name] = true
					}
				}
			case *ast.FuncDecl:
				if d.Recv != nil && len(d.Recv.List) == 1 {
					if rID := recvTypeIdent(d.Recv.List[0].Type); rID != nil && rID.Name == typeName {
						allowedTypeIdents[rID] = true
						methodDecls = append(methodDecls, d)
					}
				}
			}
		}
	}
	if len(matchedSpecs) != 1 {
		return false
	}
	ts := matchedSpecs[0]
	if ts.Assign.IsValid() || ts.TypeParams != nil {
		return false
	}
	st, ok := unwrapParens(ts.Type).(*ast.StructType)
	if !ok || st.Fields == nil {
		return false
	}
	declaredFields := map[string]bool{}
	for _, field := range st.Fields.List {
		if len(field.Names) == 0 {
			return false
		}
		for _, fn := range field.Names {
			declaredFields[fn.Name] = true
		}
	}
	for bf := range allBoundFields {
		if !declaredFields[bf] {
			return false
		}
	}

	// Verify typeName is referenced nowhere else in package testing (no other
	// composite literals, zero-value vars, new(...), fields, params, or type assertions).
	typeEscaped := false
	for _, f := range files {
		var walkTypeRefs func(n ast.Node)
		walkTypeRefs = func(n ast.Node) {
			if typeEscaped || n == nil {
				return
			}
			switch node := n.(type) {
			case *ast.SelectorExpr:
				walkTypeRefs(node.X)
			case *ast.Ident:
				if node.Name == typeName && !allowedTypeIdents[node] {
					typeEscaped = true
				}
			default:
				ast.Inspect(node, func(ch ast.Node) bool {
					if ch == node {
						return true
					}
					walkTypeRefs(ch)
					return false
				})
			}
		}
		walkTypeRefs(f)
		if typeEscaped {
			return false
		}
	}

	// Verify every method on typeName keeps the receiver unescaped and never
	// mutates or takes the address of any bound field.
	for _, m := range methodDecls {
		if m.Body == nil {
			return false
		}
		recv := recvVarName(m)
		if recv == "" {
			continue
		}
		if bodyMutatesOrTakesAddrOfAny(m.Body, map[string]bool{recv: true}) || !blockOnlySelectsOnIdent(m.Body, recv) {
			return false
		}
		var mutatedBoundField bool
		ast.Inspect(m.Body, func(n ast.Node) bool {
			if mutatedBoundField || n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					if sel, ok := unwrapParens(lhs).(*ast.SelectorExpr); ok && allBoundFields[sel.Sel.Name] {
						if id, ok2 := unwrapParens(sel.X).(*ast.Ident); ok2 && id.Name == recv {
							mutatedBoundField = true
							return false
						}
					}
				}
			case *ast.IncDecStmt:
				if sel, ok := unwrapParens(node.X).(*ast.SelectorExpr); ok && allBoundFields[sel.Sel.Name] {
					if id, ok2 := unwrapParens(sel.X).(*ast.Ident); ok2 && id.Name == recv {
						mutatedBoundField = true
						return false
					}
				}
			case *ast.UnaryExpr:
				if node.Op == token.AND {
					if sel, ok := unwrapParens(node.X).(*ast.SelectorExpr); ok && allBoundFields[sel.Sel.Name] {
						if id, ok2 := unwrapParens(sel.X).(*ast.Ident); ok2 && id.Name == recv {
							mutatedBoundField = true
							return false
						}
					}
				}
			}
			return true
		})
		if mutatedBoundField {
			return false
		}
	}

	methods := typeMethods[typeName]
	if methods == nil || len(methods) != len(methodDecls) {
		return false
	}
	if methods["ReadFrom"] != nil {
		return false
	}
	if wsFn := methods["WriteString"]; wsFn != nil {
		wsRecv := recvVarName(wsFn)
		if wsRecv == "" || wsFn.Body == nil || len(wsFn.Body.List) != 1 || wsFn.Type == nil || wsFn.Type.Params == nil || wsFn.Type.Results == nil || wsFn.Type.Params.NumFields() != 1 || len(wsFn.Type.Params.List) != 1 || len(wsFn.Type.Params.List[0].Names) != 1 || wsFn.Type.Results.NumFields() != 2 || !firstResultIsInt(wsFn.Type.Results) || !funcReturnsErrorLast(wsFn.Type) {
			return false
		}
		if _, ok := isIdentNamed(wsFn.Type.Params.List[0].Type, "string"); !ok {
			return false
		}
		sParam := wsFn.Type.Params.List[0].Names[0].Name
		if sParam == "" || sParam == "_" || sParam == wsRecv || funcShadowsAnyIdent(wsFn, map[string]bool{"byte": true, "string": true, "int": true, "error": true}) {
			return false
		}
		ret, ok := wsFn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return false
		}
		wCall, ok := unwrapParens(ret.Results[0]).(*ast.CallExpr)
		if !ok || wCall.Ellipsis.IsValid() || len(wCall.Args) != 1 {
			return false
		}
		if _, ok := isSelectorBaseField(wCall.Fun, wsRecv, "Write"); !ok {
			return false
		}
		conv, ok := unwrapParens(wCall.Args[0]).(*ast.CallExpr)
		if !ok || conv.Ellipsis.IsValid() || len(conv.Args) != 1 || !isByteSliceType(conv.Fun) {
			return false
		}
		if _, ok := isIdentNamed(conv.Args[0], sParam); !ok {
			return false
		}
	}
	writeFn := methods["Write"]
	if writeFn == nil || writeFn.Body == nil || writeFn.Type == nil || writeFn.Type.Params == nil || writeFn.Type.Results == nil || writeFn.Type.Results.NumFields() != 2 || !firstResultIsInt(writeFn.Type.Results) || !funcReturnsErrorLast(writeFn.Type) {
		return false
	}
	binding.sliceVar = singleByteSliceParamIdent(writeFn.Type.Params)
	if binding.sliceVar == "" {
		return false
	}
	return verifyTestingWriterFunc(typeName, writeFn, binding, topFuncs, typeMethods, map[string]bool{})
}

func localLogFileIdent(expr ast.Expr) (string, bool) {
	id, ok := unwrapParens(expr).(*ast.Ident)
	if !ok || id.Name == "" || id.Name == "_" || id.Name == "nil" || id.Name == "Discard" {
		return "", false
	}
	return id.Name, true
}

func bodyDeclaresAnyIdent(body *ast.BlockStmt, names map[string]bool) bool {
	if body == nil || len(names) == 0 {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.ValueSpec:
			for _, id := range node.Names {
				if names[id.Name] {
					found = true
					return false
				}
			}
		case *ast.TypeSpec:
			if node.Name != nil && names[node.Name.Name] {
				found = true
				return false
			}
			if node.TypeParams != nil {
				for _, f := range node.TypeParams.List {
					for _, id := range f.Names {
						if names[id.Name] {
							found = true
							return false
						}
					}
				}
			}
		case *ast.FuncLit:
			if node.Type != nil {
				for _, fl := range []*ast.FieldList{node.Type.Params, node.Type.Results} {
					if fl == nil {
						continue
					}
					for _, f := range fl.List {
						for _, id := range f.Names {
							if names[id.Name] {
								found = true
								return false
							}
						}
					}
				}
			}
		case *ast.AssignStmt:
			if node.Tok == token.DEFINE {
				for _, lhs := range node.Lhs {
					if id, ok := unwrapParens(lhs).(*ast.Ident); ok && names[id.Name] {
						found = true
						return false
					}
				}
			}
		case *ast.RangeStmt:
			if node.Tok == token.DEFINE {
				if id, ok := unwrapParens(node.Key).(*ast.Ident); ok && names[id.Name] {
					found = true
					return false
				}
				if id, ok := unwrapParens(node.Value).(*ast.Ident); ok && names[id.Name] {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

func funcDeclaresParamOrResult(fn *ast.FuncDecl, name string) bool {
	if fn == nil || name == "" {
		return false
	}
	if recvVarName(fn) == name {
		return true
	}
	if fn.Type != nil {
		for _, fl := range []*ast.FieldList{fn.Type.TypeParams, fn.Type.Params, fn.Type.Results} {
			if fl == nil {
				continue
			}
			for _, f := range fl.List {
				for _, id := range f.Names {
					if id.Name == name {
						return true
					}
				}
			}
		}
	}
	return false
}

func funcShadowsAnyIdent(fn *ast.FuncDecl, names map[string]bool) bool {
	if fn == nil || len(names) == 0 {
		return false
	}
	for name := range names {
		if funcDeclaresParamOrResult(fn, name) {
			return true
		}
	}
	return bodyDeclaresAnyIdent(fn.Body, names)
}

func funcLitShadowsAnyIdent(fl *ast.FuncLit, names map[string]bool) bool {
	if fl == nil || len(names) == 0 {
		return false
	}
	if fl.Type != nil {
		for _, flist := range []*ast.FieldList{fl.Type.Params, fl.Type.Results} {
			if flist == nil {
				continue
			}
			for _, f := range flist.List {
				for _, id := range f.Names {
					if names[id.Name] {
						return true
					}
				}
			}
		}
	}
	return bodyDeclaresAnyIdent(fl.Body, names)
}

func bodyHasControlFlowOrRecoverBypass(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	bad := false
	ast.Inspect(body, func(n ast.Node) bool {
		if bad || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.LabeledStmt:
			bad = true
			return false
		case *ast.BranchStmt:
			if node.Tok == token.GOTO || node.Tok == token.FALLTHROUGH || node.Label != nil {
				bad = true
				return false
			}
		case *ast.CallExpr:
			if id, ok := unwrapParens(node.Fun).(*ast.Ident); ok && id.Name == "recover" {
				bad = true
				return false
			}
		}
		return true
	})
	return bad
}

func exprHasCallOrFuncLit(expr ast.Expr) bool {
	if expr == nil {
		return false
	}
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		switch n.(type) {
		case *ast.CallExpr, *ast.FuncLit:
			found = true
			return false
		}
		return true
	})
	return found
}

func isPositiveIntLit(expr ast.Expr) bool {
	lit, ok := unwrapParens(expr).(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return false
	}
	v, err := strconv.ParseUint(lit.Value, 0, 64)
	return err == nil && v > 0
}

func isConstantOrTrivialCond(cond ast.Expr) bool {
	cond = unwrapParens(cond)
	switch e := cond.(type) {
	case nil:
		return true
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		return e.Name == "true" || e.Name == "false" || e.Name == "nil"
	case *ast.UnaryExpr:
		if e.Op == token.NOT {
			return isConstantOrTrivialCond(e.X)
		}
		return exprHasCallOrFuncLit(e.X)
	case *ast.BinaryExpr:
		if exprHasCallOrFuncLit(e.X) || exprHasCallOrFuncLit(e.Y) {
			return true
		}
		if e.Op == token.LAND || e.Op == token.LOR {
			return isConstantOrTrivialCond(e.X) || isConstantOrTrivialCond(e.Y)
		}
		if isConstantOrTrivialCond(e.X) && isConstantOrTrivialCond(e.Y) {
			return true
		}
		if xID, ok := unwrapParens(e.X).(*ast.Ident); ok {
			if yID, ok2 := unwrapParens(e.Y).(*ast.Ident); ok2 && xID.Name == yID.Name {
				return true
			}
		}
		return false
	default:
		return exprHasCallOrFuncLit(cond)
	}
}

func derefFlagNonEmptyCondIdent(cond ast.Expr) (string, bool) {
	bin, ok := unwrapParens(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return "", false
	}
	checkPair := func(ptrExpr, strExpr ast.Expr) (string, bool) {
		lit, ok := unwrapParens(strExpr).(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING || (lit.Value != `""` && lit.Value != "``") {
			return "", false
		}
		star, ok := unwrapParens(ptrExpr).(*ast.StarExpr)
		if !ok {
			return "", false
		}
		id, ok := unwrapParens(star.X).(*ast.Ident)
		if !ok || id.Name == "" || id.Name == "_" {
			return "", false
		}
		return id.Name, true
	}
	if name, ok := checkPair(bin.X, bin.Y); ok {
		return name, true
	}
	return checkPair(bin.Y, bin.X)
}

func isBenignStderrDiagStmt(stmt ast.Stmt, hasOSImport, hasFmtImport bool) bool {
	switch s := stmt.(type) {
	case *ast.EmptyStmt:
		return true
	case *ast.ExprStmt:
		if !hasOSImport || !hasFmtImport {
			return false
		}
		call, ok := unwrapParens(s.X).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) < 2 {
			return false
		}
		sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Fprint" && sel.Sel.Name != "Fprintf" && sel.Sel.Name != "Fprintln") {
			return false
		}
		pkgID, ok := unwrapParens(sel.X).(*ast.Ident)
		if !ok || pkgID.Name != "fmt" {
			return false
		}
		arg0Sel, ok := unwrapParens(call.Args[0]).(*ast.SelectorExpr)
		if !ok || arg0Sel.Sel.Name != "Stderr" {
			return false
		}
		osID, ok := unwrapParens(arg0Sel.X).(*ast.Ident)
		if !ok || osID.Name != "os" {
			return false
		}
		for _, arg := range call.Args {
			if exprHasCallOrFuncLit(arg) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func isFailureForcingExitOrPanicStmt(stmt ast.Stmt, errVar string, hasOSImport bool) bool {
	es, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := unwrapParens(es.X).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 1 || exprHasCallOrFuncLit(call.Args[0]) {
		return false
	}
	switch fun := unwrapParens(call.Fun).(type) {
	case *ast.SelectorExpr:
		id, ok := unwrapParens(fun.X).(*ast.Ident)
		return ok && id.Name == "os" && fun.Sel.Name == "Exit" && hasOSImport && isPositiveIntLit(call.Args[0])
	case *ast.Ident:
		if fun.Name != "panic" {
			return false
		}
		arg := unwrapParens(call.Args[0])
		if id, ok := arg.(*ast.Ident); ok && errVar != "" && id.Name == errVar {
			return true
		}
		if lit, ok := arg.(*ast.BasicLit); ok {
			return lit.Kind != token.STRING || (lit.Value != `""` && lit.Value != "``")
		}
		return false
	default:
		return false
	}
}

func isFailureForcingErrHandler(ifs *ast.IfStmt, errVar string, hasOSImport, hasFmtImport bool) bool {
	if ifs == nil || ifs.Else != nil || errVar == "" || errVar == "_" || errVar == "nil" || condChecksNonZeroErr(ifs.Cond) != errVar || ifs.Body == nil || len(ifs.Body.List) == 0 {
		return false
	}
	if bodyMutatesOrTakesAddrOfAny(ifs.Body, map[string]bool{errVar: true}) || bodyDeclaresAnyIdent(ifs.Body, map[string]bool{errVar: true}) {
		return false
	}
	for _, bs := range ifs.Body.List[:len(ifs.Body.List)-1] {
		if !isBenignStderrDiagStmt(bs, hasOSImport, hasFmtImport) {
			return false
		}
	}
	return isFailureForcingExitOrPanicStmt(ifs.Body.List[len(ifs.Body.List)-1], errVar, hasOSImport)
}

func errHandlerTerminalCall(ifs *ast.IfStmt) *ast.CallExpr {
	if ifs == nil || ifs.Body == nil || len(ifs.Body.List) == 0 {
		return nil
	}
	es, ok := ifs.Body.List[len(ifs.Body.List)-1].(*ast.ExprStmt)
	if !ok {
		return nil
	}
	c, _ := unwrapParens(es.X).(*ast.CallExpr)
	return c
}

func hasWritableOSOpenFlag(expr ast.Expr) (hasWrite, hasRdwr, ok bool) {
	expr = unwrapParens(expr)
	if bin, isBin := expr.(*ast.BinaryExpr); isBin {
		if bin.Op != token.OR {
			return false, false, false
		}
		lw, lr, lok := hasWritableOSOpenFlag(bin.X)
		rw, rr, rok := hasWritableOSOpenFlag(bin.Y)
		if !lok || !rok || (lw && rr) || (lr && rw) {
			return false, false, false
		}
		return lw || rw, lr || rr, true
	}
	sel, isSel := expr.(*ast.SelectorExpr)
	if !isSel || !strings.HasPrefix(sel.Sel.Name, "O_") || sel.Sel.Name == "O_RDONLY" {
		return false, false, false
	}
	id, isID := unwrapParens(sel.X).(*ast.Ident)
	if !isID || id.Name != "os" {
		return false, false, false
	}
	return sel.Sel.Name == "O_WRONLY", sel.Sel.Name == "O_RDWR", true
}

func isWritableOSLogOpenCall(call *ast.CallExpr, requiredFlagVar string) bool {
	if call == nil || call.Ellipsis.IsValid() || len(call.Args) == 0 || requiredFlagVar == "" {
		return false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkgID, ok := unwrapParens(sel.X).(*ast.Ident)
	if !ok || pkgID.Name != "os" {
		return false
	}
	pathArg := unwrapParens(call.Args[0])
	star, ok := pathArg.(*ast.StarExpr)
	if !ok {
		return false
	}
	id, ok := unwrapParens(star.X).(*ast.Ident)
	if !ok || id.Name != requiredFlagVar {
		return false
	}
	switch sel.Sel.Name {
	case "Create":
		return len(call.Args) == 1
	case "OpenFile":
		if len(call.Args) != 3 || exprHasCallOrFuncLit(call.Args[2]) {
			return false
		}
		w, rw, ok := hasWritableOSOpenFlag(call.Args[1])
		return ok && (w || rw)
	default:
		return false
	}
}

func stmtAlwaysTerminates(stmt ast.Stmt) bool {
	if stmt == nil {
		return false
	}
	switch s := stmt.(type) {
	case *ast.ReturnStmt, *ast.BranchStmt:
		return true
	case *ast.BlockStmt:
		return slices.ContainsFunc(s.List, stmtAlwaysTerminates)
	case *ast.ExprStmt:
		call, ok := unwrapParens(s.X).(*ast.CallExpr)
		if !ok {
			return false
		}
		if id, ok := unwrapParens(call.Fun).(*ast.Ident); ok && id.Name == "panic" {
			return true
		}
		if sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Exit" {
			return true
		}
		return false
	case *ast.IfStmt:
		if s.Else == nil || !stmtAlwaysTerminates(s.Body) {
			return false
		}
		return stmtAlwaysTerminates(s.Else)
	case *ast.ForStmt:
		if s.Cond != nil {
			return false
		}
		hasBreak := false
		ast.Inspect(s.Body, func(n ast.Node) bool {
			if hasBreak || n == nil {
				return false
			}
			switch br := n.(type) {
			case *ast.FuncLit, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
				return false
			case *ast.BranchStmt:
				if br.Tok == token.BREAK {
					hasBreak = true
					return false
				}
			}
			return true
		})
		return !hasBreak
	default:
		return false
	}
}

func findEnclosingFuncAndAncestors(f *ast.File, target ast.Node) (*ast.FuncDecl, []ast.Node) {
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		var stack, found []ast.Node
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if found != nil {
				return false
			}
			if n == nil {
				stack = stack[:len(stack)-1]
				return false
			}
			stack = append(stack, n)
			if n == target {
				found = slices.Clone(stack)
				return false
			}
			return true
		})
		if found != nil {
			return fn, found
		}
	}
	return nil, nil
}

func canonicalDepsReceiverKey(fn *ast.FuncDecl, call *ast.CallExpr) string {
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	recvX := unwrapParens(sel.X)
	switch r := recvX.(type) {
	case *ast.Ident:
		if r.Name == "" || r.Name == "_" || r.Name == "nil" {
			return ""
		}
		return r.Name
	case *ast.SelectorExpr:
		baseID, ok := unwrapParens(r.X).(*ast.Ident)
		if !ok || baseID.Name == "" || baseID.Name == "_" || r.Sel.Name == "" {
			return ""
		}
		if fn != nil && fn.Recv != nil && len(fn.Recv.List) == 1 && recvTypeName(fn.Recv.List[0].Type) == "M" && recvVarName(fn) == baseID.Name {
			return "<M>." + r.Sel.Name
		}
		return baseID.Name + "." + r.Sel.Name
	default:
		return ""
	}
}

type logFileOpenState struct {
	declared   bool
	opened     bool
	pendingErr string
}

func verifyLogFileOpenPrefix(stmts []ast.Stmt, fileVar, requiredFlagVar string, hasOSImport, hasFmtImport bool, allowedExits map[*ast.CallExpr]bool) bool {
	if !hasOSImport || fileVar == "" {
		return false
	}
	var walk func(list []ast.Stmt, st logFileOpenState) (logFileOpenState, bool)
	walk = func(list []ast.Stmt, st logFileOpenState) (logFileOpenState, bool) {
		for _, raw := range list {
			switch s := raw.(type) {
			case *ast.EmptyStmt:
			case *ast.DeclStmt:
				gd, ok := s.Decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					return st, false
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || len(vs.Values) != 0 {
						return st, false
					}
					for _, id := range vs.Names {
						if id.Name == fileVar {
							if st.declared || st.opened {
								return st, false
							}
							if vs.Type != nil {
								star, ok := unwrapParens(vs.Type).(*ast.StarExpr)
								if !ok {
									return st, false
								}
								sel, ok := unwrapParens(star.X).(*ast.SelectorExpr)
								if !ok || sel.Sel.Name != "File" {
									return st, false
								}
								pkgID, ok := unwrapParens(sel.X).(*ast.Ident)
								if !ok || pkgID.Name != "os" {
									return st, false
								}
							}
							st.declared = true
						}
					}
				}
			case *ast.AssignStmt:
				if (s.Tok != token.DEFINE && s.Tok != token.ASSIGN) || len(s.Lhs) != 2 || len(s.Rhs) != 1 || st.opened || st.pendingErr != "" {
					return st, false
				}
				fID, ok1 := unwrapParens(s.Lhs[0]).(*ast.Ident)
				eID, ok2 := unwrapParens(s.Lhs[1]).(*ast.Ident)
				if !ok1 || !ok2 || fID.Name != fileVar || eID.Name == "" || eID.Name == "_" || eID.Name == "nil" || eID.Name == fileVar {
					return st, false
				}
				if s.Tok == token.ASSIGN && !st.declared {
					return st, false
				}
				call, ok := unwrapParens(s.Rhs[0]).(*ast.CallExpr)
				if !ok || !isWritableOSLogOpenCall(call, requiredFlagVar) {
					return st, false
				}
				st.declared = true
				st.opened = true
				st.pendingErr = eID.Name
			case *ast.IfStmt:
				if s.Init != nil {
					return st, false
				}
				if s.Else == nil {
					if st.opened && st.pendingErr != "" && condChecksNonZeroErr(s.Cond) == st.pendingErr {
						if !isFailureForcingErrHandler(s, st.pendingErr, hasOSImport, hasFmtImport) {
							return st, false
						}
						if allowedExits != nil {
							if c := errHandlerTerminalCall(s); c != nil {
								allowedExits[c] = true
							}
						}
						st.pendingErr = ""
						continue
					}
					if st.opened && st.pendingErr != "" && condChecksEqErr(s.Cond, st.pendingErr) && len(s.Body.List) == 1 {
						if es, ok := s.Body.List[0].(*ast.ExprStmt); ok {
							if call, ok2 := unwrapParens(es.X).(*ast.CallExpr); ok2 && !call.Ellipsis.IsValid() && len(call.Args) == 2 && !exprHasCallOrFuncLit(call.Args[0]) && !exprHasCallOrFuncLit(call.Args[1]) {
								if sel, ok3 := unwrapParens(call.Fun).(*ast.SelectorExpr); ok3 && sel.Sel.Name == "Seek" {
									if rID, ok4 := unwrapParens(sel.X).(*ast.Ident); ok4 && rID.Name == fileVar {
										continue
									}
								}
							}
						}
					}
					return st, false
				}
				if isConstantOrTrivialCond(s.Cond) {
					return st, false
				}
				var elseList []ast.Stmt
				switch el := s.Else.(type) {
				case *ast.BlockStmt:
					elseList = el.List
				case *ast.IfStmt:
					elseList = []ast.Stmt{el}
				default:
					return st, false
				}
				stThen, okThen := walk(s.Body.List, st)
				stElse, okElse := walk(elseList, st)
				if !okThen || !okElse || stThen.declared != stElse.declared || stThen.opened != stElse.opened || stThen.pendingErr != stElse.pendingErr {
					return st, false
				}
				st = stThen
			default:
				return st, false
			}
		}
		return st, true
	}
	finalState, ok := walk(stmts, logFileOpenState{})
	return ok && finalState.declared && finalState.opened && finalState.pendingErr == ""
}

func verifyTestingStartLogArg(arg ast.Expr, files []*ast.File, topFuncs map[string]*ast.FuncDecl, typeMethods map[string]map[string]*ast.FuncDecl) (string, string, bool) {
	arg = unwrapParens(arg)
	switch expr := arg.(type) {
	case *ast.Ident:
		fileVar, ok := localLogFileIdent(expr)
		return fileVar, "", ok
	case *ast.UnaryExpr, *ast.CompositeLit:
		lit, wType := compositeWriterLit(expr)
		if lit == nil || wType == "" {
			return "", "", false
		}
		var fileVar string
		matchFile := func(src ast.Expr) bool {
			name, ok := localLogFileIdent(src)
			if !ok || (fileVar != "" && fileVar != name) {
				return false
			}
			fileVar = name
			return true
		}
		binding, ok := extractCompositeWriterBinding(lit, matchFile)
		if !ok || fileVar == "" || !verifyTestingCustomWriter(wType, lit, binding, files, topFuncs, typeMethods) {
			return "", "", false
		}
		return fileVar, "", true
	case *ast.CallExpr:
		if expr.Ellipsis.IsValid() {
			return "", "", false
		}
		wrapId, ok := unwrapParens(expr.Fun).(*ast.Ident)
		if !ok || len(expr.Args) == 0 {
			return "", "", false
		}
		fileVar, ok := localLogFileIdent(expr.Args[0])
		if !ok {
			return "", "", false
		}
		for _, extraArg := range expr.Args[1:] {
			badExtra := false
			ast.Inspect(extraArg, func(n ast.Node) bool {
				if badExtra || n == nil {
					return false
				}
				if u, ok := n.(*ast.UnaryExpr); ok && u.Op == token.AND {
					if id, ok2 := unwrapParens(u.X).(*ast.Ident); ok2 && id.Name == fileVar {
						badExtra = true
						return false
					}
				}
				return true
			})
			if badExtra {
				return "", "", false
			}
		}
		wrapFn := topFuncs[wrapId.Name]
		if wrapFn == nil || wrapFn.Body == nil || wrapFn.Type == nil || wrapFn.Type.Params == nil || wrapFn.Type.Results == nil || wrapFn.Type.Results.NumFields() != 1 {
			return "", "", false
		}
		pNames := paramNamesFlat(wrapFn.Type.Params)
		if len(pNames) == 0 || len(pNames) != len(expr.Args) || pNames[0] == "" || pNames[0] == "_" {
			return "", "", false
		}
		if !blockAlwaysReturns(wrapFn.Body.List) {
			return "", "", false
		}
		fileParam := pNames[0]
		if bodyMutatesOrTakesAddrOfAny(wrapFn.Body, map[string]bool{fileParam: true}) || bodyDeclaresAnyIdent(wrapFn.Body, map[string]bool{fileParam: true}) {
			return "", "", false
		}
		isWrapFileSource := func(src ast.Expr) bool {
			id, ok := unwrapParens(src).(*ast.Ident)
			return ok && id.Name == fileParam
		}
		var sawReturn bool
		valid := true
		ast.Inspect(wrapFn.Body, func(n ast.Node) bool {
			if !valid || n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.FuncLit, *ast.DeferStmt, *ast.GoStmt, *ast.LabeledStmt, *ast.BranchStmt,
				*ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
				valid = false
				return false
			case *ast.IfStmt:
				if isConstantOrTrivialCond(node.Cond) {
					valid = false
					return false
				}
			case *ast.ReturnStmt:
				sawReturn = true
				if len(node.Results) != 1 {
					valid = false
					return false
				}
				res := unwrapParens(node.Results[0])
				if isWrapFileSource(res) {
					return false
				}
				if lit, wType := compositeWriterLit(res); lit != nil && wType != "" {
					if binding, ok := extractCompositeWriterBinding(lit, isWrapFileSource); ok && verifyTestingCustomWriter(wType, lit, binding, files, topFuncs, typeMethods) {
						return false
					}
				}
				valid = false
				return false
			}
			return true
		})
		if !sawReturn || !valid {
			return "", "", false
		}
		return fileVar, wrapId.Name, true
	default:
		return "", "", false
	}
}

type verifiedStartInfo struct {
	file          *ast.File
	fn            *ast.FuncDecl
	topStmt       ast.Stmt
	declBlock     *ast.BlockStmt
	declTargetIdx int
	fileVar       string
	recvKey       string
	flagGuard     string
	openExits     map[*ast.CallExpr]bool
}

type verifiedStopInfo struct {
	file         *ast.File
	fn           *ast.FuncDecl
	topStmt      ast.Stmt
	parentBlk    *ast.BlockStmt
	stmtPos      int
	afterStopPos int
	recvKey      string
	flagGuard    string
	stopExit     *ast.CallExpr
}

type testingExitSite struct {
	file      *ast.File
	call      *ast.CallExpr
	encFn     *ast.FuncDecl
	ancestors []ast.Node
}

func flagStringEmptyDefaultName(call *ast.CallExpr) (string, bool) {
	if call == nil || call.Ellipsis.IsValid() || len(call.Args) != 3 {
		return "", false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "String" {
		return "", false
	}
	pkgID, ok := unwrapParens(sel.X).(*ast.Ident)
	if !ok || pkgID.Name != "flag" {
		return "", false
	}
	litName, ok := unwrapParens(call.Args[0]).(*ast.BasicLit)
	if !ok || litName.Kind != token.STRING {
		return "", false
	}
	parsedName, err := strconv.Unquote(litName.Value)
	if err != nil || parsedName == "" {
		return "", false
	}
	litDef, ok := unwrapParens(call.Args[1]).(*ast.BasicLit)
	if !ok || litDef.Kind != token.STRING || (litDef.Value != `""` && litDef.Value != "``") {
		return "", false
	}
	if exprHasCallOrFuncLit(call.Args[2]) {
		return "", false
	}
	return parsedName, true
}

func isFlagStringEmptyDefaultCall(call *ast.CallExpr, flagName string) bool {
	got, ok := flagStringEmptyDefaultName(call)
	return ok && got == flagName
}

func isBenignFlagInitRegStmt(stmt ast.Stmt, seenFlags map[string]bool) bool {
	var call *ast.CallExpr
	var isVarCall bool
	switch s := stmt.(type) {
	case *ast.EmptyStmt:
		return true
	case *ast.AssignStmt:
		if s.Tok != token.ASSIGN || len(s.Lhs) != 1 || len(s.Rhs) != 1 {
			return false
		}
		lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident)
		if !ok || lhsID.Name == "" || lhsID.Name == "_" {
			return false
		}
		c, ok := unwrapParens(s.Rhs[0]).(*ast.CallExpr)
		if !ok {
			return false
		}
		call = c
	case *ast.ExprStmt:
		c, ok := unwrapParens(s.X).(*ast.CallExpr)
		if !ok {
			return false
		}
		call = c
		isVarCall = true
	default:
		return false
	}
	if call.Ellipsis.IsValid() || len(call.Args) != 3 {
		return false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkgID, ok := unwrapParens(sel.X).(*ast.Ident)
	if !ok || pkgID.Name != "flag" {
		return false
	}
	var nameLitExpr, usageLitExpr ast.Expr
	if isVarCall {
		if sel.Sel.Name != "Var" {
			return false
		}
		u, ok := unwrapParens(call.Args[0]).(*ast.UnaryExpr)
		if !ok || u.Op != token.AND {
			return false
		}
		if _, ok := unwrapParens(u.X).(*ast.Ident); !ok {
			return false
		}
		nameLitExpr = call.Args[1]
		usageLitExpr = call.Args[2]
	} else {
		switch sel.Sel.Name {
		case "Bool", "Int", "Int64", "Uint", "Uint64", "String", "Float64", "Duration":
		default:
			return false
		}
		nameLitExpr = call.Args[0]
		defExpr := unwrapParens(call.Args[1])
		if exprHasCallOrFuncLit(defExpr) {
			defCall, ok := defExpr.(*ast.CallExpr)
			if !ok || defCall.Ellipsis.IsValid() || len(defCall.Args) != 1 || exprHasCallOrFuncLit(defCall.Args[0]) {
				return false
			}
			defSel, ok := unwrapParens(defCall.Fun).(*ast.SelectorExpr)
			if !ok || defSel.Sel.Name != "GOMAXPROCS" {
				return false
			}
			rtID, ok := unwrapParens(defSel.X).(*ast.Ident)
			if !ok || rtID.Name != "runtime" {
				return false
			}
		}
		usageLitExpr = call.Args[2]
	}
	nameLit, ok := unwrapParens(nameLitExpr).(*ast.BasicLit)
	if !ok || nameLit.Kind != token.STRING {
		return false
	}
	flagName, err := strconv.Unquote(nameLit.Value)
	if err != nil || flagName == "" || seenFlags[flagName] {
		return false
	}
	usageLit, ok := unwrapParens(usageLitExpr).(*ast.BasicLit)
	if !ok || usageLit.Kind != token.STRING {
		return false
	}
	seenFlags[flagName] = true
	return true
}

func blockHasFailureForcingClose(stmts []ast.Stmt, targetVar string, hasOS, hasFmt bool) (*ast.Ident, *ast.CallExpr, bool) {
	closeCallAssign := func(stmt ast.Stmt) (string, *ast.Ident) {
		as, ok := stmt.(*ast.AssignStmt)
		if !ok || (as.Tok != token.DEFINE && as.Tok != token.ASSIGN) || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return "", nil
		}
		errID, ok := unwrapParens(as.Lhs[0]).(*ast.Ident)
		if !ok || errID.Name == "" || errID.Name == "_" || errID.Name == "nil" {
			return "", nil
		}
		call, ok := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) != 0 {
			return "", nil
		}
		sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Close" {
			return "", nil
		}
		recvID, ok := unwrapParens(sel.X).(*ast.Ident)
		if !ok || recvID.Name != targetVar {
			return "", nil
		}
		return errID.Name, recvID
	}
	for i := 0; i < len(stmts); i++ {
		if ifs, isIf := stmts[i].(*ast.IfStmt); isIf && ifs.Init != nil {
			if errVar, recvID := closeCallAssign(ifs.Init); recvID != nil {
				if isFailureForcingErrHandler(ifs, errVar, hasOS, hasFmt) {
					return recvID, errHandlerTerminalCall(ifs), true
				}
				return nil, nil, false
			}
		}
		if i+1 < len(stmts) {
			if errVar, recvID := closeCallAssign(stmts[i]); recvID != nil {
				if ifs, isIf := stmts[i+1].(*ast.IfStmt); isIf && ifs.Init == nil && isFailureForcingErrHandler(ifs, errVar, hasOS, hasFmt) {
					return recvID, errHandlerTerminalCall(ifs), true
				}
				return nil, nil, false
			}
		}
		if !isBenignStderrDiagStmt(stmts[i], hasOS, hasFmt) {
			return nil, nil, false
		}
	}
	return nil, nil, false
}

func verifyTestingPackageAST(files []*ast.File, runtimePullLinknames, selfPushLinknames map[string]bool) error {
	var hasValidContextMethod, hasInvalidContextMethod bool
	fileImportsOS := map[*ast.File]bool{}
	fileImportsFmt := map[*ast.File]bool{}
	fileImportsIO := map[*ast.File]bool{}
	fileImportsFlag := map[*ast.File]bool{}
	fileImportsSync := map[*ast.File]bool{}
	fileImportsSyscall := map[*ast.File]bool{}
	funcFile := map[*ast.FuncDecl]*ast.File{}
	topFuncs := map[string]*ast.FuncDecl{}
	dupTopFuncs := map[string]bool{}
	typeMethods := map[string]map[string]*ast.FuncDecl{}
	dupTypeMethods := false
	pkgVarCounts := map[string]int{}
	zeroInitPkgVars := map[string]*ast.ValueSpec{}
	zeroInitBoolVars := map[string]bool{}
	initPkgVars := map[string]ast.Expr{}
	initPkgVarFile := map[string]*ast.File{}
	flagAllowedDeclIdents := map[string]map[*ast.Ident]bool{}
	recordAllowedFlagIdent := func(name string, id *ast.Ident) {
		if name == "" || name == "_" || id == nil {
			return
		}
		if flagAllowedDeclIdents[name] == nil {
			flagAllowedDeclIdents[name] = map[*ast.Ident]bool{}
		}
		flagAllowedDeclIdents[name][id] = true
	}
	pkgReserved := map[string]bool{
		"os":      true,
		"fmt":     true,
		"io":      true,
		"flag":    true,
		"sync":    true,
		"syscall": true,
		"panic":   true,
		"recover": true,
		"new":     true,
		"len":     true,
		"append":  true,
		"make":    true,
		"copy":    true,
		"clear":   true,
		"uintptr": true,
		"int":     true,
		"byte":    true,
		"string":  true,
		"bool":    true,
		"nil":     true,
		"error":   true,
		"true":    true,
		"false":   true,
	}

	for _, f := range files {
		for _, imp := range f.Imports {
			importPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			if imp.Name != nil && (imp.Name.Name == "." || pkgReserved[imp.Name.Name]) {
				return fmt.Errorf("testing: forbidden or shadowing import alias %q", imp.Name.Name)
			}
			switch importPath {
			case "os":
				if imp.Name != nil {
					return fmt.Errorf("testing: aliased import of os forbidden")
				}
				fileImportsOS[f] = true
			case "fmt":
				if imp.Name != nil {
					return fmt.Errorf("testing: aliased import of fmt forbidden")
				}
				fileImportsFmt[f] = true
			case "io":
				if imp.Name != nil {
					return fmt.Errorf("testing: aliased import of io forbidden")
				}
				fileImportsIO[f] = true
			case "flag":
				if imp.Name != nil {
					return fmt.Errorf("testing: aliased import of flag forbidden")
				}
				fileImportsFlag[f] = true
			case "sync":
				if imp.Name != nil {
					return fmt.Errorf("testing: aliased import of sync forbidden")
				}
				fileImportsSync[f] = true
			case "syscall":
				if imp.Name != nil {
					return fmt.Errorf("testing: aliased import of syscall forbidden")
				}
				fileImportsSyscall[f] = true
			}
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.ValueSpec:
						for idx, id := range sp.Names {
							if pkgReserved[id.Name] {
								return fmt.Errorf("testing: package-level declaration shadows %s", id.Name)
							}
							if id.Name != "_" {
								pkgVarCounts[id.Name]++
								if d.Tok == token.VAR {
									recordAllowedFlagIdent(id.Name, id)
									if len(sp.Values) == 0 {
										zeroInitPkgVars[id.Name] = sp
										if tID, ok := unwrapParens(sp.Type).(*ast.Ident); ok && tID.Name == "bool" {
											zeroInitBoolVars[id.Name] = true
										}
									} else if len(sp.Values) == len(sp.Names) {
										initPkgVars[id.Name] = sp.Values[idx]
										initPkgVarFile[id.Name] = f
									}
								}
							}
						}
					case *ast.TypeSpec:
						if sp.Name != nil && pkgReserved[sp.Name.Name] {
							return fmt.Errorf("testing: package-level type shadows %s", sp.Name.Name)
						}
					}
				}
			case *ast.FuncDecl:
				funcFile[d] = f
				if d.Recv == nil && pkgReserved[d.Name.Name] {
					return fmt.Errorf("testing: package-level function shadows %s", d.Name.Name)
				}
				if d.Body == nil {
					if d.Recv != nil || !runtimePullLinknames[d.Name.Name] {
						return fmt.Errorf("testing: unexpected bodyless function %s", d.Name.Name)
					}
				}
				if d.Name.Name == "Context" {
					if verifyTestingContextDecl(d) {
						hasValidContextMethod = true
					} else {
						hasInvalidContextMethod = true
					}
				}
				if d.Recv == nil {
					if d.Name.Name != "init" && d.Name.Name != "_" {
						if _, exists := topFuncs[d.Name.Name]; exists {
							dupTopFuncs[d.Name.Name] = true
						}
						topFuncs[d.Name.Name] = d
					}
				} else if len(d.Recv.List) == 1 {
					if rType := recvTypeName(d.Recv.List[0].Type); rType != "" {
						if typeMethods[rType] == nil {
							typeMethods[rType] = map[string]*ast.FuncDecl{}
						}
						if _, exists := typeMethods[rType][d.Name.Name]; exists {
							dupTypeMethods = true
						}
						typeMethods[rType][d.Name.Name] = d
					}
				}
			}
		}
	}
	if dupTypeMethods {
		return fmt.Errorf("testing: duplicate method declarations")
	}
	for dup := range dupTopFuncs {
		delete(topFuncs, dup)
	}
	for sym := range runtimePullLinknames {
		if fn := topFuncs[sym]; fn == nil || fn.Body != nil {
			return fmt.Errorf("testing: runtime pull linkname %s missing bodyless declaration", sym)
		}
	}
	for sym := range selfPushLinknames {
		if fn := topFuncs[sym]; fn == nil || fn.Body == nil {
			return fmt.Errorf("testing: push linkname %s missing concrete top-level function", sym)
		}
	}

	// Count all occurrences of "Main" across files to verify legacy func Main is unreferenced.
	mainIdentCount := 0
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "Main" {
				mainIdentCount++
			}
			return true
		})
	}

	// Package-wide Exit / flag / raw-syscall audit: prevent exit-0 and flag-mutation bypasses anywhere in testing.
	var mRunExitCalls []*ast.CallExpr
	var osExitSites []testingExitSite
	flagRegCounts := map[string]int{}
	for _, f := range files {
		directCalls := map[*ast.SelectorExpr]*ast.CallExpr{}
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && !call.Ellipsis.IsValid() {
				if sel, ok2 := unwrapParens(call.Fun).(*ast.SelectorExpr); ok2 {
					directCalls[sel] = call
				}
			}
			return true
		})
		var exitErr error
		ast.Inspect(f, func(n ast.Node) bool {
			if exitErr != nil || n == nil {
				return false
			}
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "Set" {
				if innerSel, okS := unwrapParens(sel.X).(*ast.SelectorExpr); okS && innerSel.Sel.Name == "CommandLine" {
					exitErr = fmt.Errorf("testing: forbidden CommandLine.Set reference")
					return false
				}
			}
			pkgID, ok := unwrapParens(sel.X).(*ast.Ident)
			if !ok {
				return true
			}
			switch pkgID.Name {
			case "CommandLine":
				if sel.Sel.Name == "Set" {
					exitErr = fmt.Errorf("testing: forbidden CommandLine.Set reference")
					return false
				}
			case "flag":
				if !fileImportsFlag[f] {
					exitErr = fmt.Errorf("testing: flag selector without unaliased flag import")
					return false
				}
				call := directCalls[sel]
				switch sel.Sel.Name {
				case "Parsed", "Parse", "Usage":
					if call == nil || len(call.Args) != 0 {
						exitErr = fmt.Errorf("testing: flag.%s must be a direct 0-argument call", sel.Sel.Name)
						return false
					}
				case "Bool", "Int", "Int64", "Uint", "Uint64", "String", "Float64", "Duration", "Var":
					if call == nil || len(call.Args) != 3 {
						exitErr = fmt.Errorf("testing: flag.%s must be a direct 3-argument call", sel.Sel.Name)
						return false
					}
					nameIdx := 0
					if sel.Sel.Name == "Var" {
						nameIdx = 1
					}
					nameLit, okL := unwrapParens(call.Args[nameIdx]).(*ast.BasicLit)
					if !okL || nameLit.Kind != token.STRING {
						exitErr = fmt.Errorf("testing: flag.%s requires literal flag name", sel.Sel.Name)
						return false
					}
					parsedName, uErr := strconv.Unquote(nameLit.Value)
					if uErr != nil || parsedName == "" {
						exitErr = fmt.Errorf("testing: invalid flag.%s name literal", sel.Sel.Name)
						return false
					}
					flagRegCounts[parsedName]++
				default:
					exitErr = fmt.Errorf("testing: forbidden flag.%s reference", sel.Sel.Name)
					return false
				}
			case "syscall":
				switch sel.Sel.Name {
				case "Exit", "Syscall", "Syscall6", "RawSyscall6":
					exitErr = fmt.Errorf("testing: forbidden syscall.%s reference", sel.Sel.Name)
					return false
				case "RawSyscall":
					call := directCalls[sel]
					if call == nil || len(call.Args) != 4 || !fileImportsSyscall[f] {
						exitErr = fmt.Errorf("testing: forbidden or non-SYS_WRITE syscall.RawSyscall")
						return false
					}
					sysSel, ok := unwrapParens(call.Args[0]).(*ast.SelectorExpr)
					if !ok || sysSel.Sel.Name != "SYS_WRITE" {
						exitErr = fmt.Errorf("testing: syscall.RawSyscall allowed only for SYS_WRITE")
						return false
					}
					sysPkg, ok := unwrapParens(sysSel.X).(*ast.Ident)
					if !ok || sysPkg.Name != "syscall" {
						exitErr = fmt.Errorf("testing: syscall.RawSyscall requires syscall.SYS_WRITE")
						return false
					}
				}
			case "os":
				if sel.Sel.Name != "Exit" {
					return true
				}
				call := directCalls[sel]
				if call == nil || len(call.Args) != 1 || !fileImportsOS[f] {
					exitErr = fmt.Errorf("testing: os.Exit must be a direct 1-argument call")
					return false
				}
				encFn, encAncestors := findEnclosingFuncAndAncestors(f, call)
				if encFn == nil || funcShadowsAnyIdent(encFn, map[string]bool{"os": true}) {
					exitErr = fmt.Errorf("testing: os.Exit outside verified function declaration")
					return false
				}
				isMRun := encFn.Recv != nil && len(encFn.Recv.List) == 1 && recvTypeName(encFn.Recv.List[0].Type) == "M" && encFn.Name.Name == "Run"
				if !exprHasCallOrFuncLit(call.Args[0]) && isPositiveIntLit(call.Args[0]) {
					if isMRun {
						mRunExitCalls = append(mRunExitCalls, call)
					}
					osExitSites = append(osExitSites, testingExitSite{
						file:      f,
						call:      call,
						encFn:     encFn,
						ancestors: encAncestors,
					})
					return true
				}
				if encFn.Recv == nil && encFn.Name.Name == "Main" && !dupTopFuncs["Main"] && !selfPushLinknames["Main"] && mainIdentCount == 1 && len(encAncestors) == 3 && len(encFn.Body.List) == 1 {
					return true
				}
				exitErr = fmt.Errorf("testing: non-positive or unverified os.Exit in %s", encFn.Name.Name)
				return false
			}
			return true
		})
		if exitErr != nil {
			return exitErr
		}
	}
	if flagRegCounts["test.testlogfile"] != 1 || flagRegCounts["test.list"] > 1 {
		return fmt.Errorf("testing: duplicate or missing test.testlogfile/test.list flag registration")
	}

	// Discover unexported package-level string-pointer flags registered for
	// "test.testlogfile" and "test.list" with empty default "", via either Form A
	// (package-level var initializer) or Form B (once-guarded Init() called by MainStart),
	// and verify neither the pointer nor *pointer is mutated or address-taken elsewhere.
	varWriteCount := map[string]int{}
	flagAddrTaken := map[string]bool{}
	flagDerefMutated := map[string]bool{}
	recordLHSWrite := func(lhs ast.Expr) {
		switch x := unwrapParens(lhs).(type) {
		case *ast.Ident:
			if x.Name != "" && x.Name != "_" {
				varWriteCount[x.Name]++
			}
		case *ast.StarExpr:
			if id, ok := unwrapParens(x.X).(*ast.Ident); ok && id.Name != "" && id.Name != "_" {
				flagDerefMutated[id.Name] = true
			}
		}
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					recordLHSWrite(lhs)
				}
			case *ast.RangeStmt:
				if node.Key != nil {
					recordLHSWrite(node.Key)
				}
				if node.Value != nil {
					recordLHSWrite(node.Value)
				}
			case *ast.IncDecStmt:
				recordLHSWrite(node.X)
			case *ast.UnaryExpr:
				if node.Op == token.AND {
					switch x := unwrapParens(node.X).(type) {
					case *ast.Ident:
						flagAddrTaken[x.Name] = true
					case *ast.StarExpr:
						if id, ok := unwrapParens(x.X).(*ast.Ident); ok {
							flagAddrTaken[id.Name] = true
						}
					}
				}
			}
			return true
		})
	}

	testlogfileFlagVars := map[string]bool{}
	listFlagVars := map[string]bool{}
	emptyDefaultStringFlags := map[string]bool{}
	flagInitFunc := map[string]*ast.FuncDecl{}

	// Form A: var fv = flag.String("...", "", ...)
	for fv, initExpr := range initPkgVars {
		f := initPkgVarFile[fv]
		if ast.IsExported(fv) || pkgVarCounts[fv] != 1 || varWriteCount[fv] != 0 || flagAddrTaken[fv] || flagDerefMutated[fv] || !fileImportsFlag[f] {
			continue
		}
		call, ok := unwrapParens(initExpr).(*ast.CallExpr)
		if !ok {
			continue
		}
		if flagName, ok := flagStringEmptyDefaultName(call); ok {
			switch flagName {
			case "test.testlogfile":
				testlogfileFlagVars[fv] = true
			case "test.list":
				listFlagVars[fv] = true
			default:
				emptyDefaultStringFlags[fv] = true
			}
		}
	}

	// Form B: zero-init var fv assigned once at top level of a 0-arg/0-result Init-style function.
	for name, fn := range topFuncs {
		f := funcFile[fn]
		if fn == nil || fn.Body == nil || !fileImportsFlag[f] || name == "MainStart" || name == "Main" {
			continue
		}
		if (fn.Type.Params != nil && fn.Type.Params.NumFields() != 0) || (fn.Type.Results != nil && fn.Type.Results.NumFields() != 0) {
			continue
		}
		if funcShadowsAnyIdent(fn, pkgReserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
			continue
		}
		startCheckIdx := 0
		if len(fn.Body.List) >= 2 {
			if ifs, ok := fn.Body.List[0].(*ast.IfStmt); ok && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
				if ret, ok2 := ifs.Body.List[0].(*ast.ReturnStmt); ok2 && len(ret.Results) == 0 {
					if onceID, ok3 := unwrapParens(ifs.Cond).(*ast.Ident); ok3 && !ast.IsExported(onceID.Name) && zeroInitBoolVars[onceID.Name] && pkgVarCounts[onceID.Name] == 1 && varWriteCount[onceID.Name] == 1 && !flagAddrTaken[onceID.Name] && !funcShadowsAnyIdent(fn, map[string]bool{onceID.Name: true}) {
						if as1, ok4 := fn.Body.List[1].(*ast.AssignStmt); ok4 && as1.Tok == token.ASSIGN && len(as1.Lhs) == 1 && len(as1.Rhs) == 1 {
							_, okL := isIdentNamed(as1.Lhs[0], onceID.Name)
							_, okR := isIdentNamed(as1.Rhs[0], "true")
							if okL && okR {
								startCheckIdx = 2
							}
						}
					}
				}
			}
		}
		seenFlags := map[string]bool{}
		for idx := startCheckIdx; idx < len(fn.Body.List); idx++ {
			stmt := fn.Body.List[idx]
			if as, ok := stmt.(*ast.AssignStmt); ok && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
				if lhsID, ok2 := unwrapParens(as.Lhs[0]).(*ast.Ident); ok2 && !ast.IsExported(lhsID.Name) && zeroInitPkgVars[lhsID.Name] != nil && pkgVarCounts[lhsID.Name] == 1 && varWriteCount[lhsID.Name] == 1 && !flagAddrTaken[lhsID.Name] && !flagDerefMutated[lhsID.Name] && !funcShadowsAnyIdent(fn, map[string]bool{lhsID.Name: true}) {
					if call, ok3 := unwrapParens(as.Rhs[0]).(*ast.CallExpr); ok3 {
						if flagName, okName := flagStringEmptyDefaultName(call); okName && !seenFlags[flagName] {
							recordAllowedFlagIdent(lhsID.Name, lhsID)
							switch flagName {
							case "test.testlogfile":
								testlogfileFlagVars[lhsID.Name] = true
								flagInitFunc[lhsID.Name] = fn
							case "test.list":
								listFlagVars[lhsID.Name] = true
								flagInitFunc[lhsID.Name] = fn
							default:
								emptyDefaultStringFlags[lhsID.Name] = true
								flagInitFunc[lhsID.Name] = fn
							}
						}
					}
				}
			}
			if !isBenignFlagInitRegStmt(stmt, seenFlags) {
				break
			}
		}
	}
	if len(testlogfileFlagVars) == 0 {
		return fmt.Errorf("testing: missing verified test.testlogfile flag registration")
	}

	stopLogAssign := func(stmt ast.Stmt) (string, *ast.CallExpr) {
		as, ok := stmt.(*ast.AssignStmt)
		if !ok || (as.Tok != token.DEFINE && as.Tok != token.ASSIGN) || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return "", nil
		}
		id, ok := unwrapParens(as.Lhs[0]).(*ast.Ident)
		if !ok || id.Name == "" || id.Name == "_" || id.Name == "nil" {
			return "", nil
		}
		call, ok := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) != 0 || !isMethodCallNamed(call, "StopTestLog") {
			return "", nil
		}
		return id.Name, call
	}

	validateCallAncestors := func(fn *ast.FuncDecl, ancestors []ast.Node, stmtIdx int) (flagGuard string, topStmt ast.Stmt, ok bool) {
		if fn == nil || stmtIdx < 1 || stmtIdx >= len(ancestors) {
			return "", nil, false
		}
		ts, isStmt := ancestors[1].(ast.Stmt)
		if !isStmt {
			return "", nil, false
		}
		for i := 0; i < stmtIdx; i++ {
			switch node := ancestors[i].(type) {
			case *ast.BlockStmt:
				childStmt, isStmt := ancestors[i+1].(ast.Stmt)
				if !isStmt {
					return "", nil, false
				}
				foundIdx := -1
				for j, bs := range node.List {
					if bs == childStmt {
						foundIdx = j
						break
					}
				}
				if foundIdx < 0 {
					return "", nil, false
				}
				for _, prior := range node.List[:foundIdx] {
					if stmtAlwaysTerminates(prior) {
						return "", nil, false
					}
				}
			case *ast.IfStmt:
				if node.Init != nil || node.Else != nil || ancestors[i+1] != node.Body || flagGuard != "" {
					return "", nil, false
				}
				fg, ok := derefFlagNonEmptyCondIdent(node.Cond)
				if !ok || !testlogfileFlagVars[fg] || funcShadowsAnyIdent(fn, map[string]bool{fg: true}) {
					return "", nil, false
				}
				flagGuard = fg
			default:
				return "", nil, false
			}
		}
		if flagGuard == "" {
			return "", nil, false
		}
		return flagGuard, ts, true
	}

	blockDeclaresVarBefore := func(blk *ast.BlockStmt, limit int, varName string) bool {
		for _, raw := range blk.List[:limit] {
			switch s := raw.(type) {
			case *ast.DeclStmt:
				if gd, ok := s.Decl.(*ast.GenDecl); ok && gd.Tok == token.VAR {
					for _, spec := range gd.Specs {
						if vs, ok2 := spec.(*ast.ValueSpec); ok2 {
							for _, id := range vs.Names {
								if id.Name == varName {
									return true
								}
							}
						}
					}
				}
			case *ast.AssignStmt:
				if s.Tok == token.DEFINE {
					for _, lhs := range s.Lhs {
						if id, ok := unwrapParens(lhs).(*ast.Ident); ok && id.Name == varName {
							return true
						}
					}
				}
			}
		}
		return false
	}

	var hasInvalidStartCall bool
	var verifiedStarts []verifiedStartInfo

	for _, f := range files {
		var startCalls []*ast.CallExpr
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && isMethodCallNamed(call, "StartTestLog") {
				startCalls = append(startCalls, call)
			}
			return true
		})
		for _, call := range startCalls {
			if len(call.Args) != 1 || call.Ellipsis.IsValid() || !fileImportsOS[f] {
				hasInvalidStartCall = true
				continue
			}
			fileVar, wrapName, ok := verifyTestingStartLogArg(call.Args[0], files, topFuncs, typeMethods)
			if !ok || fileVar == "" {
				hasInvalidStartCall = true
				continue
			}
			fn, ancestors := findEnclosingFuncAndAncestors(f, call)
			if fn == nil || len(ancestors) < 2 {
				hasInvalidStartCall = true
				continue
			}
			reserved := map[string]bool{}
			for k := range pkgReserved {
				reserved[k] = true
			}
			if wrapName != "" {
				reserved[wrapName] = true
			}
			if funcShadowsAnyIdent(fn, reserved) || funcDeclaresParamOrResult(fn, fileVar) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
				hasInvalidStartCall = true
				continue
			}
			es, ok := ancestors[len(ancestors)-2].(*ast.ExprStmt)
			if !ok || unwrapParens(es.X) != call {
				hasInvalidStartCall = true
				continue
			}
			flagGuard, topStmt, ok := validateCallAncestors(fn, ancestors, len(ancestors)-2)
			if !ok {
				hasInvalidStartCall = true
				continue
			}
			recvKey := canonicalDepsReceiverKey(fn, call)
			if recvKey == "" {
				hasInvalidStartCall = true
				continue
			}
			var declBlock *ast.BlockStmt
			declTargetIdx := -1
			for i := len(ancestors) - 3; i >= 0; i-- {
				blk, isBlk := ancestors[i].(*ast.BlockStmt)
				if !isBlk {
					continue
				}
				childStmt := ancestors[i+1].(ast.Stmt)
				idx := slices.Index(blk.List, childStmt)
				if idx < 0 {
					break
				}
				if blockDeclaresVarBefore(blk, idx, fileVar) {
					declBlock = blk
					declTargetIdx = idx
					break
				}
			}
			if declBlock == nil || declTargetIdx <= 0 || declBlock.List[declTargetIdx] != es {
				hasInvalidStartCall = true
				continue
			}
			openExits := map[*ast.CallExpr]bool{}
			if !verifyLogFileOpenPrefix(declBlock.List[:declTargetIdx], fileVar, flagGuard, fileImportsOS[f], fileImportsFmt[f], openExits) {
				hasInvalidStartCall = true
				continue
			}
			verifiedStarts = append(verifiedStarts, verifiedStartInfo{
				file:          f,
				fn:            fn,
				topStmt:       topStmt,
				declBlock:     declBlock,
				declTargetIdx: declTargetIdx,
				fileVar:       fileVar,
				recvKey:       recvKey,
				flagGuard:     flagGuard,
				openExits:     openExits,
			})
		}
	}

	verifiedStopCalls := map[*ast.CallExpr]verifiedStopInfo{}
	recordCandidateStop := func(f *ast.File, parentBlk *ast.BlockStmt, stmtPos, afterStopPos int, errVar string, call *ast.CallExpr, handler *ast.IfStmt) {
		if !isFailureForcingErrHandler(handler, errVar, fileImportsOS[f], fileImportsFmt[f]) {
			return
		}
		fn, ancestors := findEnclosingFuncAndAncestors(f, parentBlk.List[stmtPos])
		if fn == nil || len(ancestors) < 2 {
			return
		}
		if funcShadowsAnyIdent(fn, pkgReserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
			return
		}
		flagGuard, topStmt, ok := validateCallAncestors(fn, ancestors, len(ancestors)-1)
		if !ok {
			return
		}
		recvKey := canonicalDepsReceiverKey(fn, call)
		if recvKey == "" {
			return
		}
		matchedStart := false
		for _, st := range verifiedStarts {
			if st.recvKey == recvKey && flagGuard == st.flagGuard {
				matchedStart = true
				break
			}
		}
		if !matchedStart {
			return
		}
		verifiedStopCalls[call] = verifiedStopInfo{
			file:         f,
			fn:           fn,
			topStmt:      topStmt,
			parentBlk:    parentBlk,
			stmtPos:      stmtPos,
			afterStopPos: afterStopPos,
			recvKey:      recvKey,
			flagGuard:    flagGuard,
			stopExit:     errHandlerTerminalCall(handler),
		}
	}

	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			blk, ok := n.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for i, s := range blk.List {
				if ifs, isIf := s.(*ast.IfStmt); isIf {
					if errVar, call := stopLogAssign(ifs.Init); call != nil {
						recordCandidateStop(f, blk, i, i+1, errVar, call, ifs)
					}
				}
				if i+1 < len(blk.List) {
					if errVar, call := stopLogAssign(s); call != nil {
						if ifs, isIf := blk.List[i+1].(*ast.IfStmt); isIf && ifs.Init == nil {
							recordCandidateStop(f, blk, i, i+2, errVar, call, ifs)
						}
					}
				}
			}
			return true
		})
	}

	var hasCheckedStopCall, hasDiscardedStopCall bool
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if isMethodCallNamed(call, "StopTestLog") {
				if _, ok := verifiedStopCalls[call]; ok {
					hasCheckedStopCall = true
				} else {
					hasDiscardedStopCall = true
				}
			}
			return true
		})
	}
	if len(verifiedStarts) != 1 || hasInvalidStartCall || len(verifiedStopCalls) != 1 || !hasCheckedStopCall || hasDiscardedStopCall {
		return fmt.Errorf("testing: missing, duplicate, unchecked, or error-dropping StartTestLog/StopTestLog calls")
	}

	st := verifiedStarts[0]
	var sp verifiedStopInfo
	for _, info := range verifiedStopCalls {
		sp = info
	}
	if st.recvKey != sp.recvKey || st.flagGuard == "" || st.flagGuard != sp.flagGuard {
		return fmt.Errorf("testing: StartTestLog and StopTestLog receiver or flag guard mismatch")
	}

	stmtMutatesOrClosesVar := func(stmt ast.Stmt, varName string, allowClose bool) bool {
		bad := false
		ast.Inspect(stmt, func(n ast.Node) bool {
			if bad || n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					if id, ok := unwrapParens(lhs).(*ast.Ident); ok && id.Name == varName {
						bad = true
						return false
					}
				}
			case *ast.RangeStmt:
				for _, lhs := range []ast.Expr{node.Key, node.Value} {
					if lhs != nil {
						if id, ok := unwrapParens(lhs).(*ast.Ident); ok && id.Name == varName {
							bad = true
							return false
						}
					}
				}
			case *ast.IncDecStmt:
				if id, ok := unwrapParens(node.X).(*ast.Ident); ok && id.Name == varName {
					bad = true
					return false
				}
			case *ast.UnaryExpr:
				if node.Op == token.AND {
					if id, ok := unwrapParens(node.X).(*ast.Ident); ok && id.Name == varName {
						bad = true
						return false
					}
				}
			case *ast.CallExpr:
				if !allowClose {
					if sel, ok := unwrapParens(node.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Close" {
						if id, ok2 := unwrapParens(sel.X).(*ast.Ident); ok2 && id.Name == varName {
							bad = true
							return false
						}
					}
				}
			}
			return true
		})
		return bad
	}

	closeExits := map[*ast.CallExpr]bool{}
	if st.fn == sp.fn && st.declBlock == sp.parentBlk {
		if sp.stmtPos <= st.declTargetIdx {
			return fmt.Errorf("testing: StopTestLog must follow StartTestLog")
		}
		for _, midStmt := range st.declBlock.List[st.declTargetIdx+1 : sp.stmtPos] {
			if stmtAlwaysTerminates(midStmt) || stmtMutatesOrClosesVar(midStmt, st.fileVar, false) {
				return fmt.Errorf("testing: unsafe statement between StartTestLog and StopTestLog")
			}
		}
		for _, afterStmt := range sp.parentBlk.List[sp.afterStopPos:] {
			if stmtMutatesOrClosesVar(afterStmt, st.fileVar, true) {
				return fmt.Errorf("testing: unsafe mutation of testlog file after StopTestLog")
			}
		}
		_, closeExit, ok := blockHasFailureForcingClose(sp.parentBlk.List[sp.afterStopPos:], st.fileVar, fileImportsOS[sp.file], fileImportsFmt[sp.file])
		if !ok {
			return fmt.Errorf("testing: missing failure-forcing Close on testlog file after StopTestLog")
		}
		if closeExit != nil {
			closeExits[closeExit] = true
		}
		for _, exitCall := range mRunExitCalls {
			if !st.openExits[exitCall] && exitCall != sp.stopExit && !closeExits[exitCall] {
				return fmt.Errorf("testing: non-positive or unverified os.Exit in Run")
			}
		}
	} else {
		if len(mRunExitCalls) > 0 {
			return fmt.Errorf("testing: non-positive or unverified os.Exit in Run")
		}
		logFileAliases := map[string]*ast.AssignStmt{}
		for _, tailStmt := range st.declBlock.List[st.declTargetIdx+1:] {
			if stmtAlwaysTerminates(tailStmt) {
				return fmt.Errorf("testing: terminating statement after StartTestLog in start block")
			}
			if as, isAs := tailStmt.(*ast.AssignStmt); isAs && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
				if rhsID, ok := unwrapParens(as.Rhs[0]).(*ast.Ident); ok && rhsID.Name == st.fileVar {
					if lhsID, ok2 := unwrapParens(as.Lhs[0]).(*ast.Ident); ok2 && lhsID.Name != "" && lhsID.Name != "_" && lhsID.Name != st.fileVar {
						if _, dup := logFileAliases[lhsID.Name]; dup {
							return fmt.Errorf("testing: duplicate assignment to testlog file alias %s", lhsID.Name)
						}
						logFileAliases[lhsID.Name] = as
						continue
					}
				}
			}
			if stmtMutatesOrClosesVar(tailStmt, st.fileVar, false) {
				return fmt.Errorf("testing: unsafe mutation or premature Close on testlog file")
			}
		}
		if len(logFileAliases) == 0 {
			return fmt.Errorf("testing: split StartTestLog/StopTestLog missing saved testlog file variable")
		}
		allowedAliasIdents := map[*ast.Ident]bool{}
		for alias, bindAssign := range logFileAliases {
			if ast.IsExported(alias) || zeroInitPkgVars[alias] == nil || pkgVarCounts[alias] != 1 {
				return fmt.Errorf("testing: testlog file alias %s must be a unique unexported zero-initialized package var", alias)
			}
			if funcShadowsAnyIdent(st.fn, map[string]bool{alias: true}) || funcShadowsAnyIdent(sp.fn, map[string]bool{alias: true}) {
				return fmt.Errorf("testing: testlog file alias %s shadowed in lifecycle function", alias)
			}
			if lhsID, ok := unwrapParens(bindAssign.Lhs[0]).(*ast.Ident); ok {
				allowedAliasIdents[lhsID] = true
			}
			for _, f := range files {
				for _, decl := range f.Decls {
					if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.VAR {
						for _, spec := range gd.Specs {
							if vs, ok2 := spec.(*ast.ValueSpec); ok2 && len(vs.Values) == 0 {
								for _, id := range vs.Names {
									if id.Name == alias {
										allowedAliasIdents[id] = true
									}
								}
							}
						}
					}
				}
			}
			closeRecvID, closeExit, ok := blockHasFailureForcingClose(sp.parentBlk.List[sp.afterStopPos:], alias, fileImportsOS[sp.file], fileImportsFmt[sp.file])
			if !ok || closeRecvID == nil {
				return fmt.Errorf("testing: missing failure-forcing %s.Close() after StopTestLog", alias)
			}
			if closeExit != nil {
				closeExits[closeExit] = true
			}
			allowedAliasIdents[closeRecvID] = true
		}
		aliasMisused := false
		for _, f := range files {
			var walkAlias func(n ast.Node)
			walkAlias = func(n ast.Node) {
				if aliasMisused || n == nil {
					return
				}
				switch node := n.(type) {
				case *ast.SelectorExpr:
					walkAlias(node.X)
				case *ast.Ident:
					if _, isAlias := logFileAliases[node.Name]; isAlias && !allowedAliasIdents[node] {
						aliasMisused = true
					}
				default:
					ast.Inspect(node, func(ch ast.Node) bool {
						if ch == node {
							return true
						}
						walkAlias(ch)
						return false
					})
				}
			}
			walkAlias(f)
			if aliasMisused {
				return fmt.Errorf("testing: unsafe mutation or unchecked Close on saved testlog file")
			}
		}
	}

	if hasInvalidContextMethod {
		return fmt.Errorf("testing: (*common).Context has unexpected shape")
	}
	if !hasValidContextMethod {
		return fmt.Errorf("testing: missing (*common).Context")
	}
	if !verifyTestingMRunTestlogWiring(files, funcFile, topFuncs, typeMethods, st, sp, flagInitFunc, flagAllowedDeclIdents, listFlagVars, emptyDefaultStringFlags, osExitSites, closeExits, fileImportsOS, fileImportsFmt, fileImportsIO, fileImportsFlag, fileImportsSync, pkgReserved) {
		return fmt.Errorf("testing: (*M).Run does not wire MainStart deps through verified StartTestLog/StopTestLog")
	}
	return nil
}

func verifyTestingMRunTestlogWiring(
	files []*ast.File,
	funcFile map[*ast.FuncDecl]*ast.File,
	topFuncs map[string]*ast.FuncDecl,
	typeMethods map[string]map[string]*ast.FuncDecl,
	st verifiedStartInfo,
	sp verifiedStopInfo,
	flagInitFunc map[string]*ast.FuncDecl,
	flagAllowedDeclIdents map[string]map[*ast.Ident]bool,
	listFlagVars map[string]bool,
	emptyDefaultStringFlags map[string]bool,
	osExitSites []testingExitSite,
	closeExits map[*ast.CallExpr]bool,
	fileImportsOS map[*ast.File]bool,
	fileImportsFmt map[*ast.File]bool,
	fileImportsIO map[*ast.File]bool,
	fileImportsFlag map[*ast.File]bool,
	fileImportsSync map[*ast.File]bool,
	pkgReserved map[string]bool,
) bool {
	mainStart := topFuncs["MainStart"]
	mMethods := typeMethods["M"]
	runFn := mMethods["Run"]
	if mainStart == nil || mainStart.Body == nil || mainStart.Type == nil || mainStart.Type.Params == nil || mainStart.Type.Results == nil || mainStart.Type.Results.NumFields() != 1 || runFn == nil || runFn.Body == nil || runFn.Type == nil {
		return false
	}
	if (runFn.Type.Params != nil && runFn.Type.Params.NumFields() != 0) || runFn.Type.Results == nil || runFn.Type.Results.NumFields() != 1 {
		return false
	}
	if funcShadowsAnyIdent(mainStart, pkgReserved) || bodyHasControlFlowOrRecoverBypass(mainStart.Body) || !blockAlwaysReturns(mainStart.Body.List) {
		return false
	}
	if funcShadowsAnyIdent(runFn, pkgReserved) || bodyHasControlFlowOrRecoverBypass(runFn.Body) {
		return false
	}
	runRecv := recvVarName(runFn)
	if runRecv == "" {
		return false
	}

	// Verify unique type M struct declaration, collect its fields, and track all allowed M idents.
	allowedMIdents := map[*ast.Ident]bool{}
	var mStruct *ast.StructType
	var mStructFile *ast.File
	mTypeSpecs := 0
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || ts.Name == nil || ts.Name.Name != "M" {
					continue
				}
				mTypeSpecs++
				if stType, ok := ts.Type.(*ast.StructType); ok && !ts.Assign.IsValid() {
					mStruct = stType
					mStructFile = f
					allowedMIdents[ts.Name] = true
				}
			}
		}
	}
	if mTypeSpecs != 1 || mStruct == nil || mStruct.Fields == nil {
		return false
	}
	if len(mainStart.Type.Results.List) != 1 || len(mainStart.Type.Results.List[0].Names) != 0 {
		return false
	}
	msResStar, okMSStar := unwrapParens(mainStart.Type.Results.List[0].Type).(*ast.StarExpr)
	if !okMSStar {
		return false
	}
	msResID, okMSID := unwrapParens(msResStar.X).(*ast.Ident)
	if !okMSID || msResID.Name != "M" {
		return false
	}
	allowedMIdents[msResID] = true

	mFields := map[string]ast.Expr{}
	mFieldIdents := map[string]*ast.Ident{}
	for _, fld := range mStruct.Fields.List {
		if len(fld.Names) == 0 {
			return false
		}
		for _, id := range fld.Names {
			if _, dup := mFields[id.Name]; dup {
				return false
			}
			mFields[id.Name] = fld.Type
			mFieldIdents[id.Name] = id
		}
	}

	pNames := paramNamesFlat(mainStart.Type.Params)
	if len(pNames) == 0 || pNames[0] == "" || pNames[0] == "_" {
		return false
	}
	depsParam := pNames[0]
	if bodyMutatesOrTakesAddrOfAny(mainStart.Body, map[string]bool{depsParam: true}) || bodyDeclaresAnyIdent(mainStart.Body, map[string]bool{depsParam: true}) {
		return false
	}
	var depsField string
	mainStartValid := true
	sawMainStartReturn := false
	ast.Inspect(mainStart.Body, func(n ast.Node) bool {
		if !mainStartValid || n == nil {
			return false
		}
		if _, isFL := n.(*ast.FuncLit); isFL {
			mainStartValid = false
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		sawMainStartReturn = true
		if len(ret.Results) != 1 {
			mainStartValid = false
			return false
		}
		u, ok := unwrapParens(ret.Results[0]).(*ast.UnaryExpr)
		if !ok || u.Op != token.AND {
			mainStartValid = false
			return false
		}
		lit, tName := compositeWriterLit(ret.Results[0])
		if lit == nil || tName != "M" {
			mainStartValid = false
			return false
		}
		litTypeID, okLT := unwrapParens(lit.Type).(*ast.Ident)
		if !okLT || litTypeID.Name != "M" {
			mainStartValid = false
			return false
		}
		allowedMIdents[litTypeID] = true
		var retDepsField string
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				mainStartValid = false
				return false
			}
			kID, ok1 := unwrapParens(kv.Key).(*ast.Ident)
			if !ok1 || kID.Name == "" {
				mainStartValid = false
				return false
			}
			if vID, ok2 := unwrapParens(kv.Value).(*ast.Ident); ok2 && vID.Name == depsParam {
				if retDepsField != "" {
					mainStartValid = false
					return false
				}
				retDepsField = kID.Name
			}
		}
		if retDepsField == "" || (depsField != "" && depsField != retDepsField) {
			mainStartValid = false
			return false
		}
		depsField = retDepsField
		return false
	})
	if !mainStartValid || !sawMainStartReturn || depsField == "" || ast.IsExported(depsField) || mFields[depsField] == nil {
		return false
	}

	// Verify every method on M has a pointer receiver *M whose receiver variable is only field/method-selected,
	// never mutated, address-taken, or used to invoke (*M).Run recursively, and verify no other M ident exists in testing.
	for _, mFn := range mMethods {
		if mFn == nil || mFn.Body == nil || mFn.Recv == nil || len(mFn.Recv.List) != 1 || len(mFn.Recv.List[0].Names) > 1 {
			return false
		}
		rStar, okRS := unwrapParens(mFn.Recv.List[0].Type).(*ast.StarExpr)
		if !okRS {
			return false
		}
		rID, okRID := unwrapParens(rStar.X).(*ast.Ident)
		if !okRID || rID.Name != "M" {
			return false
		}
		allowedMIdents[rID] = true
		if rv := recvVarName(mFn); rv != "" {
			if bodyMutatesOrTakesAddrOfAny(mFn.Body, map[string]bool{rv: true}) || !blockOnlySelectsOnIdent(mFn.Body, rv) {
				return false
			}
			callsSelfRun := false
			ast.Inspect(mFn.Body, func(n ast.Node) bool {
				if callsSelfRun || n == nil {
					return false
				}
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Run" {
					if xID, okX := unwrapParens(sel.X).(*ast.Ident); okX && xID.Name == rv {
						callsSelfRun = true
						return false
					}
				}
				return true
			})
			if callsSelfRun {
				return false
			}
		}
	}
	for _, f := range files {
		unapprovedM := false
		var walkM func(n ast.Node)
		walkM = func(n ast.Node) {
			if unapprovedM || n == nil {
				return
			}
			switch node := n.(type) {
			case *ast.SelectorExpr:
				walkM(node.X)
			case *ast.Ident:
				if node.Name == "M" && !allowedMIdents[node] {
					unapprovedM = true
				}
			default:
				ast.Inspect(node, func(ch ast.Node) bool {
					if ch == node {
						return true
					}
					walkM(ch)
					return false
				})
			}
		}
		walkM(f)
		if unapprovedM {
			return false
		}
	}

	// Ensure M.<depsField> is never reassigned, incremented, or address-taken anywhere in testing.
	depsMutated := false
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if depsMutated || n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					if sel, ok := unwrapParens(lhs).(*ast.SelectorExpr); ok && sel.Sel.Name == depsField {
						depsMutated = true
						return false
					}
				}
			case *ast.RangeStmt:
				for _, lhs := range []ast.Expr{node.Key, node.Value} {
					if lhs != nil {
						if sel, ok := unwrapParens(lhs).(*ast.SelectorExpr); ok && sel.Sel.Name == depsField {
							depsMutated = true
							return false
						}
					}
				}
			case *ast.IncDecStmt:
				if sel, ok := unwrapParens(node.X).(*ast.SelectorExpr); ok && sel.Sel.Name == depsField {
					depsMutated = true
					return false
				}
			case *ast.UnaryExpr:
				if node.Op == token.AND {
					if sel, ok := unwrapParens(node.X).(*ast.SelectorExpr); ok && sel.Sel.Name == depsField {
						depsMutated = true
						return false
					}
				}
			}
			return true
		})
		if depsMutated {
			return false
		}
	}
	wantRecvKey := "<M>." + depsField
	if st.recvKey != wantRecvKey || sp.recvKey != wantRecvKey {
		return false
	}

	// Helper verifying that any flag pointer var used by the lifecycle appears ONLY at its
	// allowed declaration/Init sites or as the direct operand of a *<fv> dereference.
	verifyFlagPtrIdentOnlyDereferenced := func(fv string) bool {
		allowed := flagAllowedDeclIdents[fv]
		if fv == "" || len(allowed) == 0 {
			return false
		}
		ok := true
		for _, f := range files {
			var stack []ast.Node
			var walk func(n ast.Node)
			walk = func(n ast.Node) {
				if !ok || n == nil {
					return
				}
				switch node := n.(type) {
				case *ast.SelectorExpr:
					stack = append(stack, node)
					walk(node.X)
					stack = stack[:len(stack)-1]
					return
				case *ast.Ident:
					if node.Name == fv && !allowed[node] {
						starOK := false
						for idx := len(stack) - 1; idx >= 0; idx-- {
							if _, isParen := stack[idx].(*ast.ParenExpr); isParen {
								continue
							}
							if star, isStar := stack[idx].(*ast.StarExpr); isStar && unwrapParens(star.X) == node {
								starOK = true
							}
							break
						}
						if !starOK {
							ok = false
						}
					}
					return
				}
				stack = append(stack, n)
				ast.Inspect(n, func(ch ast.Node) bool {
					if ch == n {
						return true
					}
					walk(ch)
					return false
				})
				stack = stack[:len(stack)-1]
			}
			walk(f)
			if !ok {
				return false
			}
		}
		return true
	}

	// Helper verifying that any Form B flag var used by the lifecycle has its Init-style
	// function called unconditionally at top level of MainStart before return &M{...}.
	verifyFlagInitCalledInMainStart := func(fv string) bool {
		initFn := flagInitFunc[fv]
		if initFn == nil {
			return true
		}
		if funcShadowsAnyIdent(mainStart, map[string]bool{initFn.Name.Name: true}) {
			return false
		}
		for _, stmt := range mainStart.Body.List {
			if stmtAlwaysTerminates(stmt) {
				return false
			}
			switch s := stmt.(type) {
			case *ast.EmptyStmt, *ast.DeclStmt, *ast.AssignStmt:
			case *ast.ExprStmt:
				if call, ok := unwrapParens(s.X).(*ast.CallExpr); ok && !call.Ellipsis.IsValid() && len(call.Args) == 0 {
					if id, ok2 := unwrapParens(call.Fun).(*ast.Ident); ok2 && id.Name == initFn.Name.Name {
						return true
					}
				}
			default:
				return false
			}
		}
		return false
	}
	if !verifyFlagInitCalledInMainStart(st.flagGuard) || !verifyFlagPtrIdentOnlyDereferenced(st.flagGuard) {
		return false
	}

	// Check optional named-result exitCode defer at runFn.Body.List[0]:
	// defer func() { <code> = m.<exitCodeField> }()
	var exitCodeField string
	var exitCodeDefer *ast.DeferStmt
	if len(runFn.Type.Results.List) == 1 && len(runFn.Type.Results.List[0].Names) == 1 && len(runFn.Body.List) > 0 {
		codeName := runFn.Type.Results.List[0].Names[0].Name
		if ds, ok := runFn.Body.List[0].(*ast.DeferStmt); ok && codeName != "" && codeName != "_" {
			if fl, ok2 := unwrapParens(ds.Call.Fun).(*ast.FuncLit); ok2 && !ds.Call.Ellipsis.IsValid() && len(ds.Call.Args) == 0 && (fl.Type.Params == nil || fl.Type.Params.NumFields() == 0) && (fl.Type.Results == nil || fl.Type.Results.NumFields() == 0) && fl.Body != nil && len(fl.Body.List) == 1 {
				if as, ok3 := fl.Body.List[0].(*ast.AssignStmt); ok3 && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
					_, okL := isIdentNamed(as.Lhs[0], codeName)
					if sel, okR := unwrapParens(as.Rhs[0]).(*ast.SelectorExpr); okL && okR {
						if rID, okRecv := unwrapParens(sel.X).(*ast.Ident); okRecv && rID.Name == runRecv && sel.Sel.Name != "" && sel.Sel.Name != depsField && !ast.IsExported(sel.Sel.Name) {
							if fType, okFld := unwrapParens(mFields[sel.Sel.Name]).(*ast.Ident); okFld && fType.Name == "int" {
								exitCodeField = sel.Sel.Name
								exitCodeDefer = ds
							}
						}
					}
				}
			}
		}
	}
	if exitCodeField != "" {
		// Ensure exitCodeField is never written or address-taken outside runFn, and never address-taken inside runFn.
		badExitCode := false
		for _, f := range files {
			for _, decl := range f.Decls {
				ast.Inspect(decl, func(n ast.Node) bool {
					if badExitCode || n == nil {
						return false
					}
					switch node := n.(type) {
					case *ast.UnaryExpr:
						if node.Op == token.AND {
							if sel, ok := unwrapParens(node.X).(*ast.SelectorExpr); ok && sel.Sel.Name == exitCodeField {
								badExitCode = true
								return false
							}
						}
					case *ast.FuncLit:
						if decl == runFn {
							ast.Inspect(node.Body, func(fnN ast.Node) bool {
								if badExitCode || fnN == nil {
									return false
								}
								switch inner := fnN.(type) {
								case *ast.AssignStmt:
									for _, lhs := range inner.Lhs {
										if sel, ok := unwrapParens(lhs).(*ast.SelectorExpr); ok && sel.Sel.Name == exitCodeField {
											badExitCode = true
											return false
										}
									}
								case *ast.RangeStmt:
									for _, lhs := range []ast.Expr{inner.Key, inner.Value} {
										if lhs != nil {
											if sel, ok := unwrapParens(lhs).(*ast.SelectorExpr); ok && sel.Sel.Name == exitCodeField {
												badExitCode = true
												return false
											}
										}
									}
								}
								return true
							})
						}
					case *ast.AssignStmt:
						if decl != runFn {
							for _, lhs := range node.Lhs {
								if sel, ok := unwrapParens(lhs).(*ast.SelectorExpr); ok && sel.Sel.Name == exitCodeField {
									badExitCode = true
									return false
								}
							}
						}
					case *ast.RangeStmt:
						for _, lhs := range []ast.Expr{node.Key, node.Value} {
							if lhs != nil {
								if sel, ok := unwrapParens(lhs).(*ast.SelectorExpr); ok && sel.Sel.Name == exitCodeField {
									badExitCode = true
									return false
								}
							}
						}
					case *ast.IncDecStmt:
						if sel, ok := unwrapParens(node.X).(*ast.SelectorExpr); ok && sel.Sel.Name == exitCodeField {
							badExitCode = true
							return false
						}
					case *ast.KeyValueExpr:
						if kID, ok := unwrapParens(node.Key).(*ast.Ident); ok && kID.Name == exitCodeField {
							badExitCode = true
							return false
						}
					}
					return true
				})
			}
		}
		if badExitCode {
			return false
		}
	}

	// Build function/method graph over testing declarations:
	// - runnerDecl: seeded by .F / .Fn callback selectors and canonical runner names, closed backwards over callers.
	// - forward closures for os.Exit reachability auditing across per-case runners, core test/bench/fuzz runners,
	//   example runners, and active testlog lifecycle helpers.
	allDecls := []*ast.FuncDecl{}
	declByName := map[string][]*ast.FuncDecl{}
	for _, f := range files {
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				allDecls = append(allDecls, fn)
				declByName[fn.Name.Name] = append(declByName[fn.Name.Name], fn)
			}
		}
	}
	collectDirectCallees := func(nodes []ast.Node, excludeSels map[*ast.SelectorExpr]bool) []*ast.FuncDecl {
		seen := map[*ast.FuncDecl]bool{}
		var out []*ast.FuncDecl
		var walk func(n ast.Node)
		walk = func(n ast.Node) {
			if n == nil {
				return
			}
			switch node := n.(type) {
			case *ast.ValueSpec:
				if node.Type != nil {
					walk(node.Type)
				}
				for _, v := range node.Values {
					walk(v)
				}
			case *ast.KeyValueExpr:
				walk(node.Value)
			case *ast.SelectorExpr:
				if !excludeSels[node] {
					for _, target := range declByName[node.Sel.Name] {
						if target.Recv != nil && target != runFn && !seen[target] {
							seen[target] = true
							out = append(out, target)
						}
					}
				}
				walk(node.X)
			case *ast.Ident:
				for _, target := range declByName[node.Name] {
					if target.Recv == nil && target != mainStart && !seen[target] {
						seen[target] = true
						out = append(out, target)
					}
				}
			default:
				ast.Inspect(node, func(ch ast.Node) bool {
					if ch == node {
						return true
					}
					walk(ch)
					return false
				})
			}
		}
		for _, root := range nodes {
			walk(root)
		}
		return out
	}
	forwardClosure := func(seeds map[*ast.FuncDecl]bool, excludeSels map[*ast.SelectorExpr]bool) map[*ast.FuncDecl]bool {
		reached := map[*ast.FuncDecl]bool{}
		var queue []*ast.FuncDecl
		for fn := range seeds {
			if fn != nil && fn.Body != nil && !reached[fn] {
				reached[fn] = true
				queue = append(queue, fn)
			}
		}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, callee := range collectDirectCallees([]ast.Node{cur.Body}, excludeSels) {
				if !reached[callee] {
					reached[callee] = true
					queue = append(queue, callee)
				}
			}
		}
		return reached
	}

	seedRunnerNames := map[string]bool{
		"tRunner": true, "fRunner": true, "run1": true, "runN": true,
		"runTests": true, "runBenchmarks": true, "runExamples": true,
		"runFuzzTests": true, "runFuzzing": true,
		"RunTests": true, "RunBenchmarks": true, "RunExamples": true, "Benchmark": true,
	}
	perCaseExecSeedNames := map[string]bool{
		"tRunner": true, "fRunner": true, "run1": true, "runN": true,
	}
	coreTestBenchFuzzSeedNames := map[string]bool{
		"tRunner": true, "fRunner": true, "run1": true, "runN": true,
		"runTests": true, "runBenchmarks": true, "runFuzzTests": true, "runFuzzing": true,
		"RunTests": true, "RunBenchmarks": true, "Benchmark": true,
	}
	paramsMentionIdent := func(fl *ast.FieldList, target string) bool {
		if fl == nil {
			return false
		}
		hit := false
		for _, fld := range fl.List {
			ast.Inspect(fld.Type, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && id.Name == target {
					hit = true
					return false
				}
				return true
			})
		}
		return hit
	}

	runnerDecl := map[*ast.FuncDecl]bool{}
	perCaseExecSeeds := map[*ast.FuncDecl]bool{}
	coreTestBenchFuzzSeeds := map[*ast.FuncDecl]bool{}
	declCallees := map[*ast.FuncDecl][]*ast.FuncDecl{}
	for _, fn := range allDecls {
		if fn != runFn {
			if seedRunnerNames[fn.Name.Name] {
				runnerDecl[fn] = true
			}
			if perCaseExecSeedNames[fn.Name.Name] {
				perCaseExecSeeds[fn] = true
			}
			if coreTestBenchFuzzSeedNames[fn.Name.Name] {
				coreTestBenchFuzzSeeds[fn] = true
			}
		}
		hasFFnSel := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && (sel.Sel.Name == "F" || sel.Sel.Name == "Fn") {
				hasFFnSel = true
				return false
			}
			return true
		})
		if hasFFnSel && fn != runFn {
			runnerDecl[fn] = true
			if !paramsMentionIdent(fn.Type.Params, "InternalExample") {
				coreTestBenchFuzzSeeds[fn] = true
			}
		}
		declCallees[fn] = collectDirectCallees([]ast.Node{fn.Body}, nil)
	}
	for changed := true; changed; {
		changed = false
		for _, fn := range allDecls {
			if runnerDecl[fn] || fn == runFn {
				continue
			}
			for _, target := range declCallees[fn] {
				if runnerDecl[target] {
					runnerDecl[fn] = true
					changed = true
					break
				}
			}
		}
	}
	stmtCallsRunner := func(stmt ast.Stmt) bool {
		for _, target := range collectDirectCallees([]ast.Node{stmt}, nil) {
			if seedRunnerNames[target.Name.Name] || runnerDecl[target] {
				return true
			}
		}
		return false
	}

	exitSitesByFunc := map[*ast.FuncDecl][]testingExitSite{}
	for _, site := range osExitSites {
		if site.encFn == nil || site.encFn.Name.Name == "init" {
			return false
		}
		exitSitesByFunc[site.encFn] = append(exitSitesByFunc[site.encFn], site)
	}
	perCaseExecReachable := forwardClosure(perCaseExecSeeds, nil)
	for fn := range perCaseExecReachable {
		if len(exitSitesByFunc[fn]) > 0 {
			return false
		}
	}
	coreTestBenchFuzzReachable := forwardClosure(coreTestBenchFuzzSeeds, nil)
	allRunnerForwardReachable := forwardClosure(runnerDecl, nil)

	isBenignRunnerReachableExitSite := func(site testingExitSite) bool {
		idx := len(site.ancestors) - 1
		if idx < 4 || site.ancestors[idx] != site.call {
			return false
		}
		idx--
		for idx >= 0 {
			if _, isParen := site.ancestors[idx].(*ast.ParenExpr); !isParen {
				break
			}
			idx--
		}
		if idx < 3 {
			return false
		}
		es, okES := site.ancestors[idx].(*ast.ExprStmt)
		ifBlk, okIB := site.ancestors[idx-1].(*ast.BlockStmt)
		ifs, okIF := site.ancestors[idx-2].(*ast.IfStmt)
		parentBlk, okPB := site.ancestors[idx-3].(*ast.BlockStmt)
		if !okES || !okIB || !okIF || !okPB || unwrapParens(es.X) != site.call || ifs.Body != ifBlk || ifs.Else != nil || len(ifBlk.List) == 0 || ifBlk.List[len(ifBlk.List)-1] != es {
			return false
		}
		errVar := condChecksNonZeroErr(ifs.Cond)
		if errVar == "" {
			return false
		}
		hasOS := fileImportsOS[site.file]
		hasFmt := fileImportsFmt[site.file]
		for _, pre := range ifBlk.List[:len(ifBlk.List)-1] {
			if isBenignStderrDiagStmt(pre, hasOS, hasFmt) {
				continue
			}
			// Allow `if os.IsExist(errVar) { continue }` in temp-file open loop.
			if innerIf, okIn := pre.(*ast.IfStmt); okIn && innerIf.Init == nil && innerIf.Else == nil && hasOS && len(innerIf.Body.List) == 1 {
				if br, okBr := innerIf.Body.List[0].(*ast.BranchStmt); okBr && br.Tok == token.CONTINUE && br.Label == nil {
					if ieCall, okIEC := unwrapParens(innerIf.Cond).(*ast.CallExpr); okIEC && !ieCall.Ellipsis.IsValid() && len(ieCall.Args) == 1 {
						_, okSel := isSelectorBaseField(ieCall.Fun, "os", "IsExist")
						_, okArg := isIdentNamed(ieCall.Args[0], errVar)
						if okSel && okArg {
							continue
						}
					}
				}
			}
			return false
		}
		// Form 1: Pre-case filter/skip regex validation in unexported matcher constructor (`newMatcher`):
		// `if err := <ident>.verify(<arg0>, <p0>); err != nil { ... os.Exit(1) }`
		if ifs.Init != nil {
			if runnerDecl[site.encFn] || site.encFn.Recv != nil || ast.IsExported(site.encFn.Name.Name) || site.encFn.Type.Params == nil || site.encFn.Type.Results == nil || site.encFn.Type.Results.NumFields() != 1 {
				return false
			}
			fnParams := paramNamesFlat(site.encFn.Type.Params)
			if len(fnParams) != 4 || fnParams[0] == "" || fnParams[0] == "_" {
				return false
			}
			if _, isFT := unwrapParens(site.encFn.Type.Params.List[0].Type).(*ast.FuncType); !isFT {
				return false
			}
			initAs, okA := ifs.Init.(*ast.AssignStmt)
			if !okA || initAs.Tok != token.DEFINE || len(initAs.Lhs) != 1 || len(initAs.Rhs) != 1 {
				return false
			}
			if _, okLHS := isIdentNamed(initAs.Lhs[0], errVar); !okLHS {
				return false
			}
			vCall, okVC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
			if !okVC || vCall.Ellipsis.IsValid() || len(vCall.Args) != 2 || exprHasCallOrFuncLit(vCall.Args[0]) {
				return false
			}
			if _, okP0 := isIdentNamed(vCall.Args[1], fnParams[0]); !okP0 {
				return false
			}
			vSel, okVS := unwrapParens(vCall.Fun).(*ast.SelectorExpr)
			if !okVS || vSel.Sel.Name != "verify" {
				return false
			}
			if _, okBase := unwrapParens(vSel.X).(*ast.Ident); !okBase {
				return false
			}
			verifyDecls := declByName["verify"]
			if len(verifyDecls) == 0 {
				return false
			}
			for _, vd := range verifyDecls {
				if runnerDecl[vd] || len(exitSitesByFunc[vd]) > 0 {
					return false
				}
			}
			return true
		}
		// Form 2: Example stdout-capture OS failure (`os.Pipe`, `os.OpenFile`, `io.Copy`, `<file>.Seek`),
		// prohibited anywhere reachable from core Test/Benchmark/Fuzz runners.
		if coreTestBenchFuzzReachable[site.encFn] {
			return false
		}
		ifIdx := slices.Index(parentBlk.List, ast.Stmt(ifs))
		if ifIdx <= 0 {
			return false
		}
		for pos := ifIdx - 1; pos >= 0; pos-- {
			stPrev := parentBlk.List[pos]
			if as, okA := stPrev.(*ast.AssignStmt); okA && (as.Tok == token.DEFINE || as.Tok == token.ASSIGN) && len(as.Lhs) >= 2 && len(as.Rhs) == 1 {
				if _, okLast := isIdentNamed(as.Lhs[len(as.Lhs)-1], errVar); okLast {
					if bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: parentBlk.List[pos+1 : ifIdx]}, map[string]bool{errVar: true}) {
						return false
					}
					opCall, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
					if !okC || opCall.Ellipsis.IsValid() {
						return false
					}
					if _, okPipe := isSelectorBaseField(opCall.Fun, "os", "Pipe"); okPipe && hasOS && len(opCall.Args) == 0 {
						return true
					}
					if _, okOF := isSelectorBaseField(opCall.Fun, "os", "OpenFile"); okOF && hasOS && len(opCall.Args) == 3 {
						return true
					}
					if _, okCopy := isSelectorBaseField(opCall.Fun, "io", "Copy"); okCopy && fileImportsIO[site.file] && len(opCall.Args) == 2 {
						return true
					}
					if sSel, okSeek := unwrapParens(opCall.Fun).(*ast.SelectorExpr); okSeek && sSel.Sel.Name == "Seek" && len(opCall.Args) == 2 && !exprHasCallOrFuncLit(opCall.Args[0]) && !exprHasCallOrFuncLit(opCall.Args[1]) {
						if _, okRecv := unwrapParens(sSel.X).(*ast.Ident); okRecv {
							return true
						}
					}
					return false
				}
			}
			if bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: []ast.Stmt{stPrev}}, map[string]bool{errVar: true}) {
				return false
			}
		}
		return false
	}

	for fn := range allRunnerForwardReachable {
		for _, site := range exitSitesByFunc[fn] {
			if !isBenignRunnerReachableExitSite(site) {
				return false
			}
		}
	}

	stmtsHaveNoNonRunnerHelperExit := func(stmts []ast.Stmt, excludeSels map[*ast.SelectorExpr]bool) bool {
		seeds := map[*ast.FuncDecl]bool{}
		nodes := make([]ast.Node, 0, len(stmts))
		for _, s := range stmts {
			if s != nil {
				nodes = append(nodes, s)
			}
		}
		for _, callee := range collectDirectCallees(nodes, excludeSels) {
			if !runnerDecl[callee] {
				seeds[callee] = true
			}
		}
		for fn := range forwardClosure(seeds, excludeSels) {
			if !runnerDecl[fn] && len(exitSitesByFunc[fn]) > 0 {
				return false
			}
		}
		return true
	}

	bodyHasGoexit := func(body *ast.BlockStmt) bool {
		hit := false
		ast.Inspect(body, func(n ast.Node) bool {
			if hit || n == nil {
				return false
			}
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Goexit" {
				hit = true
				return false
			}
			return true
		})
		return hit
	}
	if bodyHasGoexit(runFn.Body) {
		return false
	}

	// Find flag.Parse() or if !flag.Parsed() { flag.Parse() } at top level of (*M).Run.
	runFile := funcFile[runFn]
	if !fileImportsFlag[runFile] {
		return false
	}
	isFlagCall0 := func(expr ast.Expr, fnName string) bool {
		call, ok := unwrapParens(expr).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) != 0 {
			return false
		}
		sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != fnName {
			return false
		}
		pkgID, ok := unwrapParens(sel.X).(*ast.Ident)
		return ok && pkgID.Name == "flag"
	}
	parseIdx := -1
	for i, stmt := range runFn.Body.List {
		if es, ok := stmt.(*ast.ExprStmt); ok && isFlagCall0(es.X, "Parse") {
			parseIdx = i
			break
		}
		if ifs, ok := stmt.(*ast.IfStmt); ok && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
			if u, okU := unwrapParens(ifs.Cond).(*ast.UnaryExpr); okU && u.Op == token.NOT && isFlagCall0(u.X, "Parsed") {
				if es, okE := ifs.Body.List[0].(*ast.ExprStmt); okE && isFlagCall0(es.X, "Parse") {
					parseIdx = i
					break
				}
			}
		}
	}
	if parseIdx < 0 {
		return false
	}

	// Validate pre-StartTestLog statements in (*M).Run:
	// - No runner calls and no unconditional top-level termination.
	// - Every ReturnStmt either returns a positive exit code (directly when exitCodeField == "",
	//   or preceded immediately by m.<exitCodeField> = <posIntLit> when exitCodeField != "")
	//   OR sits inside a post-Parse `if *<listFlag> != ""` block for a verified test.list flag.
	verifyRunPreStartSlice := func(limit int) bool {
		for idx, top := range runFn.Body.List[:limit] {
			if stmtAlwaysTerminates(top) || stmtCallsRunner(top) {
				return false
			}
			allowedZeroReturn := false
			if idx > parseIdx {
				if ifs, ok := top.(*ast.IfStmt); ok && ifs.Init == nil && ifs.Else == nil {
					if lf, ok2 := derefFlagNonEmptyCondIdent(ifs.Cond); ok2 && listFlagVars[lf] && !funcShadowsAnyIdent(runFn, map[string]bool{lf: true}) && verifyFlagInitCalledInMainStart(lf) && verifyFlagPtrIdentOnlyDereferenced(lf) {
						allowedZeroReturn = true
					}
				}
			}
			var checkPreBlock func(blk *ast.BlockStmt) bool
			checkPreBlock = func(blk *ast.BlockStmt) bool {
				if blk == nil {
					return true
				}
				for j, s := range blk.List {
					switch node := s.(type) {
					case *ast.ReturnStmt:
						if allowedZeroReturn {
							if exitCodeField != "" && len(node.Results) != 0 {
								return false
							}
							continue
						}
						if exitCodeField == "" {
							if len(node.Results) != 1 || exprHasCallOrFuncLit(node.Results[0]) || !isPositiveIntLit(node.Results[0]) {
								return false
							}
						} else {
							if len(node.Results) != 0 || j == 0 {
								return false
							}
							prevAs, ok := blk.List[j-1].(*ast.AssignStmt)
							if !ok || prevAs.Tok != token.ASSIGN || len(prevAs.Lhs) != 1 || len(prevAs.Rhs) != 1 || exprHasCallOrFuncLit(prevAs.Rhs[0]) || !isPositiveIntLit(prevAs.Rhs[0]) {
								return false
							}
							sel, ok := unwrapParens(prevAs.Lhs[0]).(*ast.SelectorExpr)
							if !ok || sel.Sel.Name != exitCodeField {
								return false
							}
							if rID, ok2 := unwrapParens(sel.X).(*ast.Ident); !ok2 || rID.Name != runRecv {
								return false
							}
						}
					case *ast.IfStmt:
						if !checkPreBlock(node.Body) {
							return false
						}
						switch el := node.Else.(type) {
						case nil:
						case *ast.BlockStmt:
							if !checkPreBlock(el) {
								return false
							}
						case *ast.IfStmt:
							if !checkPreBlock(&ast.BlockStmt{List: []ast.Stmt{el}}) {
								return false
							}
						default:
							return false
						}
					case *ast.BlockStmt:
						if !checkPreBlock(node) {
							return false
						}
					case *ast.GoStmt:
						return false
					case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
						hasRetOrGo := false
						ast.Inspect(node, func(n ast.Node) bool {
							if _, isFL := n.(*ast.FuncLit); isFL {
								return false
							}
							switch n.(type) {
							case *ast.ReturnStmt, *ast.GoStmt:
								hasRetOrGo = true
								return false
							}
							return true
						})
						if hasRetOrGo {
							return false
						}
					}
				}
				return true
			}
			if topIf, ok := top.(*ast.IfStmt); ok {
				if !checkPreBlock(topIf.Body) {
					return false
				}
				if topIf.Else != nil {
					if !checkPreBlock(&ast.BlockStmt{List: []ast.Stmt{topIf.Else}}) {
						return false
					}
				}
			} else {
				hasRetOrGo := false
				ast.Inspect(top, func(n ast.Node) bool {
					if _, isFL := n.(*ast.FuncLit); isFL {
						return false
					}
					switch n.(type) {
					case *ast.ReturnStmt, *ast.GoStmt:
						hasRetOrGo = true
						return false
					}
					return true
				})
				if hasRetOrGo {
					return false
				}
			}
		}
		return true
	}

	verifyOnlyAllowedDefersInRun := func(allowedAfterDefer *ast.DeferStmt) bool {
		badDeferOrGo := false
		ast.Inspect(runFn.Body, func(n ast.Node) bool {
			if badDeferOrGo || n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.DeferStmt:
				if node != exitCodeDefer && node != allowedAfterDefer {
					badDeferOrGo = true
					return false
				}
			case *ast.GoStmt:
				badDeferOrGo = true
				return false
			}
			return true
		})
		return !badDeferOrGo
	}

	// Mode 1: Inline StartTestLog and StopTestLog directly in (*M).Run.
	if st.fn == runFn && sp.fn == runFn {
		if !verifyOnlyAllowedDefersInRun(nil) {
			return false
		}
		startTopIdx := slices.Index(runFn.Body.List, st.topStmt)
		stopTopIdx := slices.Index(runFn.Body.List, sp.topStmt)
		if startTopIdx < 0 || stopTopIdx < startTopIdx || parseIdx >= startTopIdx {
			return false
		}
		if !verifyRunPreStartSlice(startTopIdx) {
			return false
		}
		checkNoRetOrGo := func(stmts []ast.Stmt) bool {
			for _, mid := range stmts {
				if stmtAlwaysTerminates(mid) {
					return false
				}
				hasRetOrGo := false
				ast.Inspect(mid, func(n ast.Node) bool {
					switch n.(type) {
					case *ast.ReturnStmt, *ast.GoStmt:
						hasRetOrGo = true
						return false
					}
					return true
				})
				if hasRetOrGo {
					return false
				}
			}
			return true
		}
		if st.topStmt == sp.topStmt {
			if st.declBlock != sp.parentBlk {
				return false
			}
			for _, pre := range st.declBlock.List[:st.declTargetIdx] {
				if stmtCallsRunner(pre) {
					return false
				}
			}
			if !checkNoRetOrGo(st.declBlock.List[st.declTargetIdx+1 : sp.stmtPos]) {
				return false
			}
			if !stmtsHaveNoNonRunnerHelperExit(st.declBlock.List[st.declTargetIdx+1:], nil) {
				return false
			}
			for _, post := range sp.parentBlk.List[sp.stmtPos:] {
				if stmtCallsRunner(post) {
					return false
				}
			}
			if !slices.ContainsFunc(sp.parentBlk.List[sp.afterStopPos:], stmtAlwaysTerminates) {
				for _, post := range runFn.Body.List[stopTopIdx+1:] {
					if stmtCallsRunner(post) {
						return false
					}
				}
			}
		} else {
			if stmtCallsRunner(st.topStmt) || stmtCallsRunner(sp.topStmt) {
				return false
			}
			if !checkNoRetOrGo(runFn.Body.List[startTopIdx+1 : stopTopIdx]) {
				return false
			}
			if !stmtsHaveNoNonRunnerHelperExit(st.declBlock.List[st.declTargetIdx+1:], nil) || !stmtsHaveNoNonRunnerHelperExit(runFn.Body.List[startTopIdx+1:stopTopIdx+1], nil) {
				return false
			}
			for _, post := range runFn.Body.List[stopTopIdx+1:] {
				if stmtCallsRunner(post) {
					return false
				}
			}
		}
		return true
	}

	// Mode 2: Split lifecycle via unexported *M methods: m.<before>() + defer m.<after>() in (*M).Run.
	if st.fn == runFn || sp.fn == runFn || st.fn == sp.fn {
		return false
	}
	beforeName := st.fn.Name.Name
	stopMethodName := sp.fn.Name.Name
	if ast.IsExported(beforeName) || ast.IsExported(stopMethodName) || mMethods[beforeName] != st.fn || mMethods[stopMethodName] != sp.fn {
		return false
	}
	isZeroArgVoidMMethod := func(fn *ast.FuncDecl) bool {
		return fn != nil && fn.Body != nil && recvVarName(fn) != "" &&
			(fn.Type.Params == nil || fn.Type.Params.NumFields() == 0) &&
			(fn.Type.Results == nil || fn.Type.Results.NumFields() == 0)
	}
	if !isZeroArgVoidMMethod(st.fn) || !isZeroArgVoidMMethod(sp.fn) {
		return false
	}

	beforeIdx := -1
	var afterName string
	var afterDeferStmt *ast.DeferStmt
	var beforeCallSel, afterDeferSel *ast.SelectorExpr
	for i := 0; i+1 < len(runFn.Body.List); i++ {
		es, ok1 := runFn.Body.List[i].(*ast.ExprStmt)
		ds, ok2 := runFn.Body.List[i+1].(*ast.DeferStmt)
		if !ok1 || !ok2 {
			continue
		}
		bCall, okB := unwrapParens(es.X).(*ast.CallExpr)
		if !okB || bCall.Ellipsis.IsValid() || len(bCall.Args) != 0 || ds.Call.Ellipsis.IsValid() || len(ds.Call.Args) != 0 {
			continue
		}
		bSel, okBS := unwrapParens(bCall.Fun).(*ast.SelectorExpr)
		aSel, okAS := unwrapParens(ds.Call.Fun).(*ast.SelectorExpr)
		if !okBS || !okAS || bSel.Sel.Name != beforeName {
			continue
		}
		bRecv, okBR := unwrapParens(bSel.X).(*ast.Ident)
		aRecv, okAR := unwrapParens(aSel.X).(*ast.Ident)
		if okBR && okAR && bRecv.Name == runRecv && aRecv.Name == runRecv {
			beforeIdx = i
			afterName = aSel.Sel.Name
			afterDeferStmt = ds
			beforeCallSel = bSel
			afterDeferSel = aSel
			break
		}
	}
	if beforeIdx < 0 || parseIdx >= beforeIdx || ast.IsExported(afterName) {
		return false
	}
	afterFn := mMethods[afterName]
	if !isZeroArgVoidMMethod(afterFn) || afterFn == runFn || afterFn == st.fn {
		return false
	}
	if funcShadowsAnyIdent(afterFn, pkgReserved) || bodyHasControlFlowOrRecoverBypass(afterFn.Body) {
		return false
	}
	if bodyHasGoexit(st.fn.Body) || bodyHasGoexit(afterFn.Body) || bodyHasGoexit(sp.fn.Body) {
		return false
	}
	if !verifyOnlyAllowedDefersInRun(afterDeferStmt) || !verifyRunPreStartSlice(beforeIdx) {
		return false
	}

	// Verify st.fn (before): no runners, no Defer/Go, no top-level termination before StartTestLog,
	// pre-StartTestLog returns only inside `if ... err != nil`, and no returns at/after StartTestLog.
	startInBeforeIdx := slices.Index(st.fn.Body.List, st.topStmt)
	if startInBeforeIdx < 0 || stmtCallsRunner(&ast.BlockStmt{List: st.fn.Body.List}) {
		return false
	}
	hasDeferOrGo := func(body *ast.BlockStmt) bool {
		hit := false
		ast.Inspect(body, func(n ast.Node) bool {
			if hit || n == nil {
				return false
			}
			switch n.(type) {
			case *ast.DeferStmt, *ast.GoStmt:
				hit = true
				return false
			}
			return true
		})
		return hit
	}
	if hasDeferOrGo(st.fn.Body) || hasDeferOrGo(afterFn.Body) || hasDeferOrGo(sp.fn.Body) {
		return false
	}
	for _, pre := range st.fn.Body.List[:startInBeforeIdx] {
		if stmtAlwaysTerminates(pre) {
			return false
		}
		var outerOptFlagOK bool
		if topIf, ok := pre.(*ast.IfStmt); ok && topIf.Init == nil && topIf.Else == nil {
			if fg, ok2 := derefFlagNonEmptyCondIdent(topIf.Cond); ok2 && emptyDefaultStringFlags[fg] && !funcShadowsAnyIdent(st.fn, map[string]bool{fg: true}) && verifyFlagInitCalledInMainStart(fg) && verifyFlagPtrIdentOnlyDereferenced(fg) {
				outerOptFlagOK = true
			}
		}
		var checkBeforeStmt func(s ast.Stmt, underErrIf bool) bool
		checkBeforeStmt = func(s ast.Stmt, underErrIf bool) bool {
			switch node := s.(type) {
			case nil, *ast.EmptyStmt, *ast.DeclStmt, *ast.AssignStmt, *ast.ExprStmt, *ast.IncDecStmt:
				hasLit := false
				ast.Inspect(s, func(n ast.Node) bool {
					if _, ok := n.(*ast.FuncLit); ok {
						hasLit = true
						return false
					}
					return true
				})
				return !hasLit
			case *ast.ReturnStmt:
				return outerOptFlagOK && underErrIf && len(node.Results) == 0
			case *ast.BlockStmt:
				for _, child := range node.List {
					if !checkBeforeStmt(child, underErrIf) {
						return false
					}
				}
				return true
			case *ast.IfStmt:
				isErrIf := underErrIf || (node.Else == nil && condChecksNonZeroErr(node.Cond) != "")
				if !checkBeforeStmt(node.Body, isErrIf) {
					return false
				}
				if node.Else != nil && !checkBeforeStmt(node.Else, false) {
					return false
				}
				return true
			default:
				return false
			}
		}
		if !checkBeforeStmt(pre, false) {
			return false
		}
	}
	for _, post := range st.fn.Body.List[startInBeforeIdx:] {
		hasRet := false
		ast.Inspect(post, func(n ast.Node) bool {
			if _, ok := n.(*ast.ReturnStmt); ok {
				hasRet = true
				return false
			}
			return true
		})
		if hasRet {
			return false
		}
	}

	// Verify afterFn -> sp.fn wiring and sp.fn head position.
	if stmtCallsRunner(&ast.BlockStmt{List: afterFn.Body.List}) || stmtCallsRunner(&ast.BlockStmt{List: sp.fn.Body.List}) {
		return false
	}
	if len(sp.fn.Body.List) == 0 || sp.fn.Body.List[0] != sp.topStmt || sp.stmtPos != 0 {
		return false
	}
	var spCallSel *ast.SelectorExpr
	var onceField string
	var onceSelIdent *ast.Ident
	if afterFn != sp.fn {
		if len(afterFn.Body.List) == 0 {
			return false
		}
		afterRecv := recvVarName(afterFn)
		s0, ok := afterFn.Body.List[0].(*ast.ExprStmt)
		if !ok {
			return false
		}
		c0, ok := unwrapParens(s0.X).(*ast.CallExpr)
		if !ok || c0.Ellipsis.IsValid() {
			return false
		}
		sel0, ok := unwrapParens(c0.Fun).(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if rID, okR := unwrapParens(sel0.X).(*ast.Ident); okR && rID.Name == afterRecv && sel0.Sel.Name == stopMethodName && len(c0.Args) == 0 {
			spCallSel = sel0
		} else if sel0.Sel.Name == "Do" && len(c0.Args) == 1 {
			fSel, okFS := unwrapParens(sel0.X).(*ast.SelectorExpr)
			if !okFS {
				return false
			}
			rID, okR := unwrapParens(fSel.X).(*ast.Ident)
			fl, okFL := unwrapParens(c0.Args[0]).(*ast.FuncLit)
			if !okR || !okFL || rID.Name != afterRecv || ast.IsExported(fSel.Sel.Name) || (fl.Type.Params != nil && fl.Type.Params.NumFields() != 0) || (fl.Type.Results != nil && fl.Type.Results.NumFields() != 0) || fl.Body == nil || len(fl.Body.List) != 1 {
				return false
			}
			innerES, okIE := fl.Body.List[0].(*ast.ExprStmt)
			if !okIE {
				return false
			}
			innerCall, okIC := unwrapParens(innerES.X).(*ast.CallExpr)
			if !okIC || innerCall.Ellipsis.IsValid() || len(innerCall.Args) != 0 {
				return false
			}
			innerSel, okIS := unwrapParens(innerCall.Fun).(*ast.SelectorExpr)
			if !okIS || innerSel.Sel.Name != stopMethodName {
				return false
			}
			if innerRecv, okIR := unwrapParens(innerSel.X).(*ast.Ident); !okIR || innerRecv.Name != afterRecv {
				return false
			}
			// Verify onceField has type sync.Once on M.
			onceTypeSel, okOT := unwrapParens(mFields[fSel.Sel.Name]).(*ast.SelectorExpr)
			if !okOT || onceTypeSel.Sel.Name != "Once" || !fileImportsSync[mStructFile] {
				return false
			}
			if syncID, okSID := unwrapParens(onceTypeSel.X).(*ast.Ident); !okSID || syncID.Name != "sync" {
				return false
			}
			onceField = fSel.Sel.Name
			onceSelIdent = fSel.Sel
			spCallSel = innerSel
		} else {
			return false
		}
	}

	// Verify call-site and field-reference isolation across the entire testing package for:
	// - onceField (only M struct field decl and afterFn's single m.<onceField>.Do)
	// - beforeName (only m.<before>() at runFn.Body.List[beforeIdx])
	// - stopMethodName when afterFn != sp.fn (only m.<sp>() at stmt 0 of afterFn)
	// - afterName (only defer m.<after>() in runFn, plus optional panic-terminating alarm FuncLit
	//   inside an unexported *M method called exclusively in runFn.Body.List[beforeIdx+2:])
	var extraAfterHelperNames = map[string]bool{}
	alarmAfterSels := map[*ast.SelectorExpr]bool{}
	isolatedOK := true
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if !isolatedOK || n == nil {
				return false
			}
			if id, isID := n.(*ast.Ident); isID && onceField != "" && id.Name == onceField {
				if id != mFieldIdents[onceField] && id != onceSelIdent {
					isolatedOK = false
					return false
				}
			}
			sel, isSel := n.(*ast.SelectorExpr)
			if !isSel {
				return true
			}
			switch sel.Sel.Name {
			case beforeName:
				if sel != beforeCallSel {
					isolatedOK = false
					return false
				}
			case stopMethodName:
				if afterFn != sp.fn && sel != spCallSel {
					isolatedOK = false
					return false
				}
			case afterName:
				if sel == afterDeferSel {
					return true
				}
				// Secondary call allowed only as stmt 0 of a panic-terminating FuncLit inside an unexported *M method.
				encFn, anc := findEnclosingFuncAndAncestors(f, sel)
				if encFn == nil || encFn == runFn || encFn == st.fn || encFn == afterFn || encFn == sp.fn || ast.IsExported(encFn.Name.Name) || mMethods[encFn.Name.Name] != encFn || funcShadowsAnyIdent(encFn, pkgReserved) {
					isolatedOK = false
					return false
				}
				hRecv := recvVarName(encFn)
				if hRecv == "" {
					isolatedOK = false
					return false
				}
				rID, okR := unwrapParens(sel.X).(*ast.Ident)
				if !okR || rID.Name != hRecv {
					isolatedOK = false
					return false
				}
				// Locate enclosing FuncLit in anc: ... -> FuncLit -> BlockStmt -> ExprStmt -> CallExpr -> sel
				if len(anc) < 5 {
					isolatedOK = false
					return false
				}
				callNode, ok1 := anc[len(anc)-2].(*ast.CallExpr)
				esNode, ok2 := anc[len(anc)-3].(*ast.ExprStmt)
				blkNode, ok3 := anc[len(anc)-4].(*ast.BlockStmt)
				flNode, ok4 := anc[len(anc)-5].(*ast.FuncLit)
				if !ok1 || !ok2 || !ok3 || !ok4 || callNode.Ellipsis.IsValid() || len(callNode.Args) != 0 || unwrapParens(callNode.Fun) != sel || unwrapParens(esNode.X) != callNode || flNode.Body != blkNode || len(blkNode.List) < 2 || blkNode.List[0] != esNode {
					isolatedOK = false
					return false
				}
				// Verify FuncLit body has no ReturnStmt, LabeledStmt, BranchStmt, DeferStmt, ForStmt, or recover,
				// and ends with unconditional panic(...).
				badFL := false
				ast.Inspect(blkNode, func(fnNode ast.Node) bool {
					if badFL || fnNode == nil {
						return false
					}
					if innerFL, isFL := fnNode.(*ast.FuncLit); isFL {
						badFL = innerFL != flNode
						return false
					}
					switch x := fnNode.(type) {
					case *ast.ReturnStmt, *ast.LabeledStmt, *ast.BranchStmt, *ast.DeferStmt, *ast.ForStmt, *ast.SelectStmt:
						badFL = true
						return false
					case *ast.CallExpr:
						if cid, ok := unwrapParens(x.Fun).(*ast.Ident); ok && cid.Name == "recover" {
							badFL = true
							return false
						}
					}
					return true
				})
				if badFL || funcLitShadowsAnyIdent(flNode, map[string]bool{"panic": true}) {
					isolatedOK = false
					return false
				}
				lastES, okLast := blkNode.List[len(blkNode.List)-1].(*ast.ExprStmt)
				if !okLast {
					isolatedOK = false
					return false
				}
				pCall, okPC := unwrapParens(lastES.X).(*ast.CallExpr)
				if !okPC || pCall.Ellipsis.IsValid() || len(pCall.Args) != 1 {
					isolatedOK = false
					return false
				}
				if pID, okPID := unwrapParens(pCall.Fun).(*ast.Ident); !okPID || pID.Name != "panic" {
					isolatedOK = false
					return false
				}
				extraAfterHelperNames[encFn.Name.Name] = true
				alarmAfterSels[sel] = true
			}
			return true
		})
		if !isolatedOK {
			return false
		}
	}

	// Any helper method containing a secondary m.<after>() panic FuncLit (e.g. startAlarm)
	// may only be referenced inside runFn.Body.List[beforeIdx+2:].
	if len(extraAfterHelperNames) > 0 {
		allowedHelperSels := map[*ast.SelectorExpr]bool{}
		for _, postStmt := range runFn.Body.List[beforeIdx+2:] {
			ast.Inspect(postStmt, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok && !call.Ellipsis.IsValid() && len(call.Args) == 0 {
					if sel, ok2 := unwrapParens(call.Fun).(*ast.SelectorExpr); ok2 && extraAfterHelperNames[sel.Sel.Name] {
						if rID, ok3 := unwrapParens(sel.X).(*ast.Ident); ok3 && rID.Name == runRecv {
							allowedHelperSels[sel] = true
						}
					}
				}
				return true
			})
		}
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				if !isolatedOK || n == nil {
					return false
				}
				if sel, ok := n.(*ast.SelectorExpr); ok && extraAfterHelperNames[sel.Sel.Name] && !allowedHelperSels[sel] {
					isolatedOK = false
					return false
				}
				return true
			})
		}
		if !isolatedOK {
			return false
		}
	}

	// Verify Mode 2 os.Exit containment across active testlog lifecycle:
	// - Direct os.Exit in st.fn (`before`) allowed ONLY in st.openExits or before startInBeforeIdx.
	// - Zero direct os.Exit in afterFn (when afterFn != sp.fn) and extraAfterHelperNames.
	// - Direct os.Exit inside sp.fn.Body.List[0] (`if *testlog != ""`) allowed ONLY in sp.stopExit or closeExits.
	// - Zero os.Exit in any non-runner helper reachable from active lifecycle statement slices.
	ancestorsTouchSlice := func(ancestors []ast.Node, slice []ast.Stmt) bool {
		for _, anc := range ancestors {
			if s, ok := anc.(ast.Stmt); ok && slices.Contains(slice, s) {
				return true
			}
		}
		return false
	}
	for _, site := range exitSitesByFunc[st.fn] {
		if !st.openExits[site.call] && !ancestorsTouchSlice(site.ancestors, st.fn.Body.List[:startInBeforeIdx]) {
			return false
		}
	}
	if afterFn != sp.fn && len(exitSitesByFunc[afterFn]) > 0 {
		return false
	}
	for helperName := range extraAfterHelperNames {
		if len(exitSitesByFunc[mMethods[helperName]]) > 0 {
			return false
		}
	}
	for _, site := range exitSitesByFunc[sp.fn] {
		if ancestorsTouchSlice(site.ancestors, sp.fn.Body.List[:1]) && site.call != sp.stopExit && !closeExits[site.call] {
			return false
		}
	}
	excludeActiveSels := map[*ast.SelectorExpr]bool{}
	if afterDeferSel != nil {
		excludeActiveSels[afterDeferSel] = true
	}
	if spCallSel != nil {
		excludeActiveSels[spCallSel] = true
	}
	for sel := range alarmAfterSels {
		excludeActiveSels[sel] = true
	}
	if !stmtsHaveNoNonRunnerHelperExit(st.declBlock.List[st.declTargetIdx+1:], excludeActiveSels) ||
		!stmtsHaveNoNonRunnerHelperExit(st.fn.Body.List[startInBeforeIdx+1:], excludeActiveSels) ||
		!stmtsHaveNoNonRunnerHelperExit(runFn.Body.List[beforeIdx+1:], excludeActiveSels) ||
		!stmtsHaveNoNonRunnerHelperExit(sp.fn.Body.List[:1], excludeActiveSels) {
		return false
	}
	if afterFn != sp.fn && !stmtsHaveNoNonRunnerHelperExit(afterFn.Body.List, excludeActiveSels) {
		return false
	}

	return true
}

func verifyTestingContextDecl(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Recv == nil || len(fn.Recv.List) != 1 || fn.Body == nil || len(fn.Body.List) != 2 {
		return false
	}
	recvField := fn.Recv.List[0]
	if len(recvField.Names) != 1 || recvField.Names[0].Name == "" {
		return false
	}
	recvName := recvField.Names[0].Name
	star, ok := recvField.Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	recvIdent, ok := star.X.(*ast.Ident)
	if !ok || recvIdent.Name != "common" {
		return false
	}
	if fn.Type.Params != nil && fn.Type.Params.NumFields() != 0 {
		return false
	}
	if fn.Type.Results == nil || fn.Type.Results.NumFields() != 1 {
		return false
	}
	exprStmt, ok := fn.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := exprStmt.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "checkFuzzFn" {
		return false
	}
	if id, ok := sel.X.(*ast.Ident); !ok || id.Name != recvName {
		return false
	}
	if lit, ok := call.Args[0].(*ast.BasicLit); !ok || lit.Kind != token.STRING || lit.Value != `"Context"` {
		return false
	}
	retStmt, ok := fn.Body.List[1].(*ast.ReturnStmt)
	if !ok || len(retStmt.Results) != 1 {
		return false
	}
	retSel, ok := retStmt.Results[0].(*ast.SelectorExpr)
	if !ok || retSel.Sel.Name != "ctx" {
		return false
	}
	retRecv, ok := retSel.X.(*ast.Ident)
	return ok && retRecv.Name == recvName
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
	if listErr != nil {
		return selectionDegradation{
			fmt.Sprintf("the audited surface of %s could not be read: %v", version, listErr),
			"; the admission needs the toolchain's standard-library source listed and readable",
		}, nil, nil
	}
	failed, pureDelegates, ioErr, ctxErr := verifyToolchainSurfaceAndDelegatesWithIO(ctx, d)
	if ctxErr != nil {
		return selectionDegradation{}, nil, ctxErr
	}
	if ioErr != nil {
		return selectionDegradation{
			fmt.Sprintf("the audited surface of %s could not be read: %v", version, ioErr),
			"; the admission needs the toolchain's standard-library source listed and readable",
		}, nil, nil
	}
	if len(failed) == 0 {
		return selectionDegradation{}, pureDelegates, nil
	}
	return selectionDegradation{
		fmt.Sprintf("the audited surface of %s moved in %d keys: %s", version, len(failed), namedMoved(failed)),
		"; the admission needs every audited standard-library package to satisfy the structural source contracts",
	}, nil, nil
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
	deg, pureDelegates, err := toolchainSourceDegradationAndDelegatesContext(ctx, snapshot.Value("GOVERSION"), d, listErr)
	if err != nil {
		return selectionDegradation{}, sourceDigests{}, err
	}
	if deg.audited() {
		d.pureDelegates = pureDelegates
	}
	return deg, d, nil
}

func isInternalStdPackagePath(pkgPath string) bool {
	return pkgPath == "internal" || strings.HasPrefix(pkgPath, "internal/") || strings.HasSuffix(pkgPath, "/internal") || strings.Contains(pkgPath, "/internal/")
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
