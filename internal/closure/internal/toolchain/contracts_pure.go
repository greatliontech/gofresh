package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/internal/auditset"
)

// AllowedPureSupportImports lists the non-pure standard-library packages that a
// package in auditset.PurePackages() or its transitive pure delegates may
// import globally under a closed selector allowlist without becoming pure
// delegates themselves. Package-specific support imports are gated in
// IsPureSupportImport with dedicated closed selector allowlists. Any other
// standard-library import from a pure or pure-delegate package is either
// explicitly forbidden or must itself verify transitively as a pure delegate.
var AllowedPureSupportImports = map[string]bool{
	"crypto/internal/fips140": true,
	"fmt":                     true,
	"math":                    true,
	"reflect":                 true,
	"runtime":                 true,
	"sync":                    true,
	"sync/atomic":             true,
	"time":                    true,
}

// AppendPolicyPackages appends all pure-delegate support import and selector
// policy tables into packages using the canonical policy digest keys.
func AppendPolicyPackages(packages map[string]bool) {
	for k, v := range AllowedPureSupportImports {
		packages["pure-import:"+k] = v
	}
	for k, v := range AllowedPureCryptoInternalFIPS140Selectors {
		packages["pure-fips140-allow:"+k] = v
	}
	for k, v := range AllowedPureBoringCipherSelectors {
		packages["pure-boring-cipher-allow:"+k] = v
	}
	for k, v := range AllowedPureFIPS140OnlyFIPSSelectors {
		packages["pure-fips140only-fips-allow:"+k] = v
	}
	for k, v := range AllowedPureFIPS140OnlyDRBGSelectors {
		packages["pure-fips140only-drbg-allow:"+k] = v
	}
	for k, v := range AllowedPureSHAGodebugSettings {
		packages["pure-sha-godebug-allow:"+k] = v
	}
	for k, v := range AllowedPureFmtSelectors {
		packages["pure-fmt-allow:"+k] = v
	}
	for k, v := range AllowedPureMathSelectors {
		packages["pure-math-allow:"+k] = v
	}
	for k, v := range AllowedPureReflectSelectors {
		packages["pure-reflect-allow:"+k] = v
	}
	for k, v := range AllowedPureFilepathliteSyscallSelectors {
		packages["pure-filepathlite-syscall-allow:"+k] = v
	}
	for k, v := range AllowedPureFilepathliteWindowsSelectors {
		packages["pure-filepathlite-windows-allow:"+k] = v
	}
	for k, v := range AllowedPureMathRandSelectors {
		packages["pure-rand-allow:"+k] = v
	}
	for k, v := range AllowedPureRuntimeSelectors {
		packages["pure-runtime-allow:"+k] = v
	}
	for k, v := range AllowedPureSyncSelectors {
		packages["pure-sync-allow:"+k] = v
	}
	for k, v := range AllowedPureSyncAtomicSelectors {
		packages["pure-sync-atomic-allow:"+k] = v
	}
	for k, v := range AllowedPureTimeSelectors {
		packages["pure-time-allow:"+k] = v
	}
}

// AllowedPureCryptoInternalFIPS140Selectors lists the selectors on
// "crypto/internal/fips140" permitted in pure and pure-delegate packages.
var AllowedPureCryptoInternalFIPS140Selectors = map[string]bool{
	"CAST":              true,
	"Enabled":           true,
	"Name":              true,
	"RecordApproved":    true,
	"RecordNonApproved": true,
	"Version":           true,
}

// AllowedPureBoringCipherSelectors lists the pure interface types on
// "crypto/cipher" permitted in crypto/internal/boring without pulling
// crypto/cipher's entropy-bearing constructors into pure delegates.
var AllowedPureBoringCipherSelectors = map[string]bool{
	"AEAD":  true,
	"Block": true,
}

// AllowedPureFIPS140OnlyFIPSSelectors lists the selectors on "crypto/fips140"
// permitted in crypto/internal/fips140only.
var AllowedPureFIPS140OnlyFIPSSelectors = map[string]bool{
	"Enforced": true,
}

// AllowedPureFIPS140OnlyDRBGSelectors lists the type/predicate selectors on
// "crypto/internal/fips140/drbg" permitted in crypto/internal/fips140only
// (excluding entropy-reading drbg.Read).
var AllowedPureFIPS140OnlyDRBGSelectors = map[string]bool{
	"DefaultReader":   true,
	"IsDefaultReader": true,
}

// AllowedPureSHAGodebugSettings lists the hardware-acceleration toggle literals
// permitted in crypto/internal/fips140/sha256 and sha512 via
// crypto/internal/fips140deps/godebug.Value.
var AllowedPureSHAGodebugSettings = map[string]bool{
	`"#ppc64sha2"`:   true,
	`"#ppc64sha512"`: true,
}

// AllowedPureFmtSelectors lists the closed set of value-formatting and
// interface/scanner selectors on "fmt" permitted in pure and pure-delegate
// packages (excluding ambient stdio Print*, Scan*).
var AllowedPureFmtSelectors = map[string]bool{
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

// AllowedPureMathSelectors lists the closed IEEE-754 bit/rounding/elementary
// selectors on "math" permitted in pure and pure-delegate packages (excluding
// platform-libm-sensitive transcendental functions).
var AllowedPureMathSelectors = map[string]bool{
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

// AllowedPureReflectSelectors lists the closed set of selectors on "reflect"
// permitted in pure and pure-delegate packages (excluding MakeFunc, Select, and
// reflective call/method-by-name dispatch).
var AllowedPureReflectSelectors = map[string]bool{
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

// AllowedPureFilepathliteSyscallSelectors lists the selectors on "syscall"
// permitted in internal/filepathlite.
var AllowedPureFilepathliteSyscallSelectors = map[string]bool{
	"UTF16PtrFromString": true,
}

// AllowedPureFilepathliteWindowsSelectors lists the selectors on
// "internal/syscall/windows" permitted in internal/filepathlite.
var AllowedPureFilepathliteWindowsSelectors = map[string]bool{
	"RtlIsDosDeviceName_U": true,
}

// AllowedPureMathRandSelectors lists the selectors on "math/rand" permitted in
// math/big (type Rand and deterministic local PRNG constructors New/NewSource).
var AllowedPureMathRandSelectors = map[string]bool{
	"New":       true,
	"NewSource": true,
	"Rand":      true,
}

// AllowedPureRuntimeSelectors lists the selectors on "runtime" permitted when a
// pure or pure-delegate package imports "runtime".
var AllowedPureRuntimeSelectors = map[string]bool{
	"Caller":    true,
	"FuncForPC": true,
	"GOARCH":    true,
	"GOOS":      true,
	"Goexit":    true,
	"KeepAlive": true,
}

// AllowedPureSyncSelectors lists the closed set of synchronization primitives
// on "sync" permitted in pure and pure-delegate packages for internal memos and
// pools.
var AllowedPureSyncSelectors = map[string]bool{
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

// AllowedPureSyncAtomicSelectors lists the closed set of primitives on
// "sync/atomic" permitted in pure and pure-delegate packages (excluding
// arbitrary-value atomic.Value and generic atomic.Pointer).
var AllowedPureSyncAtomicSelectors = map[string]bool{
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

// AllowedPureTimeSelectors lists the closed set of pure value, layout, and
// deterministic parsing selectors on "time" permitted in pure and pure-delegate
// packages (excluding Now, Since, Until, Local, LoadLocation*, timers, Sleep,
// and unchained Unix* local-zone constructors).
var AllowedPureTimeSelectors = map[string]bool{
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

// IsPureSupportImport reports whether importPath is an approved support import
// for pkgPath under a closed selector allowlist.
func IsPureSupportImport(pkgPath, importPath string) bool {
	if importPath == "unsafe" || AllowedPureSupportImports[importPath] {
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

// ForbiddenPureImport reports whether importPath is forbidden in pure or
// pure-delegate package pkgPath.
func ForbiddenPureImport(pkgPath, importPath string) bool {
	if importPath == "" || importPath == "C" || strings.HasPrefix(importPath, ".") {
		return true
	}
	if first, _, _ := strings.Cut(importPath, "/"); strings.Contains(first, ".") {
		return true
	}
	if IsPureSupportImport(pkgPath, importPath) || auditset.PurePackage(importPath) {
		return false
	}
	if auditset.AlwaysExternalPackage(importPath) || auditset.ClassBPackage(importPath) {
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

type pureSupportSelectorRule struct {
	localIdent string
	allowed    map[string]bool
	errFormat  string
}

func pureSupportSelectorRules() map[string]pureSupportSelectorRule {
	return map[string]pureSupportSelectorRule{
		"time": {
			localIdent: "time",
			allowed:    AllowedPureTimeSelectors,
			errFormat:  "%s: forbidden ambient time.%s reference",
		},
		"math/rand": {
			localIdent: "rand",
			allowed:    AllowedPureMathRandSelectors,
			errFormat:  "%s: forbidden global rand.%s reference",
		},
		"runtime": {
			localIdent: "runtime",
			allowed:    AllowedPureRuntimeSelectors,
			errFormat:  "%s: forbidden runtime.%s reference",
		},
		"fmt": {
			localIdent: "fmt",
			allowed:    AllowedPureFmtSelectors,
			errFormat:  "%s: forbidden ambient fmt.%s reference",
		},
		"math": {
			localIdent: "math",
			allowed:    AllowedPureMathSelectors,
			errFormat:  "%s: forbidden math.%s reference",
		},
		"reflect": {
			localIdent: "reflect",
			allowed:    AllowedPureReflectSelectors,
			errFormat:  "%s: forbidden reflect.%s reference",
		},
		"sync": {
			localIdent: "sync",
			allowed:    AllowedPureSyncSelectors,
			errFormat:  "%s: forbidden sync.%s reference",
		},
		"sync/atomic": {
			localIdent: "atomic",
			allowed:    AllowedPureSyncAtomicSelectors,
			errFormat:  "%s: forbidden atomic.%s reference",
		},
		"crypto/internal/fips140": {
			localIdent: "fips140",
			allowed:    AllowedPureCryptoInternalFIPS140Selectors,
			errFormat:  "%s: forbidden fips140.%s reference",
		},
		"crypto/cipher": {
			localIdent: "cipher",
			allowed:    AllowedPureBoringCipherSelectors,
			errFormat:  "%s: forbidden cipher.%s reference",
		},
		"crypto/fips140": {
			localIdent: "fips140",
			allowed:    AllowedPureFIPS140OnlyFIPSSelectors,
			errFormat:  "%s: forbidden crypto/fips140.%s reference",
		},
		"crypto/internal/fips140/drbg": {
			localIdent: "drbg",
			allowed:    AllowedPureFIPS140OnlyDRBGSelectors,
			errFormat:  "%s: forbidden drbg.%s reference",
		},
		"crypto/internal/fips140deps/godebug": {
			localIdent: "godebug",
			allowed:    nil,
			errFormat:  "%s: forbidden godebug.%s reference",
		},
		"syscall": {
			localIdent: "syscall",
			allowed:    AllowedPureFilepathliteSyscallSelectors,
			errFormat:  "%s: forbidden syscall.%s reference",
		},
		"internal/syscall/windows": {
			localIdent: "windows",
			allowed:    AllowedPureFilepathliteWindowsSelectors,
			errFormat:  "%s: forbidden windows.%s reference",
		},
		"os": {
			localIdent: "os",
			allowed:    map[string]bool{"Stderr": true},
			errFormat:  "%s: forbidden os.%s reference",
		},
	}
}

// VerifyPurePackageAST verifies that a pure or pure-delegate standard-library
// package's AST files obey the closed import and support-selector rules.
func VerifyPurePackageAST(pkgPath string, files []*ast.File) error {
	rules := pureSupportSelectorRules()
	for _, f := range files {
		activeRules := map[string]pureSupportSelectorRule{}
		var activeRulePaths []string
		for _, imp := range f.Imports {
			importPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			if ForbiddenPureImport(pkgPath, importPath) {
				return fmt.Errorf("%s: forbidden import %q in pure package", pkgPath, importPath)
			}
			if importPath == "unsafe" {
				if imp.Name != nil && imp.Name.Name != "_" {
					return fmt.Errorf("%s: aliased import \"unsafe\" (%s) forbidden in pure package", pkgPath, imp.Name.Name)
				}
				continue
			}
			if IsPureSupportImport(pkgPath, importPath) && imp.Name != nil {
				return fmt.Errorf("%s: aliased import %q (%s) forbidden in pure package", pkgPath, importPath, imp.Name.Name)
			}
			if rule, ok := rules[importPath]; ok {
				if _, exists := activeRules[importPath]; !exists {
					activeRules[importPath] = rule
					activeRulePaths = append(activeRulePaths, importPath)
				}
			}
		}

		_, importsSync := activeRules["sync"]
		_, importsAtomic := activeRules["sync/atomic"]
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

		if len(activeRules) > 0 {
			_, importsTime := activeRules["time"]
			_, importsMathRand := activeRules["math/rand"]
			_, importsOS := activeRules["os"]
			_, importsReflect := activeRules["reflect"]
			_, importsSHAGodebug := activeRules["crypto/internal/fips140deps/godebug"]

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
								if lit, ok := node.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING && AllowedPureSHAGodebugSettings[lit.Value] {
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
						for _, impPath := range activeRulePaths {
							rule := activeRules[impPath]
							if id.Name != rule.localIdent {
								continue
							}
							if rule.allowed[node.Sel.Name] {
								continue
							}
							if impPath == "time" && allowedTimeUnixUTC[node] {
								continue
							}
							if impPath == "math/rand" && paramRandAllowed[node] {
								continue
							}
							if impPath == "crypto/internal/fips140deps/godebug" && allowedGodebugValue[node] {
								continue
							}
							violation = fmt.Errorf(rule.errFormat, pkgPath, node.Sel.Name)
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
