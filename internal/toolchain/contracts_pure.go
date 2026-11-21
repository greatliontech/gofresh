package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/internal/auditset"
)

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

// appendPolicyPackages appends all pure-delegate support import and selector
// policy tables into packages using the canonical policy digest keys.
func appendPolicyPackages(packages map[string]bool) {
	for k, v := range allowedPureSupportImports {
		packages["pure-import:"+k] = v
	}
	for k, v := range allowedPureCryptoInternalFIPS140Selectors {
		packages["pure-fips140-allow:"+k] = v
	}
	for k, v := range allowedPureBoringCipherSelectors {
		packages["pure-boring-cipher-allow:"+k] = v
	}
	for k, v := range allowedPureFIPS140OnlyFIPSSelectors {
		packages["pure-fips140only-fips-allow:"+k] = v
	}
	for k, v := range allowedPureFIPS140OnlyDRBGSelectors {
		packages["pure-fips140only-drbg-allow:"+k] = v
	}
	for k, v := range allowedPureSHAGodebugSettings {
		packages["pure-sha-godebug-allow:"+k] = v
	}
	for k, v := range allowedPureFmtSelectors {
		packages["pure-fmt-allow:"+k] = v
	}
	for k, v := range allowedPureMathSelectors {
		packages["pure-math-allow:"+k] = v
	}
	for k, v := range allowedPureReflectSelectors {
		packages["pure-reflect-allow:"+k] = v
	}
	for k, v := range allowedPureFilepathliteSyscallSelectors {
		packages["pure-filepathlite-syscall-allow:"+k] = v
	}
	for k, v := range allowedPureFilepathliteWindowsSelectors {
		packages["pure-filepathlite-windows-allow:"+k] = v
	}
	for k, v := range allowedPureMathRandSelectors {
		packages["pure-rand-allow:"+k] = v
	}
	for k, v := range allowedPureRuntimeSelectors {
		packages["pure-runtime-allow:"+k] = v
	}
	for k, v := range allowedPureSyncSelectors {
		packages["pure-sync-allow:"+k] = v
	}
	for k, v := range allowedPureSyncAtomicSelectors {
		packages["pure-sync-atomic-allow:"+k] = v
	}
	for k, v := range allowedPureTimeSelectors {
		packages["pure-time-allow:"+k] = v
	}
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
	"Enforced": auditset.Symbol("crypto/fips140", "Enforced"),
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

func derivePureSelectorsFromAuditset(base []string, stdlibInternalExtras ...string) map[string]bool {
	out := make(map[string]bool, len(base)+len(stdlibInternalExtras))
	for _, sym := range base {
		out[sym] = true
	}
	for _, sym := range stdlibInternalExtras {
		out[sym] = true
	}
	return out
}

// allowedPureFmtSelectors derives the closed set of value-formatting and
// interface/scanner selectors on "fmt" permitted in pure and pure-delegate
// packages from auditset.PackageSymbols("fmt") plus writer-first Fprint*
// (excluding ambient stdio Print* and Scan*/Fscan*).
var allowedPureFmtSelectors = derivePureSelectorsFromAuditset(
	auditset.PackageSymbols("fmt"),
	"Fprint", "Fprintf", "Fprintln",
)

// allowedPureMathSelectors derives the closed IEEE-754 bit/rounding/elementary
// selectors on "math" permitted in pure and pure-delegate packages from
// auditset.PackageSymbols("math") plus Log10 and Log2 (used internally by
// encoding/json/v2 and math/big).
var allowedPureMathSelectors = derivePureSelectorsFromAuditset(
	auditset.PackageSymbols("math"),
	"Log10", "Log2",
)

// allowedPureReflectSelectors derives the closed set of selectors on "reflect"
// permitted in pure and pure-delegate packages from auditset.PackageSymbols("reflect")
// plus internal value/container helpers used by encoding/* (excluding MakeFunc,
// Select, and reflective call/method-by-name dispatch).
var allowedPureReflectSelectors = derivePureSelectorsFromAuditset(
	auditset.PackageSymbols("reflect"),
	"Append", "Bytes", "Copy", "Indirect", "Interface",
	"MakeMap", "MakeMapWithSize", "MakeSlice", "MapOf",
	"New", "Pointer", "PointerTo", "Ptr", "Slice", "SliceOf",
	"TypeAssert", "TypeFor", "UnsafePointer", "Value", "ValueOf", "Zero",
)

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

// allowedPureMathRandSelectors derives the selectors on "math/rand" permitted
// in math/big directly from auditset.PackageSymbols("math/rand") (explicit-seed
// local PRNG constructors New/NewSource and Rand/Source/Source64 types;
// top-level unseeded sampling functions and transcendental distributions remain
// excluded).
var allowedPureMathRandSelectors = derivePureSelectorsFromAuditset(
	auditset.PackageSymbols("math/rand"),
)

// allowedPureRuntimeSelectors derives the selectors on "runtime" permitted when
// a pure or pure-delegate package imports "runtime" from
// auditset.PackageSymbols("runtime") plus internal stack/liveness helpers.
var allowedPureRuntimeSelectors = derivePureSelectorsFromAuditset(
	auditset.PackageSymbols("runtime"),
	"Caller", "FuncForPC", "Goexit", "KeepAlive",
)

// allowedPureSyncSelectors derives the closed set of synchronization primitives
// on "sync" permitted in pure and pure-delegate packages from
// auditset.SyncTopLevelSymbols() plus internal OnceFunc/OnceValue/OnceValues
// and WaitGroup helpers.
var allowedPureSyncSelectors = derivePureSelectorsFromAuditset(
	auditset.SyncTopLevelSymbols(),
	"OnceFunc", "OnceValue", "OnceValues", "WaitGroup",
)

// allowedPureSyncAtomicSelectors derives the closed set of primitives on
// "sync/atomic" permitted in pure and pure-delegate packages from
// auditset.PackageSymbols("sync/atomic") plus internal pointer load/CAS helpers
// (excluding arbitrary-value atomic.Value and generic atomic.Pointer).
var allowedPureSyncAtomicSelectors = derivePureSelectorsFromAuditset(
	auditset.PackageSymbols("sync/atomic"),
	"CompareAndSwapPointer", "LoadPointer",
)

// allowedPureTimeSelectors derives the closed set of pure value, layout, and
// deterministic parsing selectors on "time" permitted in pure and pure-delegate
// packages from auditset.PackageSymbols("time") plus internal Location, Parse,
// ParseError, and UTC selectors used by encoding/* (excluding Now, Since,
// Until, Local, LoadLocation*, timers, Sleep, and unchained Unix* constructors).
var allowedPureTimeSelectors = derivePureSelectorsFromAuditset(
	auditset.PackageSymbols("time"),
	"Location", "Parse", "ParseError", "UTC",
)

// isPureSupportImport reports whether importPath is an approved support import
// for pkgPath under a closed selector allowlist.
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

// forbiddenPureImport reports whether importPath is forbidden in pure or
// pure-delegate package pkgPath.
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
			allowed:    allowedPureTimeSelectors,
			errFormat:  "%s: forbidden ambient time.%s reference",
		},
		"math/rand": {
			localIdent: "rand",
			allowed:    allowedPureMathRandSelectors,
			errFormat:  "%s: forbidden global rand.%s reference",
		},
		"runtime": {
			localIdent: "runtime",
			allowed:    allowedPureRuntimeSelectors,
			errFormat:  "%s: forbidden runtime.%s reference",
		},
		"fmt": {
			localIdent: "fmt",
			allowed:    allowedPureFmtSelectors,
			errFormat:  "%s: forbidden ambient fmt.%s reference",
		},
		"math": {
			localIdent: "math",
			allowed:    allowedPureMathSelectors,
			errFormat:  "%s: forbidden math.%s reference",
		},
		"reflect": {
			localIdent: "reflect",
			allowed:    allowedPureReflectSelectors,
			errFormat:  "%s: forbidden reflect.%s reference",
		},
		"sync": {
			localIdent: "sync",
			allowed:    allowedPureSyncSelectors,
			errFormat:  "%s: forbidden sync.%s reference",
		},
		"sync/atomic": {
			localIdent: "atomic",
			allowed:    allowedPureSyncAtomicSelectors,
			errFormat:  "%s: forbidden atomic.%s reference",
		},
		"crypto/internal/fips140": {
			localIdent: "fips140",
			allowed:    allowedPureCryptoInternalFIPS140Selectors,
			errFormat:  "%s: forbidden fips140.%s reference",
		},
		"crypto/cipher": {
			localIdent: "cipher",
			allowed:    allowedPureBoringCipherSelectors,
			errFormat:  "%s: forbidden cipher.%s reference",
		},
		"crypto/fips140": {
			localIdent: "fips140",
			allowed:    allowedPureFIPS140OnlyFIPSSelectors,
			errFormat:  "%s: forbidden crypto/fips140.%s reference",
		},
		"crypto/internal/fips140/drbg": {
			localIdent: "drbg",
			allowed:    allowedPureFIPS140OnlyDRBGSelectors,
			errFormat:  "%s: forbidden drbg.%s reference",
		},
		"crypto/internal/fips140deps/godebug": {
			localIdent: "godebug",
			allowed:    nil,
			errFormat:  "%s: forbidden godebug.%s reference",
		},
		"syscall": {
			localIdent: "syscall",
			allowed:    allowedPureFilepathliteSyscallSelectors,
			errFormat:  "%s: forbidden syscall.%s reference",
		},
		"internal/syscall/windows": {
			localIdent: "windows",
			allowed:    allowedPureFilepathliteWindowsSelectors,
			errFormat:  "%s: forbidden windows.%s reference",
		},
		"os": {
			localIdent: "os",
			allowed:    map[string]bool{"Stderr": true},
			errFormat:  "%s: forbidden os.%s reference",
		},
	}
}

// verifyPurePackageAST verifies that a pure or pure-delegate standard-library
// package's AST files obey the closed import and support-selector rules.
func verifyPurePackageAST(pkgPath string, files []*ast.File) error {
	rules := pureSupportSelectorRules()
	for _, f := range files {
		activeRules := map[string]pureSupportSelectorRule{}
		var activeRulePaths []string
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
