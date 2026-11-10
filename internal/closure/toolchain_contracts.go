package closure

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/closure/internal/cprep"
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
	var readCache map[string]trackedFileRead
	if lp.digest != "" {
		readCache = make(map[string]trackedFileRead, len(lp.Files))
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
			raw, err := readPackageFileTracked(lp.Dir, name, readCache)
			if err != nil {
				return offSurfaceVerdict{}, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
			}
			if ext == ".syso" {
				cprep.CollectRawBytesRuntimeSymbolRefs(raw, directRuntime)
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
		src, err := readPackageFileTracked(lp.Dir, name, readCache)
		if err != nil {
			return offSurfaceVerdict{}, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		text := string(src)
		scanOffSurfaceGoDirectives(text, directRuntime, func(localSym, target string) {
			linkDirectives = append(linkDirectives, twoArgLink{localSym: localSym, target: target})
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
			return offSurfaceVerdict{}, iErr
		}
		if vErr != nil {
			directRuntime["runtime.*"] = true
		} else {
			if cprep.ScanPreprocessedNonGoSymbolRefs(lp.ImportPath, incHdrs, nonGoTexts, directRuntime, extAsm, nil) {
				directRuntime["runtime.*"] = true
			}
			for ext := range extAsm {
				if tPkg, tSym, ok := cprep.SplitLinknameTarget(ext); ok && tPkg != lp.ImportPath {
					seedCrossMap[offSurfaceCrossEdge{Pkg: tPkg, Sym: tSym}] = true
				}
			}
		}
	}
	if lp.digest != "" {
		curDigest, err := verifyReadPackageDigest(ctx, lp, readCache)
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
		tPkg, tSym, ok := cprep.SplitLinknameTarget(ld.target)
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
	type pkgSel struct {
		pkg string
		sel string
	}
	visited := map[workItem]bool{}
	var queue []workItem
	pkgReachedTypes := map[string]map[string]bool{}
	pkgReachedSels := map[string]map[string]bool{}
	globalExportedSels := map[string]bool{}
	pendingByPkgSel := map[pkgSel][]string{}
	pendingByExportedSel := map[string][]workItem{}

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
				ps := pkgSel{pkg: pkg, sel: sel}
				for _, mDecl := range pendingByPkgSel[ps] {
					enqueue(pkg, mDecl)
				}
				delete(pendingByPkgSel, ps)
			}
		}
		if ast.IsExported(sel) && !globalExportedSels[sel] {
			globalExportedSels[sel] = true
			for _, wi := range pendingByExportedSel[sel] {
				enqueue(wi.pkg, wi.decl)
			}
			delete(pendingByExportedSel, sel)
		}
	}

	enqueueCross := func(rawPkg, sym string) {
		if rawPkg == "runtime" {
			if base := cprep.LeadingASCIIIdent(sym); base != "" {
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
				mBase := cprep.LeadingASCIIIdent(methodPart)
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
			if !pkgReachedTypes[item.pkg][item.decl] {
				pkgReachedTypes[item.pkg][item.decl] = true
				for _, m := range methods {
					mDecl := "method:" + item.decl + "." + m
					if pkgReachedSels[item.pkg][m] || (ast.IsExported(m) && globalExportedSels[m]) {
						enqueue(item.pkg, mDecl)
						continue
					}
					ps := pkgSel{pkg: item.pkg, sel: m}
					pendingByPkgSel[ps] = append(pendingByPkgSel[ps], mDecl)
					if ast.IsExported(m) {
						pendingByExportedSel[m] = append(pendingByExportedSel[m], workItem{pkg: item.pkg, decl: mDecl})
					}
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

	activeStateCands := map[string]atomicStateCand{}
	allowedIdentsByState := map[string]map[*ast.Ident]bool{}
	mutatorSetByState := map[string]map[string]bool{}
	for sName, cand := range stateCands {
		if pkgDeclCounts[sName] != 1 || anyLinknameLocal[sName] || aliasedRuntimeSym[sName] || nonGoIdents[sName] {
			continue
		}
		activeStateCands[sName] = cand
		allowedIdentsByState[sName] = map[*ast.Ident]bool{cand.declIdent: true}
		mutatorSetByState[sName] = map[string]bool{}
	}

	verifiedStateMutators := map[string][]string{}
	verifiedStateIsBool := map[string]bool{}
	if len(activeStateCands) > 0 {
		nonSelPropIdents := map[string][]*ast.Ident{}
		var collectNonSel func(n ast.Node) bool
		collectNonSel = func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.SelectorExpr:
				ast.Inspect(node.X, collectNonSel)
				return false
			case *ast.Ident:
				nonSelPropIdents[node.Name] = append(nonSelPropIdents[node.Name], node)
				return false
			default:
				return true
			}
		}
		for _, f := range files {
			ast.Inspect(f, collectNonSel)
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				var shadowed map[string]bool
				shadows := func(name string) bool {
					if shadowed == nil {
						shadowed = map[string]bool{}
						if r := recvVarName(fn); r != "" {
							shadowed[r] = true
						}
						if fn.Type != nil {
							for _, fl := range []*ast.FieldList{fn.Type.TypeParams, fn.Type.Params, fn.Type.Results} {
								if fl == nil {
									continue
								}
								for _, fld := range fl.List {
									for _, id := range fld.Names {
										shadowed[id.Name] = true
									}
								}
							}
						}
						ast.Inspect(fn.Body, func(n ast.Node) bool {
							if n == nil {
								return false
							}
							switch node := n.(type) {
							case *ast.ValueSpec:
								for _, id := range node.Names {
									shadowed[id.Name] = true
								}
							case *ast.TypeSpec:
								if node.Name != nil {
									shadowed[node.Name.Name] = true
								}
								if node.TypeParams != nil {
									for _, fld := range node.TypeParams.List {
										for _, id := range fld.Names {
											shadowed[id.Name] = true
										}
									}
								}
							case *ast.FuncLit:
								if node.Type != nil {
									for _, fl := range []*ast.FieldList{node.Type.Params, node.Type.Results} {
										if fl == nil {
											continue
										}
										for _, fld := range fl.List {
											for _, id := range fld.Names {
												shadowed[id.Name] = true
											}
										}
									}
								}
							case *ast.AssignStmt:
								if node.Tok == token.DEFINE {
									for _, lhs := range node.Lhs {
										if id, ok := unwrapParens(lhs).(*ast.Ident); ok {
											shadowed[id.Name] = true
										}
									}
								}
							case *ast.RangeStmt:
								if node.Tok == token.DEFINE {
									if id, ok := unwrapParens(node.Key).(*ast.Ident); ok {
										shadowed[id.Name] = true
									}
									if id, ok := unwrapParens(node.Value).(*ast.Ident); ok {
										shadowed[id.Name] = true
									}
								}
							}
							return true
						})
					}
					return shadowed[name]
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
					if !okID {
						return true
					}
					cand, isCand := activeStateCands[baseID.Name]
					if !isCand || shadows(baseID.Name) || shadows("false") {
						return true
					}
					switch {
					case sel.Sel.Name == "Load" && len(call.Args) == 0:
						allowedIdentsByState[baseID.Name][baseID] = true
					case sel.Sel.Name == "Store" && len(call.Args) == 1:
						isZero := (!cand.isBool && isZeroIntLit(call.Args[0]))
						if cand.isBool {
							_, isZero = isIdentNamed(call.Args[0], "false")
						}
						if isZero {
							allowedIdentsByState[baseID.Name][baseID] = true
						} else if fn.Recv == nil && fn.Name != nil && !ast.IsExported(fn.Name.Name) && fn.Name.Name != "init" {
							allowedIdentsByState[baseID.Name][baseID] = true
							mutatorSetByState[baseID.Name][fn.Name.Name] = true
						}
					}
					return true
				})
			}
		}

		allAllowed := func(name string, allowed map[*ast.Ident]bool) bool {
			for _, id := range nonSelPropIdents[name] {
				if !allowed[id] {
					return false
				}
			}
			return true
		}

		for sName, cand := range activeStateCands {
			if !allAllowed(sName, allowedIdentsByState[sName]) {
				continue
			}
			mutatorSet := mutatorSetByState[sName]
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
				if !mutatorsValid || !allAllowed(mName, map[*ast.Ident]bool{mFn.Name: true}) {
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

var pureSupportSelectorRules = map[string]pureSupportSelectorRule{
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

func verifyPurePackageAST(pkgPath string, files []*ast.File) error {
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
			if rule, ok := pureSupportSelectorRules[importPath]; ok {
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
