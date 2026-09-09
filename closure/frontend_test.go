package closure

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The analyzing frontend is spelled once and every persistent memo
// scope holding a frontend derivation composes it — the three
// syntax-level scopes and the four type-level ones (through the shared
// guard key); the listing memo, the analyzed toolchain's own account,
// does not — while the closure identity excludes it by design and the
// composed identity strategy is pinned as a conscious golden, so a
// reverted bump cannot pass unseen. The source half of the pin walks the
// closure package and its internal packages for any other spelling of
// runtime.Version, allowing only the helper, the toolchain audit's own
// key sites, and the selection degradation; that half observes the
// tree, so an overlay probe never reaches it — the value half above
// carries the probe-able claims (REQ-closure-identity-strategy).
func TestMemoScopesKeyOnTheOneFrontendSpelling(t *testing.T) {
	frontend := runtime.Version()
	if AnalyzingFrontend() != frontend {
		t.Fatalf("AnalyzingFrontend = %q, want %q", AnalyzingFrontend(), frontend)
	}
	if canonicalScope() != canonicalStrategy+" "+frontend || variantParseScope() != variantParseStrategy+" "+frontend {
		t.Fatalf("syntax memo scopes %q, %q do not compose the frontend %q", canonicalScope(), variantParseScope(), frontend)
	}
	if got := (&Hasher{selectionResolved: true}).effectScanScope(); !strings.HasPrefix(got, effectScanStrategy+" "+frontend) {
		t.Fatalf("effect scan scope %q does not compose the frontend", got)
	}
	scope := AnalysisScope{Toolchain: "go1.x", BuildConfig: "cfg", ProofStrategy: "proofs@1", FactStrategy: "facts@1"}
	for name, value := range map[string]string{"Proofs": scope.Proofs(), "TestingScan": scope.TestingScan(), "Facts": scope.Facts(), "Scan": scope.Scan()} {
		if !strings.Contains(value, "|"+frontend) {
			t.Errorf("type-level memo scope %s = %q does not compose the frontend", name, value)
		}
	}
	if strings.Contains(IdentityStrategy, frontend) {
		t.Fatalf("the identity strategy %q composes the analyzing frontend", IdentityStrategy)
	}
	if want := "gofresh/closure@1 gofresh/canonical-member@2 gofresh/variant-parse@1"; IdentityStrategy != want {
		t.Fatalf("the identity strategy is %q, want the composed %q — a derivation moved, or a bump was reverted; update the golden consciously", IdentityStrategy, want)
	}
	allowed := map[string]bool{"AnalyzingFrontend": true, "auditedToolchainSource": true, "ToolchainSelectionNotice": true, "NewAtContextEnvSnapshot": true}
	tracked := map[string]bool{"canonicalScope": false, "effectScanScope": false, "variantParseScope": false, "guards": false}
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != "." && !strings.HasPrefix(path, "internal") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return err
		}
		// The whole file is walked — package-level initializers included
		// — with the enclosing function tracked, and every mention of
		// runtime.Version counts, called or not.
		var enclosing []string
		ast.Inspect(f, func(n ast.Node) bool {
			if n == nil {
				enclosing = enclosing[:len(enclosing)-1]
				return false
			}
			name := "<package level>"
			if fn, ok := n.(*ast.FuncDecl); ok {
				name = fn.Name.Name
			} else if len(enclosing) > 0 {
				name = enclosing[len(enclosing)-1]
			}
			enclosing = append(enclosing, name)
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == "runtime" && sel.Sel.Name == "Version" && !allowed[name] {
					t.Errorf("%s: %s spells runtime.Version outside the frontend helper and the toolchain audit", path, name)
				}
			}
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "AnalyzingFrontend" {
					if _, isTracked := tracked[name]; isTracked {
						tracked[name] = true
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for scope, reads := range tracked {
		if !reads {
			t.Errorf("memo scope %s does not read AnalyzingFrontend", scope)
		}
	}
}
