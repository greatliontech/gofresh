package closure

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
)

func selectedSourceFixtureBinder(t *testing.T, source computationSource) *selectedSourceBinder {
	t.Helper()
	limits := defaultComputationRelationLimits()
	b, err := newSelectedSourceBinder(t.Context(), source, source.prog.Roots["F"], selectedSourceLimits{work: limits.work, depth: limits.depth, bytes: limits.bytes})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSelectedSourceOwnerBinding(t *testing.T) {
	for _, mode := range []string{"program", "package", "syntax", "copied-declaration", "object", "sizes", "fset", "file", "duplicate-package"} {
		t.Run(mode, func(t *testing.T) {
			s := relationFixture(t, "func F(x int32)int32{return x}", 64)
			other := relationFixture(t, "func F(x int32)int32{return x}", 64)
			root, p := s.prog.Roots["F"], s.prog.Pkgs[0]
			switch mode {
			case "program":
				root = other.prog.Roots["F"]
			case "package":
				root.Pkg = other.prog.Roots["F"].Pkg
			case "syntax":
				p.Syntax = other.prog.Pkgs[0].Syntax
			case "copied-declaration":
				decl := *p.Syntax[0].Decls[0].(*ast.FuncDecl)
				p.Syntax[0].Decls[0] = &decl
			case "object":
				decl := p.Syntax[0].Decls[0].(*ast.FuncDecl)
				p.TypesInfo.Defs[decl.Name] = other.prog.Roots["F"].Object()
			case "sizes":
				p.TypesSizes = nil
			case "fset":
				p.Fset = other.prog.Pkgs[0].Fset
			case "file":
				p.CompiledGoFiles[0] = "/foreign/p.go"
			case "duplicate-package":
				s.prog.Pkgs = append(s.prog.Pkgs, p)
			}
			limits := selectedSourceLimits{work: 262144, depth: 128, bytes: 16 << 20}
			b, err := newSelectedSourceBinder(t.Context(), s, root, limits)
			if err == nil {
				_, err = b.bindDeclaration(root)
			}
			if err == nil {
				t.Fatal("cross-owner or incomplete binding accepted")
			}
		})
	}
	// A pointer-copy package with identical labels must not enter the cache.
	s := relationFixture(t, "func F(x int32)int32{return x}", 64)
	b := selectedSourceFixtureBinder(t, s)
	p := *s.prog.Pkgs[0]
	if _, err := b.selectedPackage(s.prog.Roots["F"], &p); err == nil {
		t.Fatal("equal package labels replaced selected loader identity")
	}
}

func TestSelectedSourceBindingHasNoScalarInterfacePolicy(t *testing.T) {
	s := relationFixture(t, "func F(p *int){}", 32)
	b := selectedSourceFixtureBinder(t, s)
	bound, err := b.bindDeclaration(s.prog.Roots["F"])
	if err != nil || bound.pkg != s.prog.Pkgs[0] || bound.decl != s.prog.Roots["F"].Syntax() {
		t.Fatal("pointer/void declaration could not be bound", err)
	}
	// This supplies no interpretation of the pointer or proof of non-use; that
	// requires the consuming grammar's actual instruction walk.
}

func TestSelectedSourceAbsoluteListingPaths(t *testing.T) {
	s := relationFixture(t, "func F(x int32)int32{return x}", 64)
	root, pkg := s.prog.Roots["F"], s.prog.Pkgs[0]
	if !filepath.IsAbs(pkg.CompiledGoFiles[0]) {
		t.Fatal("fixture must supply a platform-absolute source path")
	}
	want, err := selectedSourceFixtureBinder(t, s).bindDeclaration(root)
	if err != nil {
		t.Fatal(err)
	}
	for i := range s.metas {
		if s.metas[i].ImportPath == pkg.ID {
			s.metas[i].GoFiles = slices.Clone(pkg.CompiledGoFiles)
		}
	}
	got, err := selectedSourceFixtureBinder(t, s).bindDeclaration(root)
	if err != nil || got.identity != want.identity || got.decl != want.decl {
		t.Fatalf("absolute and relative listing identities disagree: %v", err)
	}
	for i := range s.metas {
		if s.metas[i].ImportPath == pkg.ID {
			s.metas[i].GoFiles[0] = filepath.Join(filepath.Dir(pkg.CompiledGoFiles[0]), "other.go")
		}
	}
	if _, err := selectedSourceFixtureBinder(t, s).bindDeclaration(root); err == nil {
		t.Fatal("a different absolute listing path acquired the original declaration")
	}
}

func TestSelectedSourceDirectiveInventoryCoversSyntaxAndComments(t *testing.T) {
	for _, mode := range []string{"attached", "unattached", "both"} {
		t.Run(mode, func(t *testing.T) {
			s := relationFixture(t, "//go:noinline\nfunc F(x int32)int32{return x}", 64)
			file := s.prog.Pkgs[0].Syntax[0]
			decl := file.Decls[0].(*ast.FuncDecl)
			switch mode {
			case "attached":
				file.Comments = nil
			case "unattached":
				decl.Doc = nil
			}
			b := selectedSourceFixtureBinder(t, s)
			bound, err := b.bindDeclaration(s.prog.Roots["F"])
			if err != nil {
				t.Fatal(err)
			}
			got := b.packages[bound.pkg].directives
			if len(got) != 1 || got[0].text != "//go:noinline" {
				t.Fatalf("inventory: %+v", got)
			}
			scope, inputs := relationInputs(t, s)
			if r, err := deriveComputationRelation(t.Context(), s, s.prog.Roots["F"], scope, inputs, computationRelationLimits{}); r != nil || err == nil {
				t.Fatal("directive inventory bypassed independent scalar policy")
			}
		})
	}
}

func TestSelectedSourceInventoryIsNotScalarAuthority(t *testing.T) {
	for _, mode := range []string{"assembly", "directive", "linkname", "bodyless", "effect"} {
		t.Run(mode, func(t *testing.T) {
			text := "func F(x int32)int32{return x}"
			switch mode {
			case "directive":
				text = "//go:noinline\n" + text
			case "linkname":
				text = "//go:linkname F external.F\n" + text
			case "bodyless":
				text = "func F(x int32)int32"
			case "effect":
				text = "func F(x int32)int32{println(x);return x}"
			}
			s := relationFixture(t, text, 64)
			if mode == "assembly" {
				s.metas[0].SFiles = []string{"native.s"}
			}
			b := selectedSourceFixtureBinder(t, s)
			bound, err := b.bindDeclaration(s.prog.Roots["F"])
			if err != nil {
				t.Fatalf("identity imposed scalar policy: %v", err)
			}
			p := b.packages[bound.pkg]
			if mode == "assembly" && !slices.Equal(p.otherInputs, []selectedSourceInput{{"assembly", "native.s"}}) {
				t.Fatalf("native boundary inventory: %+v", p.otherInputs)
			}
			if mode == "directive" || mode == "linkname" {
				want, _, _ := strings.Cut(text, "\n")
				if len(p.directives) != 1 || p.directives[0].text != want || p.directives[0].at == token.NoPos {
					t.Fatalf("directive boundary inventory: %+v", p.directives)
				}
			}
			if mode == "bodyless" && bound.decl.Body != nil {
				t.Fatal("fabricated body")
			}
			scope, inputs := relationInputs(t, s)
			if r, err := deriveComputationRelation(t.Context(), s, s.prog.Roots["F"], scope, inputs, computationRelationLimits{}); r != nil || err == nil {
				t.Fatal("selected input identity acquired scalar authority")
			}
		})
	}
}

func TestSelectedSourceWarmCacheKeepsScalarPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, text, refusal string
	}{
		{"ordinary", "func F(x int32)int32{return x}", ""},
		{"assembly", "func F(x int32)int32{return x}", "opaque selected package inputs"},
		{"directive", "//go:noinline\nfunc F(x int32)int32{return x}", "unsupported local implementation directive"},
		{"linkname", "//go:linkname F external.F\nfunc F(x int32)int32{return x}", "unsupported local implementation directive"},
		{"bodyless", "func F(x int32)int32", "selected function body binding disagrees"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := relationFixture(t, tc.text, 32)
			if tc.name == "assembly" {
				s.metas[0].SFiles = []string{"native.s"}
			}
			b := selectedSourceFixtureBinder(t, s)
			root := s.prog.Roots["F"]
			bound, err := b.bindDeclaration(root)
			if err != nil {
				t.Fatal("identity cache warm-up", err)
			}
			work, bytes := b.work, b.bytes
			// Reuse the actual identity cache, but supply no previously checked
			// scalar relation. Inventory must not stand in for scalar policy.
			c := &computationRelationChecker{selectedSourceBinder: b, relations: map[*ssa.Function]computationRelationDependency{}}
			dep, pkg, err := c.bind(root)
			if tc.refusal != "" {
				if err == nil || !strings.Contains(err.Error(), tc.refusal) || len(c.relations) != 0 {
					t.Fatalf("warm identity bypassed scalar policy: %v", err)
				}
				if b.work != work || b.bytes != bytes {
					t.Fatal("policy refusal reconstructed the cached identity")
				}
				return
			}
			if err != nil || pkg != bound.pkg || dep.source != bound.identity.source || dep.body != bound.identity.body || dep.wordBits != 32 {
				t.Fatal("ordinary declaration failed with the warm identity cache", err)
			}
			if b.work <= work || c.work != b.work || b.bytes != bytes {
				t.Fatal("scalar body checking did not spend the shared counter")
			}
			// A second semantic check has the same cached identity and no work
			// remaining. It must fail in the body walk, not receive a fresh budget.
			b.limits.work = b.work
			c = &computationRelationChecker{selectedSourceBinder: b, relations: map[*ssa.Function]computationRelationDependency{}}
			if _, _, err := c.bind(root); err == nil || !strings.Contains(err.Error(), "work budget") || b.work != b.limits.work+1 {
				t.Fatalf("warm-cache scalar check reset the shared budget: %v", err)
			}
		})
	}
}

func TestSelectedSourceInitNeedsActualDeclaration(t *testing.T) {
	s := relationFixture(t, "var value int;func init(){value=7};func F(x int32)int32{return x}", 64)
	b := selectedSourceFixtureBinder(t, s)
	p := s.prog.Pkgs[0]
	var explicit *ssa.Function
	for _, d := range p.Syntax[0].Decls {
		if d, ok := d.(*ast.FuncDecl); ok && d.Name.Name == "init" {
			explicit = s.prog.Prog.FuncValue(p.TypesInfo.Defs[d.Name].(*types.Func))
		}
	}
	if explicit == nil {
		t.Fatal("fixture has no explicit init")
	}
	if _, err := b.bindDeclaration(explicit); err != nil {
		t.Fatal("actual init declaration", err)
	}
	generated := s.prog.Prog.Package(p.Types).Func("init")
	for _, label := range []string{generated.Synthetic, "", "package initializer", explicit.Synthetic} {
		generated.Synthetic = label
		if _, err := b.bindDeclaration(generated); err == nil {
			t.Fatal("synthetic label established generated init ownership")
		}
	}
	// A copied ordinary function retains every descriptive field, but lacks the
	// program's exact typed declaration binding.
	copy := *s.prog.Roots["F"]
	if _, err := b.bindDeclaration(&copy); err == nil {
		t.Fatal("copied SSA function borrowed declaration")
	}
}

func TestSelectedSourceCacheAndSharedBudget(t *testing.T) {
	s := relationFixture(t, "func helper(x int32)int32{return x};func F(x int32)int32{return helper(x)}", 32)
	b := selectedSourceFixtureBinder(t, s)
	root := s.prog.Roots["F"]
	bound, err := b.bindDeclaration(root)
	if err != nil {
		t.Fatal(err)
	}
	if bound.pkg.TypesSizes != s.prog.Pkgs[0].TypesSizes || bound.pkg.TypesSizes.Sizeof(types.Typ[types.Int]) != 4 {
		t.Fatal("binding replaced selected size model with verifier sizes")
	}
	before := bound.identity
	work, bytes := b.work, b.bytes
	if again, err := b.bindDeclaration(root); err != nil || again.identity != before || b.work != work || b.bytes != bytes {
		t.Fatal("bound declaration was reconstructed", err)
	}
	b.limits.work, b.limits.bytes = work, bytes
	helper := s.prog.Prog.Package(bound.pkg.Types).Func("helper")
	if _, err := b.selectedPackage(helper, bound.pkg); err != nil {
		t.Fatal("validated package was reconstructed", err)
	}
	if _, err := b.bindDeclaration(helper); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatal("second declaration reset shared budget", err)
	}
	// Published identity is a value, not a live projection of mutable source.
	bound.pkg.Syntax[0].Name.Name = "changed"
	if bound.identity != before {
		t.Fatal("frozen identity changed")
	}
	// The scalar interpreter spends the very same counter, after selection has
	// used it. A separate fresh counter would accept this operation.
	c := &computationRelationChecker{selectedSourceBinder: b}
	if err := c.tick(root, root.Pos()); err == nil {
		t.Fatal("scalar work reset selection budget")
	}
}

// Keep the direct package seam honest independently of function binding.
func TestSelectedSourcePackageRequiresSelectedTypes(t *testing.T) {
	s := relationFixture(t, "func F(x int32)int32{return x}", 64)
	b := selectedSourceFixtureBinder(t, s)
	for _, p := range []*packages.Package{nil, {ID: s.prog.Pkgs[0].ID}} {
		if _, err := b.selectedPackage(s.prog.Roots["F"], p); err == nil {
			t.Fatal("absent selected types accepted")
		}
	}
}
