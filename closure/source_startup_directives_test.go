package closure

import (
	"context"
	"errors"
	"go/ast"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func TestSourceStartupUnusedFunctionDeclarations(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []string
	}{
		{"ordinary", []string{`package dep;func absent()int;func differentlyNamed(string);var X=7;func init(){X=9}`}},
		{"linked", []string{"package dep\nimport _ \"unsafe\"\n//go:linkname absent missing.example/remote.Target\nfunc absent()int\n//go:linkname differentlyNamed\nfunc differentlyNamed(string)\nvar X=7\nfunc init(){X=9}"}},
		{"cross-file", []string{"package dep\nimport _ \"unsafe\"\n//go:linkname renamed missing.example/remote.Target", `package dep;func renamed()int;var X=7;func init(){X=9}`}},
		{"shared-remote", []string{"package dep\nimport _ \"unsafe\"\n//go:linkname first missing.Target\nfunc first()\n//go:linkname second missing.Target\nfunc second()\nvar X=9"}},
		{"named-unsafe", []string{"package dep\nimport \"unsafe\"\n//go:linkname renamed missing.Target\nfunc renamed()\nconst _=unsafe.Sizeof(0)\nvar X=9"}},
		{"renamed-unsafe", []string{"package dep\nimport u \"unsafe\"\n//go:linkname renamed missing.Target\nfunc renamed()\nconst _=u.Sizeof(0)\nvar X=9"}},
		{"field-whitespace", []string{"package dep\nimport _ \"unsafe\"\n//go:linkname \trenamed\tmissing.Target  \nfunc renamed()\nvar X=9"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, main, use := startupFixture(t, map[string][]string{"dep": tc.files, "main": {`package main;import "dep";func consume(int){};func main(){consume(dep.X)}`}})
			got, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{})
			if err != nil {
				t.Fatal(err)
			}
			if startupScalar(t, got).ExactString() != "9" || len(got.startup.order) != 2 {
				t.Fatal("unused declaration admission skipped imported initialization")
			}
			var want, actual []string
			for _, text := range tc.files {
				for _, line := range strings.Split(text, "\n") {
					if strings.HasPrefix(line, "//go:linkname ") {
						want = append(want, line)
					}
				}
			}
			for _, d := range got.startup.order[0].input.directives {
				actual = append(actual, d.text)
			}
			if !slices.Equal(actual, want) {
				t.Fatalf("lost exact unresolved linkage identity: got %q, want %q", actual, want)
			}
		})
	}
}

func TestSourceStartupOpaqueFunctionValueIsOnlyIdentity(t *testing.T) {
	in, main, use := startupFixture(t, map[string][]string{"main": {`package main
import _ "unsafe"
//go:linkname opaque absent.remote
func opaque()int
var F=opaque
func consume(func()int){}
func main(){consume(F)}
`}})
	got, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	value := got.regions[0].packet.observations[0].value
	if value.kind != regionCallable || value.target != main.Pkg.Func("opaque") {
		t.Fatal("opaque function identity lost")
	}
	binder, err := newSelectedSourceBinder(t.Context(), in.source, main, defaultRegistrationLimits().source)
	if err != nil {
		t.Fatal(err)
	}
	if bound, err := binder.bindCallable(value.target); err == nil || bound.function != nil {
		t.Fatal("opaque identity became an implemented callable")
	}
}

func TestSourceStartupReachedOpaqueFunctions(t *testing.T) {
	for _, linked := range []bool{false, true} {
		for _, tc := range []struct {
			name, declarations, prefix string
			phase                      sourceStartupPhase
		}{
			{"initializer", `var X=opaque()`, "", sourceStartupInitialization},
			{"explicit-init", `var X int;func init(){X=opaque()}`, "", sourceStartupInitialization},
			{"main-prefix", `var X int;func Run(){X=opaque()}`, "dep.Run();", sourceStartupEntry},
			{"function-value", `var F=opaque;var X int;func Run(){X=F()}`, "dep.Run();", sourceStartupEntry},
			{"callback-init", `var X int;func invoke(f func()int){X=f()};func init(){invoke(opaque)}`, "", sourceStartupInitialization},
			{"callback-main", `var X int;func invoke(f func()int){X=f()};func Run(){invoke(opaque)}`, "dep.Run();", sourceStartupEntry},
		} {
			t.Run(tc.name+map[bool]string{false: "/ordinary", true: "/linked"}[linked], func(t *testing.T) {
				preamble := "package dep\n"
				if linked {
					// A selected nominal target exists, but must never supply the
					// body of this unresolved declaration through its remote spelling.
					preamble += "import _ \"unsafe\"\n//go:linkname opaque dep.nominal\n"
				}
				in, main, use := startupFixture(t, map[string][]string{
					"dep":  {preamble + "func opaque()int\nfunc nominal()int{return 7}\n" + tc.declarations},
					"main": {`package main;import "dep";func consume(int){};func main(){` + tc.prefix + `consume(dep.X)}`},
				})
				got, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{})
				var failure *sourceStartupFailure
				if got != nil || !errors.As(err, &failure) || failure.phase != tc.phase || failure.operation != "interpret" || failure.packageID != "dep" || !slices.Equal(failure.dependencyPath, []string{"main", "dep"}) || len(failure.operations) == 0 {
					t.Fatalf("lost opaque call boundary: %v, %v", got, err)
				}
				call, ok := failure.operations[len(failure.operations)-1].(*ssa.Call)
				if !ok || call.Parent().Pkg.Pkg.Path() != "dep" || !strings.Contains(err.Error(), "call target has no supported ordinary source body") {
					t.Fatalf("refused before actual opaque invocation: %v", err)
				}
			})
		}
	}
}

func TestSourceStartupFunctionLinknameRefusals(t *testing.T) {
	for _, tc := range []struct{ name, imports, directive, declaration string }{
		{"variable", `import _ "unsafe"`, "//go:linkname opaque remote.X", "var opaque int"},
		{"bodyful", `import _ "unsafe"`, "//go:linkname opaque remote.F", "func opaque()int{return 7}"},
		{"bodyful-one-arg", `import _ "unsafe"`, "//go:linkname opaque", "func opaque()int{return 7}"},
		{"unknown", `import _ "unsafe"`, "//go:linkname missing remote.F", "func opaque()int"},
		{"method", `import _ "unsafe"`, "//go:linkname opaque remote.F", "type T int;func(T)opaque()int{return 7}"},
		{"type", `import _ "unsafe"`, "//go:linkname opaque remote.F", "type opaque int"},
		{"empty", `import _ "unsafe"`, "//go:linkname ", "func opaque()int"},
		{"extra", `import _ "unsafe"`, "//go:linkname opaque remote.F extra", "func opaque()int"},
		{"trailing-comment", `import _ "unsafe"`, "//go:linkname opaque remote.F // comment", "func opaque()int"},
		{"tab-verb", `import _ "unsafe"`, "//go:linkname\topaque remote.F", "func opaque()int"},
		{"instantiation", `import _ "unsafe"`, "//go:linkname opaque remote.F[int]", "func opaque()int"},
		{"duplicate", `import _ "unsafe"`, "//go:linkname opaque remote.F\n//go:linkname opaque remote.F", "func opaque()int"},
		{"conflict", `import _ "unsafe"`, "//go:linkname opaque remote.F\n//go:linkname opaque remote.G", "func opaque()int"},
		{"missing-unsafe", "", "//go:linkname opaque remote.F", "func opaque()int"},
		{"other-directive", `import _ "unsafe"`, "//go:linkname opaque remote.F\n//go:noescape", "func opaque()int"},
		{"misplaced", `import _ "unsafe"`, "var X int //go:linkname opaque remote.F", "func opaque()int"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, main, use := startupFixture(t, map[string][]string{"dep": {"package dep\n" + tc.imports + "\n" + tc.directive + "\n" + tc.declaration}, "main": {`package main;import _ "dep";func consume(int){};func main(){consume(0)}`}})
			got, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{})
			var failure *sourceStartupFailure
			if got != nil || !errors.As(err, &failure) || failure.phase != sourceStartupSelection || failure.operation != "external-storage" || !slices.Equal(failure.dependencyPath, []string{"main", "dep"}) {
				t.Fatalf("invalid directive accepted or wrong boundary: %v %v", got, err)
			}
		})
	}
}

func TestSourceStartupFunctionLinknameOwnership(t *testing.T) {
	for _, mode := range []string{"missing-def", "foreign-def", "copied-ssa", "missing-ssa", "borrowed-body", "duplicate-declaration", "unsafe-other-file", "missing-unsafe-binding", "conflict-other-file"} {
		t.Run(mode, func(t *testing.T) {
			texts := []string{"package dep\nimport _ \"unsafe\"\n//go:linkname opaque remote.F\nfunc opaque()int", "package dep"}
			if mode == "unsafe-other-file" {
				texts = []string{"package dep\n//go:linkname opaque remote.F\nfunc opaque()int", "package dep\nimport _ \"unsafe\""}
			}
			if mode == "conflict-other-file" {
				texts[1] += "\nimport _ \"unsafe\"\n//go:linkname opaque other.F"
			}
			in, main, use := startupFixture(t, map[string][]string{"dep": texts, "main": {`package main;import _ "dep";func consume(int){};func main(){consume(0)}`}})
			p := in.source.prog.Pkgs[0]
			owner := main.Prog.Package(p.Types)
			fn := owner.Func("opaque")
			decl := fn.Syntax().(*ast.FuncDecl)
			switch mode {
			case "missing-def":
				delete(p.TypesInfo.Defs, decl.Name)
			case "foreign-def":
				p.TypesInfo.Defs[decl.Name] = main.Pkg.Func("consume").Object()
			case "copied-ssa":
				copy := *fn
				owner.Members["opaque"] = &copy
			case "missing-ssa":
				delete(owner.Members, "opaque")
			case "borrowed-body":
				fn.Blocks = main.Blocks
			case "duplicate-declaration":
				p.Syntax[1].Decls = append(p.Syntax[1].Decls, decl)
			case "missing-unsafe-binding":
				delete(p.TypesInfo.Defs, p.Syntax[0].Imports[0].Name)
			}
			got, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{})
			var failure *sourceStartupFailure
			if got != nil || !errors.As(err, &failure) || failure.phase != sourceStartupSelection || !slices.Equal(failure.dependencyPath, []string{"main", "dep"}) {
				t.Fatalf("unbound declaration admitted: %v %v", got, err)
			}
		})
	}
}

func TestSourceStartupFunctionLinknameBounds(t *testing.T) {
	in, main, _ := startupFixture(t, map[string][]string{"main": {"package main\nimport _ \"unsafe\"\n//go:linkname opaque remote.F\nfunc opaque()int\nfunc main(){}"}})
	for _, mode := range []string{"work", "bytes", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			b, err := newSelectedSourceBinder(t.Context(), in.source, main, defaultRegistrationLimits().source)
			if err != nil {
				t.Fatal(err)
			}
			p := b.pkgs[main.Pkg.Pkg]
			inventory, err := b.selectedPackage(main, p)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "work":
				b.limits.work = b.work + 2
			case "bytes":
				b.limits.bytes = b.bytes + len(inventory.directives[0].text) - 1
			case "cancel":
				b.ctx = &regionCallCountingContext{Context: t.Context(), stop: 3}
			}
			err = b.sourceStartupDirectives(p, inventory)
			if err == nil || mode == "cancel" && !errors.Is(err, context.Canceled) || mode != "cancel" && !strings.Contains(err.Error(), "budget") {
				t.Fatal("directive parsing exceeded its bound", err)
			}
		})
	}
}

func TestSourceStartupBodylessEntriesRefuse(t *testing.T) {
	for _, text := range []string{
		`package main;func main()`,
		`package main;func init(){};func consume(int){};func main(){consume(0)}`,
	} {
		in, main, use := startupFixture(t, map[string][]string{"main": {text}})
		for _, declaration := range in.source.prog.Pkgs[0].Syntax[0].Decls {
			if decl, ok := declaration.(*ast.FuncDecl); ok && decl.Name.Name == "init" {
				// go/types already rejects a bodyless init. Removing that body
				// afterward must not let an inconsistent selected owner skip it.
				decl.Body = nil
			}
		}
		if got, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{}); got != nil || err == nil {
			t.Fatal("unimplemented startup entry accepted")
		}
	}
}

func TestSourceStartupFunctionLinknameImportByteBudget(t *testing.T) {
	in, main, _ := startupFixture(t, map[string][]string{"main": {`package main
import _ "unsafe"
//go:linkname first remote.First
func first()
//go:linkname second remote.Second
func second()
func main(){}
`}})
	for _, complete := range []bool{false, true} {
		binder, err := newSelectedSourceBinder(t.Context(), in.source, main, defaultRegistrationLimits().source)
		if err != nil {
			t.Fatal(err)
		}
		p := binder.pkgs[main.Pkg.Pkg]
		inventory, err := binder.selectedPackage(main, p)
		if err != nil {
			t.Fatal(err)
		}
		allowance := 0
		for _, directive := range inventory.directives {
			allowance += len(directive.text)
			if complete {
				for _, spec := range directive.file.Imports {
					allowance += len(spec.Path.Value)
				}
			}
		}
		binder.limits.bytes = binder.bytes + allowance
		err = binder.sourceStartupDirectives(p, inventory)
		if complete {
			if err != nil {
				t.Fatal("complete decoding allowance refused", err)
			}
		} else if err == nil || !strings.Contains(err.Error(), "byte budget") {
			t.Fatal("repeated import decoding escaped the shared byte budget", err)
		}
	}
}
