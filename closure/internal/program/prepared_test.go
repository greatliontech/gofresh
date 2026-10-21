package program

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/format"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
)

const preparedModule = "example.com/prepared/"

func preparationModule(t *testing.T) (string, []string) {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":              "module example.com/prepared\n\ngo 1.27\n",
		"a/a.go":              "package a\nfunc G() {}\nfunc init() {}\n",
		"a/a_test.go":         "package a\nimport \"testing\"\nfunc helper() {}\nfunc TestA(t *testing.T) { G() }\n",
		"a/ext_test.go":       "package a_test\nimport (\"testing\"; \"example.com/prepared/r\")\nfunc helper() {}\nfunc TestExternal(t *testing.T) { r.Use() }\n",
		"r/r.go":              "package r\nimport \"example.com/prepared/a\"\nfunc G() {}\nfunc Use() { a.G() }\n",
		"r/r_test.go":         "package r\nimport \"testing\"\nfunc TestR(t *testing.T) { Use() }\n",
		"plain/p.go":          "package differentname\nfunc P() {}\n",
		"onlyext/p.go":        "package onlyext\nfunc P() {}\n",
		"onlyext/ext_test.go": "package onlyext_test\nimport (\"testing\"; \"example.com/prepared/onlyext\")\nfunc TestExternal(t *testing.T) { onlyext.P() }\n",
		"onlytest/p_test.go":  "package onlytest\nimport \"testing\"\nfunc TestOnly(t *testing.T) {}\n",
		"cmd/main.go":         "package main\nfunc main() {}\n",
		"cmd/main_test.go":    "package main\nimport \"testing\"\nfunc TestMain(m *testing.M) { m.Run() }\nfunc TestCommand(t *testing.T) {}\n",
		"generic/g.go":        "package generic\ntype Ring struct{}\nfunc (*Ring) N[T ~int](v T) T { return v }\nfunc Use() int { return new(Ring).N(7) }\n",
		"bad/p.go":            "package bad\nvar Broken int = \"wrong\"\n",
		"ownbad/p.go":         "package ownbad\nimport _ \"example.com/prepared/bad\"\nfunc P() {}\n",
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir, os.Environ()
}

type programInventory struct {
	Packages  map[string][]string
	SSA       []string
	Roots     map[string]string
	Ambiguous map[string]bool
	TestMain  string
}

func inventory(t *testing.T, p *Program) programInventory {
	t.Helper()
	ids := map[*types.Package]string{}
	out := programInventory{Packages: map[string][]string{}, Roots: map[string]string{}, Ambiguous: p.Ambiguous}
	for _, pkg := range p.Pkgs {
		if prior, ok := ids[pkg.Types]; ok && prior != pkg.ID {
			t.Fatalf("type package conflates %s and %s", prior, pkg.ID)
		}
		ids[pkg.Types] = pkg.ID
	}
	for _, pkg := range p.Pkgs {
		facts := []string{"path=" + pkg.PkgPath, "for=" + pkg.ForTest, "name=" + pkg.Name}
		for _, file := range pkg.GoFiles {
			facts = append(facts, "source="+file)
		}
		for _, file := range pkg.CompiledGoFiles {
			facts = append(facts, "file="+file)
		}
		for path, dep := range pkg.Imports {
			facts = append(facts, "import="+path+"="+dep.ID)
		}
		for _, dep := range pkg.Types.Imports() {
			id, ok := ids[dep]
			if !ok {
				t.Fatalf("typed import of %s has no exact graph owner: %s", pkg.ID, dep.Path())
			}
			facts = append(facts, "typesimport="+id)
		}
		slices.Sort(facts)
		out.Packages[pkg.ID] = facts
	}
	for _, pkg := range p.Prog.AllPackages() {
		id, ok := ids[pkg.Pkg]
		if !ok {
			t.Fatalf("SSA package has no exact typed owner: %s", pkg.Pkg.Path())
		}
		out.SSA = append(out.SSA, id)
	}
	slices.Sort(out.SSA)
	key := func(fn *ssa.Function) string {
		if fn == nil {
			return ""
		}
		id := ""
		if fn.Pkg != nil {
			id = ids[fn.Pkg.Pkg]
		}
		pos := p.Prog.Fset.PositionFor(fn.Pos(), false)
		return fmt.Sprintf("%s|%s|%s:%d|%s", id, fn.String(), pos.Filename, pos.Offset, fn.Synthetic)
	}
	for name, fn := range p.Roots {
		out.Roots[name] = key(fn)
	}
	out.TestMain = key(p.TestMain)
	return out
}

func TestPreparedProgramsMatchIndependentLoads(t *testing.T) {
	if testing.Short() {
		t.Skip("builds independent whole-program SSA controls")
	}
	dir, env := preparationModule(t)
	names := []string{"a", "r", "plain", "onlyext", "onlytest", "cmd", "generic", "bad", "ownbad"}
	var paths []string
	for _, name := range names {
		paths = append(paths, preparedModule+name)
	}
	prepared, err := Prepare(t.Context(), dir, env, nil, paths...)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			path := preparedModule + name
			got, err := prepared.Build(t.Context(), path)
			if name == "bad" || name == "ownbad" {
				if err == nil || got != nil || !strings.Contains(err.Error(), "wrong") {
					t.Fatalf("invalid closure accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want, err := Load(t.Context(), dir, env, nil, path)
			if err != nil {
				t.Fatal(err)
			}
			gi, wi := inventory(t, got), inventory(t, want)
			gv, wv := reflect.ValueOf(gi), reflect.ValueOf(wi)
			for i := 0; i < gv.NumField(); i++ {
				if !reflect.DeepEqual(gv.Field(i).Interface(), wv.Field(i).Interface()) {
					t.Fatalf("prepared inventory differs from independent load in %s", gv.Type().Field(i).Name)
				}
			}
			if got.Prog == want.Prog {
				t.Fatal("SSA shared with independent load")
			}
			switch name {
			case "a":
				if !got.Ambiguous["helper"] || got.Roots["G"] == nil || got.Roots["Use"] != nil || got.Roots["init#a.go#0"] == nil {
					t.Fatal("own/ambiguous/init roots lost or dependency rooted")
				}
				if _, ok := gi.Packages[preparedModule+"r ["+preparedModule+"a.test]"]; !ok {
					t.Fatal("triangle recompilation absent; partition test vacuous")
				}
			case "r":
				if _, ok := gi.Packages[preparedModule+"r ["+preparedModule+"a.test]"]; ok {
					t.Fatal("foreign recompilation entered r's program")
				}
			case "onlyext":
				if got.Roots["P"] != nil || got.Roots["TestExternal"] == nil {
					t.Fatal("external-only root refusal changed")
				}
			case "onlytest":
				if got.Roots["TestOnly"] == nil {
					t.Fatal("test-only root lost")
				}
				if len(prepared.roots[path][0].GoFiles) != 0 {
					t.Fatal("ordinary test-only fixture unexpectedly has GoFiles")
				}
				stdBody := false
				for _, pkg := range got.Prog.AllPackages() {
					if pkg.Pkg.Path() == "testing" {
						fn := pkg.Func("Init")
						stdBody = fn != nil && len(fn.Blocks) > 0
					}
				}
				if !stdBody {
					t.Fatal("standard-library bodies absent")
				}
			case "cmd":
				if got.TestMain == nil || got.Roots["main"] == nil {
					t.Fatal("command or harness root absent")
				}
			case "generic":
				if got.Roots["Use"] == nil || got.Roots["Ring.N"] == nil {
					t.Fatal("generic method roots absent")
				}
				materialized := false
				for fn := range ssautil.AllFunctions(got.Prog) {
					if fn.Origin() == got.Roots["Ring.N"] && len(fn.TypeArgs()) > 0 && len(fn.Blocks) > 0 {
						materialized = true
					}
				}
				if !materialized {
					t.Fatal("generic method instantiation has no body")
				}
			}
		})
	}
	if p, err := prepared.Build(t.Context(), preparedModule+"unregistered"); err == nil || p != nil {
		t.Fatal("unregistered path accepted")
	}
}

type typedInputSnapshot struct {
	syntax  string
	info    types.Info
	imports []*types.Package
}

func typedSyntax(t *testing.T, p *Prepared) map[string]typedInputSnapshot {
	t.Helper()
	out := map[string]typedInputSnapshot{}
	for _, roots := range p.roots {
		packages.Visit(roots, nil, func(pkg *packages.Package) {
			if _, ok := out[pkg.ID]; ok {
				return
			}
			// Include a shared dependency as well as every fixture variant.
			if !strings.HasPrefix(pkg.PkgPath, preparedModule) && pkg.PkgPath != "testing" {
				return
			}
			var buf bytes.Buffer
			for _, file := range pkg.Syntax {
				if err := format.Node(&buf, pkg.Fset, file); err != nil {
					t.Fatal(err)
				}
			}
			info := *pkg.TypesInfo
			info.Defs = maps.Clone(info.Defs)
			info.Uses = maps.Clone(info.Uses)
			info.Types = maps.Clone(info.Types)
			info.Instances = maps.Clone(info.Instances)
			info.Implicits = maps.Clone(info.Implicits)
			info.Selections = maps.Clone(info.Selections)
			info.Scopes = maps.Clone(info.Scopes)
			info.InitOrder = slices.Clone(info.InitOrder)
			info.FileVersions = maps.Clone(info.FileVersions)
			out[pkg.ID] = typedInputSnapshot{buf.String(), info, slices.Clone(pkg.Types.Imports())}
		})
	}
	return out
}

func TestPreparedBuildsOwnSSAAndPreserveTypedInputs(t *testing.T) {
	if testing.Short() {
		t.Skip("builds whole-program SSA repeatedly")
	}
	dir, env := preparationModule(t)
	a, b := preparedModule+"a", preparedModule+"generic"
	p, err := Prepare(t.Context(), dir, env, nil, a, b)
	if err != nil {
		t.Fatal(err)
	}
	before := typedSyntax(t, p)
	first, err := p.Build(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	first.PkgScopeProbe = map[bool]error{true: errors.New("prior analysis")}
	if _, err := p.Build(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	last, err := p.Build(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	if first.Prog == last.Prog || first.Roots["G"] == last.Roots["G"] || last.PkgScopeProbe != nil {
		t.Fatal("SSA or analysis state crossed builds")
	}
	if first.Roots["G"].Object() != last.Roots["G"].Object() {
		t.Fatal("typed preparation was not actually shared")
	}
	if !reflect.DeepEqual(inventory(t, first), inventory(t, last)) || !reflect.DeepEqual(before, typedSyntax(t, p)) {
		t.Fatal("repeated build changed typed inputs or semantic inventory")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if prog, err := p.Build(ctx, a); prog != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled build: %v", err)
	}
	if prep, err := Prepare(ctx, dir, env, nil, a); prep != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled preparation: %v", err)
	}
}

type mutateContext struct {
	context.Context
	once func()
}

func (c *mutateContext) Err() error {
	if c.once != nil {
		f := c.once
		c.once = nil
		f()
	}
	return c.Context.Err()
}

func TestPreparedCapturesContainersAndNewGenerations(t *testing.T) {
	if testing.Short() {
		t.Skip("loads source and build-configuration generations")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/generation\n\ngo 1.27\n"), 0644); err != nil {
		t.Fatal(err)
	}
	write := func(name, text string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("p.go", "package generation\nfunc Before() {}\n")
	write("tag.go", "//go:build selected\n\npackage generation\nfunc Selected() {}\n")
	paths := []string{"example.com/generation"}
	flags := []string{"-tags=selected"}
	env := append(os.Environ(), "PREPARATION_CAPTURE=original")
	ctx := &mutateContext{Context: t.Context(), once: func() {
		paths[0] = "missing.invalid/package"
		flags[0] = "-badflag"
		env[len(env)-1] = "GOFLAGS=-badflag"
	}}
	p, err := Prepare(ctx, dir, env, flags, paths...)
	if err != nil {
		t.Fatal(err)
	}
	first, err := p.Build(t.Context(), "example.com/generation")
	if err != nil || first.Roots["Before"] == nil || first.Roots["Selected"] == nil {
		t.Fatalf("caller mutation altered preparation: %v", err)
	}
	// The previous owner's quiescent span has ended. Never use it as a
	// current-tree view after this edit; both fresh loads must see the edit.
	write("p.go", "package generation\nfunc After() {}\n")
	next, err := Prepare(t.Context(), dir, os.Environ(), nil, "example.com/generation")
	if err != nil {
		t.Fatal(err)
	}
	got, err := next.Build(t.Context(), "example.com/generation")
	if err != nil {
		t.Fatal(err)
	}
	want, err := Load(t.Context(), dir, os.Environ(), nil, "example.com/generation")
	if err != nil {
		t.Fatal(err)
	}
	if got.Roots["After"] == nil || got.Roots["Before"] != nil || got.Roots["Selected"] != nil || !reflect.DeepEqual(inventory(t, got), inventory(t, want)) {
		t.Fatal("new generation retained source/configuration facts")
	}
	if p, err := Prepare(t.Context(), dir, os.Environ(), nil); err == nil || p != nil {
		t.Fatal("empty roster implicitly loaded the working directory")
	}
	unsupported, err := Prepare(t.Context(), dir, os.Environ(), nil, ".")
	if err != nil {
		t.Fatal(err)
	}
	if p, err := unsupported.Build(t.Context(), "."); err == nil || p != nil {
		t.Fatal("non-import-path request built a partial program")
	}
}

func TestPreparedGeneratedMainRequiresTargetVariants(t *testing.T) {
	if testing.Short() {
		t.Skip("compares actual package/test-executable selections")
	}
	const target = "example.com/suffixed/q"
	for _, mode := range []string{"valid-command", "invalid-command", "colliding-test-main"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string]string{
				"go.mod":         "module example.com/suffixed\n\ngo 1.27\n",
				"q/q.go":         "package q\nfunc Q() {}\n",
				"q.test/main.go": "package main\nimport \"example.com/suffixed/q\"\nfunc main() { q.Q() }\n",
			}
			if mode == "invalid-command" {
				files["q.test/main.go"] += "var Broken int = \"wrong\"\n"
			}
			if mode == "colliding-test-main" {
				files["q/q_test.go"] = "package q\nimport \"testing\"\nfunc TestQ(t *testing.T) { Q() }\n"
			}
			for name, text := range files {
				path := filepath.Join(dir, name)
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(text), 0644); err != nil {
					t.Fatal(err)
				}
			}
			env := os.Environ()
			want, err := Load(t.Context(), dir, env, nil, target)
			if err != nil {
				t.Fatalf("independent q: %v", err)
			}
			command, commandErr := Load(t.Context(), dir, env, nil, target+".test")
			if mode == "invalid-command" {
				if commandErr == nil || command != nil {
					t.Fatal("ill-typed command control accepted")
				}
			} else if commandErr != nil || command.Roots["main"] == nil {
				t.Fatalf("ordinary command control: %v", commandErr)
			}
			// Both request orders must preserve the same separation/refusal.
			for _, paths := range [][]string{{target, target + ".test"}, {target + ".test", target}} {
				prepared, err := Prepare(t.Context(), dir, env, nil, paths...)
				if mode == "colliding-test-main" {
					// Go may reject the ID collision globally. If it supplies one
					// graph, neither request may consume its ambiguous root ID.
					if err != nil {
						if prepared != nil {
							t.Fatal("failed load returned preparation")
						}
						continue
					}
					for _, path := range paths {
						if p, err := prepared.Build(t.Context(), path); err == nil || p != nil {
							t.Fatalf("ambiguous root %s accepted", path)
						}
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				got, err := prepared.Build(t.Context(), target)
				if err != nil {
					t.Fatalf("unrelated ordinary command contaminated q: %v", err)
				}
				if !reflect.DeepEqual(inventory(t, got), inventory(t, want)) {
					t.Fatal("ordinary .test command entered q's program")
				}
				got, err = prepared.Build(t.Context(), target+".test")
				if mode == "invalid-command" {
					if err == nil || got != nil {
						t.Fatal("invalid ordinary command lost its own load error")
					}
				} else if err != nil || !reflect.DeepEqual(inventory(t, got), inventory(t, command)) {
					t.Fatalf("ordinary command selection changed: %v", err)
				}
			}
		})
	}
}
