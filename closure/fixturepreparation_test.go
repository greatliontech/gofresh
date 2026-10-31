package closure

import (
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	progpkg "github.com/greatliontech/gofresh/closure/internal/program"
)

// fixtureEvidence projects identities rather than pointers or raw token.Pos:
// independent loads own different type universes and file-set base offsets.
type fixtureEvidence struct {
	Proof                                                 Observability
	All, Subject, Startup, Harness                        []string
	Resolved                                              []string
	Targets                                               map[string][]string
	Whole, SubjectEffects, StartupEffects, HarnessEffects tier2Result
}

func fixtureProgramEvidence(t *testing.T, dir string, p *program, symbol string) fixtureEvidence {
	t.Helper()
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: p.PkgPath, Symbol: symbol}
	rows, err := attributedReachableSets(h.ctx, h.SelectionAudited(), h.source.pureDelegates, p, []Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	r := rows[0]
	ids := map[*types.Package]string{}
	for _, pkg := range p.Pkgs {
		ids[pkg.Types] = pkg.ID
	}
	fnKey := func(fn *ssa.Function) string {
		if fn == nil {
			return "<nil>"
		}
		id := ""
		if fn.Pkg != nil {
			id = ids[fn.Pkg.Pkg]
		}
		pos := p.Prog.Fset.PositionFor(fn.Pos(), false)
		return fmt.Sprintf("%s|%s|%s:%d|%s", id, fn.String(), pos.Filename, pos.Offset, fn.Synthetic)
	}
	set := func(m map[*ssa.Function]bool) []string {
		var out []string
		for fn, present := range m {
			if present {
				out = append(out, fnKey(fn))
			}
		}
		slices.Sort(out)
		return out
	}
	siteKey := func(site ssa.CallInstruction) string {
		pos := p.Prog.Fset.PositionFor(site.Pos(), false)
		return fmt.Sprintf("%s|%s:%d|%s", fnKey(site.Parent()), pos.Filename, pos.Offset, site.String())
	}
	e := fixtureEvidence{All: set(r.functions), Subject: set(r.subjectFunctions), Startup: set(r.startupFunctions), Harness: set(r.testMainFunctions), Targets: map[string][]string{}}
	for site, yes := range r.resolved {
		if yes {
			e.Resolved = append(e.Resolved, siteKey(site))
		}
	}
	slices.Sort(e.Resolved)
	for site, targets := range r.dynamicTargets {
		e.Targets[siteKey(site)] = set(targets)
	}
	metas, err := h.list(p.PkgPath)
	if err != nil {
		t.Fatal(err)
	}
	base := newTier2Base(h, p, metas)
	e.Whole, err = h.tier2Reachable(base, r)
	if err != nil {
		t.Fatal(err)
	}
	subjectReach := r
	subjectReach.functions = r.subjectFunctions
	e.SubjectEffects, err = h.tier2Reachable(base, subjectReach)
	if err != nil {
		t.Fatal(err)
	}
	startupReach := r
	startupReach.functions = nonStandardFunctions(base, r.startupFunctions)
	e.StartupEffects = directExternalEffects(base, startupReach)
	harnessReach := r
	harnessReach.functions = nonStandardFunctions(base, r.testMainFunctions)
	e.HarnessEffects = testMainObservedEffects(base, harnessReach)
	for _, result := range []*tier2Result{&e.Whole, &e.SubjectEffects, &e.StartupEffects, &e.HarnessEffects} {
		slices.SortFunc(result.effects, func(a, b externalEffect) int { return strings.Compare(fmt.Sprintf("%+v", a), fmt.Sprintf("%+v", b)) })
	}
	// Exercise the public singleton pipeline too: the raw projection above
	// cannot stand in for its full disposition, diagnostics and outcome method.
	p.PkgScopeProbe = nil
	h.progs[p.PkgPath] = p
	proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	e.Proof = proofs[subject]
	return e
}

func assertFixtureEvidence(t *testing.T, got, want fixtureEvidence) {
	t.Helper()
	g, w := reflect.ValueOf(got), reflect.ValueOf(want)
	for i := 0; i < g.NumField(); i++ {
		if !reflect.DeepEqual(g.Field(i).Interface(), w.Field(i).Interface()) {
			t.Errorf("prepared/independent evidence differs in %s", g.Type().Field(i).Name)
		}
	}
}

func TestFixturePreparationPreservesIndependentEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("compares independent whole-program analyses")
	}
	const base = "github.com/greatliontech/gofresh/closure/fixtures/"
	cases := []struct {
		path, symbol string
		observable   bool
	}{
		{base + "observable", "TestReadFile", true},
		{base + "initfile", "TestInitFile", false},
		{base + "harnessmainwrite", "TestProd", false},
		{base + "dyncaller", "RunCheck", true},
	}
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, tc := range cases {
		paths = append(paths, tc.path)
	}
	prepared, err := progpkg.Prepare(h.ctx, h.dir, h.packageEnv, h.buildFlags, paths...)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.symbol, func(t *testing.T) {
			p, err := prepared.Build(t.Context(), tc.path)
			if err != nil {
				t.Fatal(err)
			}
			got := fixtureProgramEvidence(t, h.dir, p, tc.symbol)
			p, err = progpkg.Load(t.Context(), h.dir, h.packageEnv, h.buildFlags, tc.path)
			if err != nil {
				t.Fatal(err)
			}
			want := fixtureProgramEvidence(t, h.dir, p, tc.symbol)
			assertFixtureEvidence(t, got, want)
			if got.Proof.Observable != tc.observable {
				t.Fatalf("positive/negative control: %+v", got.Proof)
			}
		})
	}
}

func TestFixturePreparationExcludesForeignInitializersAndCallers(t *testing.T) {
	if testing.Short() {
		t.Skip("compares independent whole-program analyses")
	}
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":      "module example.com/isolation\n\ngo 1.27\n",
		"p/p.go":      "package p\nfunc Run(check func() bool) bool { return check() }\nfunc Local() bool { return Run(func() bool { return true }) }\n",
		"caller/p.go": "package caller\nimport (\"os\"; \"example.com/isolation/p\")\nfunc Foreign() bool { return p.Run(func() bool { return os.WriteFile(\"foreign\", nil, 0600) == nil }) }\n",
		"poison/p.go": "package poison\nimport \"os\"\nfunc init() { _ = os.WriteFile(\"poison\", nil, 0600) }\n",
	}
	for name, text := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, name, text)
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	const target = "example.com/isolation/p"
	// First isolate caller enumeration, then add unrelated startup poison.
	for _, paths := range [][]string{{target, "example.com/isolation/caller"}, {target, "example.com/isolation/caller", "example.com/isolation/poison"}} {
		prepared, err := progpkg.Prepare(h.ctx, dir, h.packageEnv, nil, paths...)
		if err != nil {
			t.Fatal(err)
		}
		p, err := prepared.Build(t.Context(), target)
		if err != nil {
			t.Fatal(err)
		}
		got := fixtureProgramEvidence(t, dir, p, "Run")
		p, err = progpkg.Load(t.Context(), dir, h.packageEnv, nil, target)
		if err != nil {
			t.Fatal(err)
		}
		want := fixtureProgramEvidence(t, dir, p, "Run")
		assertFixtureEvidence(t, got, want)
		if !got.Proof.Observable {
			t.Fatalf("foreign fixture contaminated closed subject: %+v", got.Proof)
		}
	}
}
