package closure

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	progpkg "github.com/greatliontech/gofresh/closure/internal/program"
)

// fixturePrograms shares loaded representation, never analysis results, for
// unchanged fixtures under one Hasher's configuration. Only the latest SSA
// program is held; its own PkgPath is the key, so a failed replacement cannot
// leave a stale key beside a nil program. An explicit roster additionally holds
// one typed preparation for the parent. Its source/dependencies and effective
// build configuration stay quiescent through cleanup. Source-editing and
// independent-load tests do not use this helper. The owner and its callers are
// sequential, including lazy type/SSA method construction.
type fixturePrograms struct {
	h      *Hasher
	loaded *program
	// An explicit immutable roster opts into one typed generation. Preparation
	// is lazy: a table whose subtests are all filtered out loads nothing.
	roster                []string
	prepared              *progpkg.Prepared
	prepareErr            error
	attempted             bool
	prepare               func(context.Context, string, []string, []string, ...string) (*progpkg.Prepared, error)
	typedLoads, ssaBuilds int
}

func newFixturePrograms(t *testing.T, h *Hasher, roster ...string) *fixturePrograms {
	t.Helper()
	f := &fixturePrograms{h: h, prepare: progpkg.Prepare}
	for _, path := range roster {
		if !slices.Contains(f.roster, path) {
			f.roster = append(f.roster, path)
		}
	}
	t.Cleanup(f.release)
	return f
}

func (f *fixturePrograms) supply(t *testing.T, pkgPath string) {
	t.Helper()
	if err := f.acquire(pkgPath); err != nil {
		t.Fatalf("load fixture %s: %v", pkgPath, err)
	}
}

func (f *fixturePrograms) acquire(pkgPath string) error {
	if f.h.ctx != nil {
		if err := f.h.ctx.Err(); err != nil {
			f.releaseProgram()
			return err
		}
	}
	if len(f.roster) > 0 && !slices.Contains(f.roster, pkgPath) {
		f.releaseProgram()
		return fmt.Errorf("fixture %s is outside the immutable roster", pkgPath)
	}
	if f.loaded == nil || f.loaded.PkgPath != pkgPath {
		f.releaseProgram()
		if len(f.roster) > 0 && !f.attempted {
			f.attempted = true
			f.typedLoads++
			f.prepared, f.prepareErr = f.prepare(f.h.ctx, f.h.dir, f.h.packageEnv, f.h.buildFlags, f.roster...)
		}
		// Cancellation never licenses an independent fallback, including a
		// context error returned by a preparation whose context is still live.
		if err := f.h.ctx.Err(); err != nil {
			return err
		}
		if errors.Is(f.prepareErr, context.Canceled) || errors.Is(f.prepareErr, context.DeadlineExceeded) {
			return f.prepareErr
		}
		// Cache only successful fixture loads, as the precise-analysis
		// driver's local-load path does. A failed case still fails the test;
		// later cases retain their opportunity to load and assert independently.
		var p *program
		var err error
		f.ssaBuilds++
		if f.prepared != nil {
			p, err = f.prepared.Build(f.h.ctx, pkgPath)
		} else {
			// Only a load-wide operational preparation failure reaches this
			// fallback. Per-root selection/load errors remain Build errors.
			f.typedLoads++
			p, err = progpkg.Load(f.h.ctx, f.h.dir, f.h.packageEnv, f.h.buildFlags, pkgPath)
		}
		if err != nil {
			return err
		}
		f.loaded = p
	}
	// Reset analysis-failure discrimination; only structural SSA caches may
	// carry across these otherwise independent singleton analyses.
	f.loaded.PkgScopeProbe = nil
	f.h.progs[pkgPath] = f.loaded
	return nil
}

func (f *fixturePrograms) releaseProgram() {
	if f.loaded != nil {
		delete(f.h.progs, f.loaded.PkgPath)
		f.loaded = nil
	}
}

func (f *fixturePrograms) release() {
	f.releaseProgram()
	f.prepared = nil
	f.roster = nil
	f.prepareErr = nil
}

// checkPreparationCounts uses the actually entered subtests' transitions, so
// legitimate -run filtering retains the same cost assertions.
func (f *fixturePrograms) checkPreparationCounts(t *testing.T, transitions int) {
	t.Helper()
	wantLoads := 0
	if transitions > 0 {
		wantLoads = 1
	}
	if f.typedLoads != wantLoads || f.ssaBuilds != transitions {
		t.Errorf("fixture preparation: typed loads=%d SSA builds=%d, want %d/%d", f.typedLoads, f.ssaBuilds, wantLoads, transitions)
	}
}

func TestFixtureProgramSupplyKeepsOnlyLoadedRepresentation(t *testing.T) {
	h := &Hasher{progs: map[string]*program{}}
	owner := newFixturePrograms(t, h)
	p := &program{PkgPath: "example.com/fixture", PkgScopeProbe: map[bool]error{true: errors.New("prior analysis")}}
	owner.loaded = p
	owner.supply(t, p.PkgPath)
	if p.PkgScopeProbe != nil || h.progs[p.PkgPath] != p {
		t.Fatal("supplying loaded representation retained failure analysis or lost the actual program")
	}
	owner.release()
	if owner.loaded != nil || len(h.progs) != 0 {
		t.Fatal("release retained the fixture's loaded representation")
	}
	var childOwner *fixturePrograms
	t.Run("owner cleanup", func(t *testing.T) {
		childOwner = newFixturePrograms(t, h)
		childOwner.loaded = p
		childOwner.supply(t, p.PkgPath)
	})
	if childOwner.loaded != nil || len(h.progs) != 0 {
		t.Fatal("the completed owner's cleanup retained its program")
	}
}

func TestFixturePreparationLifetimeAndFailureIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("loads fixture modules and whole-program SSA")
	}
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/fixtureowner\n\ngo 1.27\n")
	for name, source := range map[string]string{"a": "func A() {}", "b": "func B() {}", "bad": "var Broken int = \"wrong\""} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, filepath.Join(name, "p.go"), "package fixture\n"+source+"\n")
	}
	const a, b, bad = "example.com/fixtureowner/a", "example.com/fixtureowner/b", "example.com/fixtureowner/bad"
	newOwner := func(t *testing.T) *fixturePrograms {
		t.Helper()
		h, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		return newFixturePrograms(t, h, a, b, bad)
	}
	t.Run("lazy and bounded", func(t *testing.T) {
		owner := newOwner(t)
		if owner.prepared != nil || owner.attempted || owner.typedLoads != 0 {
			t.Fatal("constructor prepared filtered-out cases")
		}
		owner.supply(t, a)
		first := owner.loaded
		prep := owner.prepared
		first.PkgScopeProbe = map[bool]error{true: errors.New("old analysis")}
		owner.supply(t, a)
		if first.PkgScopeProbe != nil {
			t.Fatal("case inherited the package-scope probe")
		}
		owner.supply(t, b)
		if owner.h.progs[a] != nil || len(owner.h.progs) != 1 || owner.prepared != prep {
			t.Fatal("replacement retained prior SSA or dropped preparation")
		}
		owner.supply(t, a)
		if owner.loaded == first || owner.loaded.Prog == first.Prog {
			t.Fatal("A-B-A reused prior SSA")
		}
		owner.checkPreparationCounts(t, 3)
		owner.release()
		if owner.loaded != nil || owner.prepared != nil || owner.roster != nil || len(owner.h.progs) != 0 {
			t.Fatal("cleanup retained fixture references")
		}
	})
	t.Run("per-root failure", func(t *testing.T) {
		owner := newOwner(t)
		owner.supply(t, a)
		if err := owner.acquire(bad); err == nil {
			t.Fatal("bad fixture accepted")
		}
		if owner.loaded != nil || len(owner.h.progs) != 0 {
			t.Fatal("failed replacement left stale program key")
		}
		owner.supply(t, b)
		if owner.typedLoads != 1 || owner.prepareErr != nil {
			t.Fatal("per-root failure triggered independent fallback")
		}
		if err := owner.acquire("example.com/fixtureowner/unregistered"); err == nil || owner.loaded != nil {
			t.Fatal("unregistered fixture accepted or retained previous SSA")
		}
	})
	t.Run("global operational fallback", func(t *testing.T) {
		owner := newOwner(t)
		owner.prepare = func(context.Context, string, []string, []string, ...string) (*progpkg.Prepared, error) {
			return nil, errors.New("loader-wide operational failure")
		}
		if err := owner.acquire(bad); err == nil {
			t.Fatal("bad independent fixture accepted")
		}
		owner.supply(t, a)
		owner.supply(t, b)
		if owner.typedLoads != 4 || owner.ssaBuilds != 3 || owner.prepared != nil {
			t.Fatalf("fallback attempts: %+v", owner)
		}
	})
	t.Run("cancelled preparation never falls back", func(t *testing.T) {
		owner := newOwner(t)
		owner.prepare = func(context.Context, string, []string, []string, ...string) (*progpkg.Prepared, error) {
			return nil, context.Canceled
		}
		for _, path := range []string{a, b} {
			if err := owner.acquire(path); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation: %v", err)
			}
		}
		if owner.typedLoads != 1 || owner.ssaBuilds != 0 || owner.loaded != nil {
			t.Fatal("cancelled preparation attempted fallback")
		}
	})
	t.Run("cancelled owner drops cached SSA", func(t *testing.T) {
		owner := newOwner(t)
		owner.supply(t, a)
		ctx, cancel := context.WithCancel(owner.h.ctx)
		cancel()
		owner.h.ctx = ctx
		if err := owner.acquire(a); !errors.Is(err, context.Canceled) || owner.loaded != nil || len(owner.h.progs) != 0 {
			t.Fatalf("cancelled cached supply: %v", err)
		}
	})
}
