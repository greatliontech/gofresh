package closure

import (
	"errors"
	"testing"

	progpkg "github.com/greatliontech/gofresh/closure/internal/program"
)

// fixturePrograms shares loaded representation, never analysis results, for
// unchanged fixtures under one Hasher's configuration. Only the latest package
// is held; its own PkgPath is the key, so a failed replacement cannot leave a
// stale key beside a nil program. Source-editing and independent-load tests do
// not use this helper. The owner and its callers are sequential.
type fixturePrograms struct {
	h      *Hasher
	loaded *program
}

func newFixturePrograms(t *testing.T, h *Hasher) *fixturePrograms {
	t.Helper()
	f := &fixturePrograms{h: h}
	t.Cleanup(f.release)
	return f
}

func (f *fixturePrograms) supply(t *testing.T, pkgPath string) {
	t.Helper()
	if f.loaded == nil || f.loaded.PkgPath != pkgPath {
		f.release()
		// Cache only successful fixture loads, as the precise-analysis
		// driver's local-load path does. A failed case still fails the test;
		// later cases retain their opportunity to load and assert independently.
		p, err := progpkg.Load(f.h.ctx, f.h.dir, f.h.packageEnv, f.h.buildFlags, pkgPath)
		if err != nil {
			t.Fatalf("load fixture %s: %v", pkgPath, err)
		}
		f.loaded = p
	}
	// Reset analysis-failure discrimination; only structural SSA caches may
	// carry across these otherwise independent singleton analyses.
	f.loaded.PkgScopeProbe = nil
	f.h.progs[pkgPath] = f.loaded
}

func (f *fixturePrograms) release() {
	if f.loaded != nil {
		delete(f.h.progs, f.loaded.PkgPath)
		f.loaded = nil
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
