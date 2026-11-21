package observability

import (
	"context"
	"errors"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/testenv"
)

// TestRecompiledDependencyStaysOutOfSubjectRoots pins subject rooting
// (REQ-closure-analysis): the reachability walk roots at the subject, so the
// candidate-root index for a package must come only from that package's own
// variants. `go list` marks every package recompiled into the test binary with
// ForTest — including an intermediate dependency (a's external test imports r,
// r imports a → "r [a.test]") — but the dependency's top-level functions are
// not subjects of the tested package: a name shared with the tested package
// must not read as an ambiguous root, and a name the tested package never
// declares must be refused, never silently resolved to the dependency's
// closure.
func TestRecompiledDependencyStaysOutOfSubjectRoots(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	writeTriangle := func(t *testing.T, aSource, rSource string) string {
		t.Helper()
		dir := t.TempDir()
		for name, content := range map[string]string{
			"go.mod": "module example.com/triangle\n\ngo 1.26\n",
			"a/a.go": aSource,
			// The in-package test file makes "a [a.test]" a distinct variant, so
			// r — importing a, imported by a's external test — is recompiled
			// against it as "r [a.test]" with ForTest set.
			"a/in_test.go":  "package a\n\nimport \"testing\"\n\nfunc TestInternal(t *testing.T) {}\n",
			"a/ext_test.go": "package a_test\n\nimport (\n\t\"testing\"\n\n\t\"example.com/triangle/r\"\n)\n\nfunc TestExternal(t *testing.T) { r.Use() }\n",
			"r/r.go":        rSource,
		} {
			path := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		// The assertions below hold vacuously if the recompiled dependency
		// variant stops materializing, so its presence is load-bearing.
		cfg := &packages.Config{
			Mode:  packages.NeedName | packages.NeedForTest | packages.NeedImports | packages.NeedDeps,
			Tests: true,
			Dir:   dir,
		}
		loaded, err := packages.Load(cfg, "example.com/triangle/a")
		if err != nil {
			t.Fatalf("variant guard load: %v", err)
		}
		variant := false
		packages.Visit(loaded, nil, func(p *packages.Package) {
			if p.PkgPath == "example.com/triangle/r" && p.ForTest == "example.com/triangle/a" {
				variant = true
			}
		})
		if !variant {
			t.Fatal("fixture no longer yields the recompiled dependency variant r [a.test]; the assertions below would hold vacuously")
		}
		return dir
	}

	t.Run("shared name is no root collision", func(t *testing.T) {
		dir := writeTriangle(t,
			"package a\n\nfunc G() {}\n",
			"package r\n\nimport \"example.com/triangle/a\"\n\nfunc Use() { a.G() }\n\nfunc G() {}\n",
		)
		h, err := NewAt(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, os.Environ()))
		if err != nil {
			t.Fatalf("NewAt: %v", err)
		}
		_, reach, err := computeTier2ResultAndReach(h, "example.com/triangle/a", "G")
		if err != nil {
			t.Fatalf("analysis of a.G with a same-named dependency symbol: %v", err)
		}
		if len(reach) == 0 {
			t.Fatal("empty reachability for a's own G")
		}
	})

	t.Run("dependency symbol is not rootable under the tested package", func(t *testing.T) {
		dir := writeTriangle(t,
			"package a\n\nfunc A() {}\n",
			"package r\n\nimport \"example.com/triangle/a\"\n\nfunc Use() { a.A() }\n",
		)
		h, err := NewAt(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, os.Environ()))
		if err != nil {
			t.Fatalf("NewAt: %v", err)
		}
		fixtures := newFixturePrograms(t, h)
		fixtures.supply(t, "example.com/triangle/a")
		if _, reach, err := computeTier2ResultAndReach(h, "example.com/triangle/a", "A"); err != nil || len(reach) == 0 {
			t.Fatalf("analysis of a.A: reach %v, %v; want a's own subject to resolve", reach, err)
		}
		fixtures.supply(t, "example.com/triangle/a")
		if _, err := computeTier2Result(h, "example.com/triangle/a", "Use"); err == nil {
			t.Fatal("analysis of a.Use: want an error (a never declares Use), got the recompiled dependency's closure")
		}
	})
}

func TestOpenFileFlagsUseSelectedGOOS(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine over the fixture corpus")
	}
	env := append([]string(nil), os.Environ()...)
	found := false
	for i, entry := range env {
		if strings.HasPrefix(entry, "GOOS=") {
			env[i] = "GOOS=plan9"
			found = true
		}
	}
	if !found {
		env = append(env, "GOOS=plan9")
	}
	h, err := newAtEnv(context.Background(), "", env)
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/observablefresh"
	subjects := []Subject{
		{Package: pkg, Symbol: "TestTempDirOpenFile"},
		{Package: pkg, Symbol: "TestOpenFileUnknownFlags"},
	}
	results, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	if !results[subjects[0]].Observable {
		t.Fatalf("Plan 9 recognized flags = %+v, want observable", results[subjects[0]])
	}
	if results[subjects[1]].Observable {
		t.Fatalf("Plan 9 unknown flags = %+v, want blocked", results[subjects[1]])
	}
}

func TestNonInternalDelegatesAdmittedOnlyThroughAuditedStdCallers(t *testing.T) {
	if testing.Short() {
		t.Skip("builds whole-program SSA over a temporary module")
	}
	isolateProofCache(t)
	dir := t.TempDir()
	const pkg = "example.com/noninternal"
	writeTree(t, dir, map[string]string{
		"go.mod": "module " + pkg + "\n\ngo 1.26\n",
		"p_test.go": `package noninternal

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/json"
	"hash"
	"io"
	"testing"
)

func TestAdmittedSHA256AndJSON(t *testing.T) {
	var h hash.Hash = sha256.New()
	_, _ = h.Write([]byte("ok"))
	_ = h.Sum(nil)
	m := json.RawMessage(` + "`" + `{"a":1}` + "`" + `)
	_, _ = m.MarshalJSON()
	var marshaler json.Marshaler = m
	if _, err := marshaler.MarshalJSON(); err != nil {
		_ = err.Error()
	}
}

func TestDirectSHA3Static(t *testing.T) {
	h := sha3.New256()
	_, _ = h.Write([]byte("x"))
}

func TestDirectSHA3FuncValue(t *testing.T) {
	fn := sha3.New256
	_ = fn()
}

func TestDirectSHA3Invoke(t *testing.T) {
	var d sha3.SHA3
	var w io.Writer = &d
	_, _ = w.Write([]byte("x"))
}

func TestCryptoRegisterHash(t *testing.T) {
	crypto.RegisterHash(crypto.SHA256, sha256.New)
}
`,
		"jsonv2_direct_test.go": `//go:build goexperiment.jsonv2

package noninternal

import (
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"testing"
)

func TestDirectJSONTextStatic(t *testing.T) {
	_ = jsontext.Value("{}").IsValid()
}

func TestDirectJSONTextFuncValue(t *testing.T) {
	fn := jsontext.Value.IsValid
	_ = fn(jsontext.Value("{}"))
}

func TestDirectJSONTextInvoke(t *testing.T) {
	var m json.Marshaler = jsontext.Value("{}")
	_, err := m.MarshalJSON()
	if err != nil {
		_ = err.Error()
	}
}

func TestDirectJSONV2Static(t *testing.T) {
	_, _ = jsonv2.Marshal(1)
}

func TestDirectJSONV2FuncValue(t *testing.T) {
	fn := jsonv2.Marshal
	_, _ = fn(1)
}

func TestDirectJSONV2Invoke(t *testing.T) {
	var err error = &jsonv2.SemanticError{}
	_ = err.Error()
}
`,
	})
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !h.SelectionAudited() {
		t.Fatalf("running toolchain not audited: %s", h.SelectionNotice())
	}
	subjects := []Subject{
		{Package: pkg, Symbol: "TestAdmittedSHA256AndJSON"},
		{Package: pkg, Symbol: "TestDirectSHA3Static"},
		{Package: pkg, Symbol: "TestDirectSHA3FuncValue"},
		{Package: pkg, Symbol: "TestDirectSHA3Invoke"},
		{Package: pkg, Symbol: "TestCryptoRegisterHash"},
	}
	batched, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	if obs := batched[subjects[0]]; !obs.Observable {
		t.Fatalf("TestAdmittedSHA256AndJSON refused: %+v", obs)
	}
	for _, s := range subjects[1:] {
		if obs := batched[s]; obs.Observable {
			t.Fatalf("%s admitted despite direct reference to unaudited public package: %+v", s.Symbol, obs)
		}
		soloH, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		solo, err := soloH.ComputeObservabilityBatch([]Subject{s})
		if err != nil {
			t.Fatal(err)
		}
		if batched[s] != solo[s] {
			t.Fatalf("%s batch (%+v) != solo (%+v)", s.Symbol, batched[s], solo[s])
		}
	}

	// Under GOEXPERIMENT=jsonv2, json.RawMessage is a type alias for
	// encoding/json/jsontext.Value: user code importing only "encoding/json"
	// remains admitted, while direct user references to non-internal pure
	// delegates remain refused.
	jsonV2Hasher, err := newAtEnv(context.Background(), dir, environmentWith("GOEXPERIMENT=jsonv2"))
	if err != nil {
		t.Fatal(err)
	}
	if !jsonV2Hasher.SelectionAudited() {
		t.Fatalf("GOEXPERIMENT=jsonv2 selection not audited: %s", jsonV2Hasher.SelectionNotice())
	}
	jsonV2Subjects := []Subject{
		subjects[0],
		{Package: pkg, Symbol: "TestDirectJSONTextStatic"},
		{Package: pkg, Symbol: "TestDirectJSONTextFuncValue"},
		{Package: pkg, Symbol: "TestDirectJSONTextInvoke"},
		{Package: pkg, Symbol: "TestDirectJSONV2Static"},
		{Package: pkg, Symbol: "TestDirectJSONV2FuncValue"},
		{Package: pkg, Symbol: "TestDirectJSONV2Invoke"},
	}
	jsonV2Obs, err := jsonV2Hasher.ComputeObservabilityBatch(jsonV2Subjects)
	if err != nil {
		t.Fatal(err)
	}
	if obs := jsonV2Obs[jsonV2Subjects[0]]; !obs.Observable {
		t.Fatalf("TestAdmittedSHA256AndJSON refused under GOEXPERIMENT=jsonv2: %+v", obs)
	}
	for _, s := range jsonV2Subjects[1:] {
		if obs := jsonV2Obs[s]; obs.Observable {
			t.Fatalf("%s admitted under GOEXPERIMENT=jsonv2 despite direct user reference: %+v", s.Symbol, obs)
		}
	}
	if got := jsonV2Obs[Subject{Package: pkg, Symbol: "TestDirectJSONTextInvoke"}].Reason; !strings.HasPrefix(got, "subject reachability is not closed:") {
		t.Fatalf("TestDirectJSONTextInvoke reason = %q, want closed-invoke provenance refusal", got)
	}
	if t2Admitted, _, err := computeTier2ResultAndReach(jsonV2Hasher, pkg, "TestAdmittedSHA256AndJSON"); err != nil {
		t.Fatal(err)
	} else if t2Admitted.unverifiable || t2Admitted.widen {
		t.Fatalf("TestAdmittedSHA256AndJSON tier2 refused under GOEXPERIMENT=jsonv2: %+v", t2Admitted)
	}
	for _, sym := range []string{"TestDirectJSONTextStatic", "TestDirectJSONTextFuncValue"} {
		t2, _, err := computeTier2ResultAndReach(jsonV2Hasher, pkg, sym)
		if err != nil {
			t.Fatal(err)
		}
		if !t2.unverifiable || !strings.Contains(t2.reason, "encoding/json/jsontext") {
			t.Fatalf("%s tier2 = %+v, want unaudited encoding/json/jsontext refusal", sym, t2)
		}
	}
	if t2Inv, _, err := computeTier2ResultAndReach(jsonV2Hasher, pkg, "TestDirectJSONTextInvoke"); err != nil {
		t.Fatal(err)
	} else if !t2Inv.widen {
		t.Fatalf("TestDirectJSONTextInvoke tier2 = %+v, want widen=true", t2Inv)
	}
	reversed := slices.Clone(jsonV2Subjects)
	slices.Reverse(reversed)
	jsonV2HasherRev, err := newAtEnv(context.Background(), dir, environmentWith("GOEXPERIMENT=jsonv2"))
	if err != nil {
		t.Fatal(err)
	}
	jsonV2ObsRev, err := jsonV2HasherRev.ComputeObservabilityBatch(reversed)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range jsonV2Subjects {
		if jsonV2Obs[s] != jsonV2ObsRev[s] {
			t.Fatalf("%s order-dependent observability under GOEXPERIMENT=jsonv2: forward=%+v reverse=%+v", s.Symbol, jsonV2Obs[s], jsonV2ObsRev[s])
		}
	}
}

func TestNonInternalDelegateCrossPackageAndSiblingIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns go list and loads standard library")
	}
	isolateProofCache(t)

	dir := t.TempDir()
	const mod = "example.com/mod"
	writeTree(t, dir, map[string]string{
		"go.mod": "module " + mod + "\n\ngo 1.26\n",
		"pkga/a.go": `package pkga

import "crypto/sha3"

type SHA3Holder struct {
	D sha3.SHA3
}

type SHA3Alias = sha3.SHA3
`,
		"pkga/a_jsonv2.go": `//go:build goexperiment.jsonv2

package pkga

import "encoding/json/jsontext"

type JSONHolder struct {
	V jsontext.Value
}

type ValAlias = jsontext.Value
`,
		"pkgb/b_test.go": `package pkgb

import (
	"encoding/json"
	"io"
	"testing"

	"` + "example.com/mod/pkga" + `"
)

//go:noinline
func callWriter(w io.Writer) error {
	_, err := w.Write([]byte("x"))
	return err
}

func TestCrossPkgSHA3FieldStatic(t *testing.T) {
	var h pkga.SHA3Holder
	_, _ = h.D.Write([]byte("x"))
}

func TestCrossPkgSHA3FieldInvoke(t *testing.T) {
	var h pkga.SHA3Holder
	if err := callWriter(&h.D); err != nil {
		_ = err.Error()
	}
}

func TestCrossPkgSHA3AliasFuncValue(t *testing.T) {
	var d pkga.SHA3Alias
	fn := d.Write
	_, _ = fn([]byte("x"))
}

func TestCleanRawMessageCrossPkg(t *testing.T) {
	m := json.RawMessage("{}")
	_, _ = m.MarshalJSON()
}
`,
		"pkgb/b_jsonv2_test.go": `//go:build goexperiment.jsonv2

package pkgb

import (
	"encoding/json"
	"testing"

	"` + "example.com/mod/pkga" + `"
)

//go:noinline
func callMarshaler(m json.Marshaler) ([]byte, error) {
	return m.MarshalJSON()
}

func TestCrossPkgJSONFieldStatic(t *testing.T) {
	h := pkga.JSONHolder{V: pkga.ValAlias("{}")}
	_ = h.V.IsValid()
}

func TestCrossPkgJSONAliasFuncValue(t *testing.T) {
	fn := pkga.ValAlias.IsValid
	_ = fn(pkga.ValAlias("{}"))
}

func TestCrossPkgJSONFieldInvoke(t *testing.T) {
	h := pkga.JSONHolder{V: pkga.ValAlias("{}")}
	if _, err := callMarshaler(h.V); err != nil {
		_ = err.Error()
	}
}

func TestCrossPkgJSONAliasInvoke(t *testing.T) {
	var v pkga.ValAlias = pkga.ValAlias("{}")
	if _, err := callMarshaler(v); err != nil {
		_ = err.Error()
	}
}
`,
		"isolated/clean_test.go": `package isolated

import (
	"encoding/json"
	"testing"
)

//go:noinline
func callIsolatedMarshaler(m json.Marshaler) ([]byte, error) {
	return m.MarshalJSON()
}

func TestCleanRawMessageSibling(t *testing.T) {
	raw := json.RawMessage(` + "`" + `{"k":1}` + "`" + `)
	if _, err := callIsolatedMarshaler(raw); err != nil {
		_ = err.Error()
	}
}
`,
		"isolated/dirty_jsonv2_test.go": `//go:build goexperiment.jsonv2

package isolated

import (
	"encoding/json/jsontext"
	"testing"
)

func TestDirtyDirectJSONTextSibling(t *testing.T) {
	if _, err := callIsolatedMarshaler(jsontext.Value("{}")); err != nil {
		_ = err.Error()
	}
}
`,
	})

	pkgB := mod + "/pkgb"
	pkgIso := mod + "/isolated"

	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	sha3Subjects := []Subject{
		{Package: pkgB, Symbol: "TestCleanRawMessageCrossPkg"},
		{Package: pkgB, Symbol: "TestCrossPkgSHA3FieldStatic"},
		{Package: pkgB, Symbol: "TestCrossPkgSHA3FieldInvoke"},
		{Package: pkgB, Symbol: "TestCrossPkgSHA3AliasFuncValue"},
	}
	sha3Obs, err := h.ComputeObservabilityBatch(sha3Subjects)
	if err != nil {
		t.Fatal(err)
	}
	if !sha3Obs[sha3Subjects[0]].Observable {
		t.Fatalf("TestCleanRawMessageCrossPkg refused: %+v", sha3Obs[sha3Subjects[0]])
	}
	for _, s := range sha3Subjects[1:] {
		if sha3Obs[s].Observable {
			t.Fatalf("%s admitted despite cross-package crypto/sha3 exposure: %+v", s.Symbol, sha3Obs[s])
		}
		t2, _, err := computeTier2ResultAndReach(h, s.Package, s.Symbol)
		if err != nil {
			t.Fatal(err)
		}
		if !t2.unverifiable && !t2.widen {
			t.Fatalf("%s tier2 admitted cross-package crypto/sha3 exposure: %+v", s.Symbol, t2)
		}
	}

	jsonV2Env := environmentWith("GOEXPERIMENT=jsonv2")
	jh, err := newAtEnv(t.Context(), dir, jsonV2Env)
	if err != nil {
		t.Fatal(err)
	}
	if !jh.SelectionAudited() {
		t.Fatalf("GOEXPERIMENT=jsonv2 selection not audited: %s", jh.SelectionNotice())
	}
	crossJSONSubjects := []Subject{
		{Package: pkgB, Symbol: "TestCleanRawMessageCrossPkg"},
		{Package: pkgB, Symbol: "TestCrossPkgJSONFieldStatic"},
		{Package: pkgB, Symbol: "TestCrossPkgJSONAliasFuncValue"},
		{Package: pkgB, Symbol: "TestCrossPkgJSONFieldInvoke"},
		{Package: pkgB, Symbol: "TestCrossPkgJSONAliasInvoke"},
	}
	crossObs, err := jh.ComputeObservabilityBatch(crossJSONSubjects)
	if err != nil {
		t.Fatal(err)
	}
	if !crossObs[crossJSONSubjects[0]].Observable {
		t.Fatalf("TestCleanRawMessageCrossPkg refused under jsonv2: %+v", crossObs[crossJSONSubjects[0]])
	}
	for _, s := range crossJSONSubjects[1:] {
		if crossObs[s].Observable {
			t.Fatalf("%s admitted despite cross-package jsontext exposure: %+v", s.Symbol, crossObs[s])
		}
		t2, _, err := computeTier2ResultAndReach(jh, s.Package, s.Symbol)
		if err != nil {
			t.Fatal(err)
		}
		if !t2.unverifiable && !t2.widen {
			t.Fatalf("%s tier2 admitted cross-package jsontext exposure: %+v", s.Symbol, t2)
		}
	}

	// Sibling-test batch equivalence: importing encoding/json/jsontext in
	// dirty_jsonv2_test.go must not poison TestCleanRawMessageSibling in
	// clean_test.go, regardless of batch order or solo execution.
	cleanSubj := Subject{Package: pkgIso, Symbol: "TestCleanRawMessageSibling"}
	dirtySubj := Subject{Package: pkgIso, Symbol: "TestDirtyDirectJSONTextSibling"}

	jhIso1, err := newAtEnv(t.Context(), dir, jsonV2Env)
	if err != nil {
		t.Fatal(err)
	}
	batch1, err := jhIso1.ComputeObservabilityBatch([]Subject{cleanSubj, dirtySubj})
	if err != nil {
		t.Fatal(err)
	}
	jhIso2, err := newAtEnv(t.Context(), dir, jsonV2Env)
	if err != nil {
		t.Fatal(err)
	}
	batch2, err := jhIso2.ComputeObservabilityBatch([]Subject{dirtySubj, cleanSubj})
	if err != nil {
		t.Fatal(err)
	}
	jhSoloClean, err := newAtEnv(t.Context(), dir, jsonV2Env)
	if err != nil {
		t.Fatal(err)
	}
	soloClean, err := jhSoloClean.ComputeObservabilityBatch([]Subject{cleanSubj})
	if err != nil {
		t.Fatal(err)
	}
	if !batch1[cleanSubj].Observable || !batch1[cleanSubj].EffectFree {
		t.Fatalf("clean sibling refused when batched with jsontext sibling: %+v", batch1[cleanSubj])
	}
	if batch1[dirtySubj].Observable {
		t.Fatalf("dirty jsontext sibling admitted: %+v", batch1[dirtySubj])
	}
	if batch1[cleanSubj] != batch2[cleanSubj] || batch1[cleanSubj] != soloClean[cleanSubj] {
		t.Fatalf("batch equivalence violated for clean sibling: b1=%+v b2=%+v solo=%+v", batch1[cleanSubj], batch2[cleanSubj], soloClean[cleanSubj])
	}
	if t2Clean, _, err := computeTier2ResultAndReach(jhIso1, pkgIso, cleanSubj.Symbol); err != nil {
		t.Fatal(err)
	} else if t2Clean.unverifiable || t2Clean.widen {
		t.Fatalf("clean sibling tier2 poisoned by jsontext sibling: %+v", t2Clean)
	}
}

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
	rows, err := attributedReachableSets(h.Context(), h.SelectionAudited(), h.PureDelegates(), p, []Subject{subject})
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
	metas, err := h.List(p.PkgPath)
	if err != nil {
		t.Fatal(err)
	}
	base := newTier2Base(h.Hasher, p, metas)
	e.Whole, err = tier2Reachable(h.Hasher, base, r)
	if err != nil {
		t.Fatal(err)
	}
	subjectReach := r
	subjectReach.functions = r.subjectFunctions
	e.SubjectEffects, err = tier2Reachable(h.Hasher, base, subjectReach)
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
	const base = "github.com/greatliontech/gofresh/internal/closure/testdata/"
	cases := []struct {
		path, symbol string
		observable   bool
	}{
		{base + "observable", "TestReadFile", true},
		{base + "initfile", "TestInitFile", false},
		{base + "observablemutation", "TestRemove", false},
		{base + "harnessroot", "BenchmarkProd", true},
	}
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, tc := range cases {
		paths = append(paths, tc.path)
	}
	prepared, err := Prepare(h.Context(), h.Dir(), h.PackageEnv(), h.BuildFlags(), paths...)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.symbol, func(t *testing.T) {
			p, err := prepared.Build(t.Context(), tc.path)
			if err != nil {
				t.Fatal(err)
			}
			got := fixtureProgramEvidence(t, h.Dir(), p, tc.symbol)
			p, err = Load(t.Context(), h.Dir(), h.PackageEnv(), h.BuildFlags(), tc.path)
			if err != nil {
				t.Fatal(err)
			}
			want := fixtureProgramEvidence(t, h.Dir(), p, tc.symbol)
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
		prepared, err := Prepare(h.Context(), dir, h.PackageEnv(), nil, paths...)
		if err != nil {
			t.Fatal(err)
		}
		p, err := prepared.Build(t.Context(), target)
		if err != nil {
			t.Fatal(err)
		}
		got := fixtureProgramEvidence(t, dir, p, "Run")
		p, err = Load(t.Context(), dir, h.PackageEnv(), nil, target)
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

// BenchmarkFixturePreparation compares identical source-loading/SSA workloads.
// Each iteration owns a new generation, each target a fresh SSA program. Neither
// arm computes or serves proof memos. Typed-graph retention lasts one iteration;
// allocation totals are not a measurement of its live or peak resident memory.
//
//gofresh:pure
func BenchmarkFixturePreparation(b *testing.B) {
	const base = "github.com/greatliontech/gofresh/internal/closure/testdata/"
	paths := []string{base + "observable", base + "external", base + "initfile", base + "rootcollision/bench"}
	h, err := newAt("")
	if err != nil {
		b.Fatal(err)
	}
	b.Run("independent", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for _, path := range paths {
				if _, err := Load(b.Context(), h.Dir(), h.PackageEnv(), h.BuildFlags(), path); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("prepared", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			prepared, err := Prepare(b.Context(), h.Dir(), h.PackageEnv(), h.BuildFlags(), paths...)
			if err != nil {
				b.Fatal(err)
			}
			for _, path := range paths {
				if _, err := prepared.Build(b.Context(), path); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
}

// BenchmarkComputeObservabilityBatch measures the proof analyzer end to end
// over a mixed fixture set — the per-target cost a consumer's capture batch
// pays. Allocations are the tracked axis; the memo is disabled (no scope)
// so the analysis itself is measured.
//
//gofresh:pure
func BenchmarkComputeObservabilityBatch(b *testing.B) {
	const base = "github.com/greatliontech/gofresh/internal/closure/testdata/"
	subjects := []Subject{
		{Package: base + "observable", Symbol: "TestReadFile"},
		{Package: base + "observable", Symbol: "TestGetenv"},
		{Package: base + "observablebad", Symbol: "TestOpenStat"},
		{Package: base + "observablefresh", Symbol: "TestFreshFileNameEscape"},
		{Package: base + "observablemutation", Symbol: "TestRemove"},
	}
	b.ReportAllocs()
	for b.Loop() {
		h, err := newAt("")
		if err != nil {
			b.Fatal(err)
		}
		if _, err := h.ComputeObservabilityBatch(subjects); err != nil {
			b.Fatal(err)
		}
	}
}

func TestFixturePreparationLifetimeAndFailureIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("toolchain integration test")
	}
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/fixtureowner\n\ngo 1.27\n")
	for name, source := range map[string]string{"a": "func A() {}", "b": "func B() {}", "bad": "var Broken int = \"wrong\""} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, filepath.Join(name, "p.go"), "package fixture\n"+source+"\n")
	}
	const a, b, bad = "example.com/fixtureowner/a", "example.com/fixtureowner/b", "example.com/fixtureowner/bad"
	newOwner := func(t *testing.T) *fixturePrograms {
		t.Helper()
		h, err := NewAt(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, os.Environ()))
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
		owner.prepare = func(context.Context, string, []string, []string, ...string) (*Prepared, error) {
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
		owner.prepare = func(context.Context, string, []string, []string, ...string) (*Prepared, error) {
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
		ctx, cancel := context.WithCancel(owner.h.Context())
		cancel()
		_ = owner.h.WithContext(ctx, func() error {
			if err := owner.acquire(a); !errors.Is(err, context.Canceled) || owner.loaded != nil || len(owner.h.progs) != 0 {
				t.Fatalf("cancelled cached supply: %v", err)
			}
			return nil
		})
	})
}

func TestOffSurfaceTriggerRefusedWhileSiblingObservable(t *testing.T) {
	if testing.Short() {
		t.Skip("builds overlaid GOROOT and runs observability over off-surface trigger")
	}
	isolateProofCache(t)
	ctx := context.Background()
	snap, err := (gotool.Runner{}).TakeEnvSnapshot(ctx, ".", environmentWith())
	if err != nil {
		t.Fatal(err)
	}
	goroot := snap.Value("GOROOT")
	origGetwd, err := os.ReadFile(filepath.Join(goroot, "src/os/getwd.go"))
	if err != nil {
		t.Fatal(err)
	}
	origFilePosix, err := os.ReadFile(filepath.Join(goroot, "src/os/file_posix.go"))
	if err != nil {
		t.Fatal(err)
	}
	hookedGetwd := strings.Replace(
		string(origGetwd),
		"func Getwd() (dir string, err error) {\n",
		"func Getwd() (dir string, err error) {\n\tif gofreshSimOverlay {\n\t\tif wd, handled, werr := gofreshTryGetwd(); handled {\n\t\t\treturn wd, werr\n\t\t}\n\t}\n",
		1,
	)
	hookedFilePosix := strings.Replace(
		string(origFilePosix),
		"func (f *File) Close() error {\n\tif f == nil {\n\t\treturn ErrInvalid\n\t}\n",
		"func (f *File) Close() error {\n\tif f == nil {\n\t\treturn ErrInvalid\n\t}\n\tif gofreshSimOverlay {\n\t\tif s := gofreshStateOf(f.file); s != nil {\n\t\t\treturn nil\n\t\t}\n\t}\n",
		1,
	)
	const simRuntimeClean = `//go:build simoverlay

package runtime

import "internal/runtime/atomic"

var gofreshSimFlag atomic.Uint32

func gofreshSimEnable() {
	gofreshSimFlag.Store(1)
}

func gofreshSimGate() bool {
	return gofreshSimFlag.Load() != 0
}
`
	const simOSOff = `//go:build !simoverlay

package os

const gofreshSimOverlay = false

func gofreshTryGetwd() (string, bool, error) { return "", false, nil }
func gofreshStateOf(_ *file) *int            { return nil }
`
	const simOSOn = `//go:build simoverlay

package os

import (
	"runtime"
	"sync/atomic"
	"unsafe"
)

const gofreshSimOverlay = true

//go:linkname gofreshOSGate runtime.gofreshSimGate
func gofreshOSGate() bool

type gofreshSimTable[T any, S any] struct {
	spine atomic.Pointer[S]
	count int
}

func (t *gofreshSimTable[T, S]) get(idx int) *S {
	sp := t.spine.Load()
	if sp == nil || idx < 0 || idx > t.count {
		return nil
	}
	return sp
}

func (t *gofreshSimTable[T, S]) register(s *S) {
	t.count++
	t.spine.Store(s)
}

var gofreshSimStates gofreshSimTable[file, int]

func gofreshSimIdx(f *file) (int, bool) {
	return int(uintptr(unsafe.Pointer(f))), true
}

func gofreshStateOf(f *file) *int {
	idx, ok := gofreshSimIdx(f)
	if !ok {
		return nil
	}
	s := gofreshSimStates.get(idx)
	runtime.KeepAlive(f)
	return s
}

func gofreshRegisterSim(_ *file) {
	if !gofreshOSGate() {
		return
	}
	v := 1
	gofreshSimStates.register(&v)
}

func gofreshTryGetwd() (string, bool, error) {
	if !gofreshOSGate() {
		return "", false, nil
	}
	gofreshRegisterSim(nil)
	return "/sim", true, nil
}
`
	_, simValidEnv := testenv.OverlayGOROOTEnv(t, environmentWith(), map[string]string{
		"src/runtime/gofresh_sim_overlay.go":     simRuntimeClean,
		"src/os/gofresh_sim_off.go":              simOSOff,
		"src/os/gofresh_sim_on.go":               simOSOn,
		"src/os/getwd.go":                        hookedGetwd,
		"src/os/file_posix.go":                   hookedFilePosix,
		"src/image/color/gofresh_sim_trigger.go": "//go:build simoverlay\n\npackage color\n\nimport _ \"unsafe\"\n\n//go:linkname gofreshPullEnable runtime.gofreshSimEnable\nfunc gofreshPullEnable()\n\nfunc ActivateSim() { gofreshPullEnable() }\n",
	})
	modDir := t.TempDir()
	writeTree(t, modDir, map[string]string{
		"go.mod": "module example.com/offsurface\n\ngo 1.24\n",
		"sub_test.go": `package offsurface

import (
	"image/color"
	"os"
	"strings"
	"testing"
)

func TestCallsOffSurfaceTrigger(t *testing.T) {
	color.ActivateSim()
}

func TestCleanOffSurfaceSibling(t *testing.T) {
	_ = os.Getenv("GOFRESH_OFFSURFACE_CLEAN")
	if strings.TrimSpace(" ok ") != "ok" {
		t.Fatal("unexpected trim result")
	}
}
`,
	})
	modView, err := newAtEnv(ctx, modDir, simValidEnv, "-tags", "simoverlay")
	if err != nil {
		t.Fatal(err)
	}
	if !modView.SelectionAudited() {
		t.Fatalf("off-surface non-startup trigger unexpectedly invalidated selection: %s", modView.SelectionNotice())
	}
	trigSubj := Subject{Package: "example.com/offsurface", Symbol: "TestCallsOffSurfaceTrigger"}
	cleanSubj := Subject{Package: "example.com/offsurface", Symbol: "TestCleanOffSurfaceSibling"}
	obs, err := modView.ComputeObservabilityBatch([]Subject{trigSubj, cleanSubj})
	if err != nil {
		t.Fatal(err)
	}
	if obs[trigSubj].Observable {
		t.Fatalf("subject calling off-surface gate activator admitted as observable: %+v", obs[trigSubj])
	}
	t2Trig, _, err := computeTier2ResultAndReach(modView, trigSubj.Package, trigSubj.Symbol)
	if err != nil {
		t.Fatal(err)
	}
	if !t2Trig.unverifiable {
		t.Fatalf("tier2 admitted subject calling off-surface gate activator: %+v", t2Trig)
	}
	if !obs[cleanSubj].Observable {
		t.Fatalf("clean sibling subject in off-surface test refused: %+v", obs[cleanSubj])
	}
}
