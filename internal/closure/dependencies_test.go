package closure

import (
	"context"
	"maps"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

func TestContentIdentityIncludesEverySelectedPackage(t *testing.T) {
	r := rand.New(rand.NewSource(310))
	for draw := 0; draw < 12; draw++ {
		dir := t.TempDir()
		inventory := surfaceListing{}
		for i := 0; i < 2+r.Intn(5); i++ {
			name := string(rune('a' + i))
			pkgDir := filepath.Join(dir, name)
			writeTree(t, pkgDir, map[string]string{"one.go": "package p\n", "two.go": "package p\nvar X = 1\n"})
			inventory.Packages = append(inventory.Packages, listedPackage{ImportPath: name, Dir: pkgDir, Files: []string{"one.go", "two.go"}, Audited: i == 0})
		}
		read := func(l surfaceListing) sourceDigests {
			t.Helper()
			d, err := digestListing(context.Background(), l)
			if err != nil {
				t.Fatal(err)
			}
			return d
		}
		base := read(inventory)
		permuted := inventory
		permuted.Packages = slices.Clone(inventory.Packages)
		r.Shuffle(len(permuted.Packages), func(i, j int) {
			permuted.Packages[i], permuted.Packages[j] = permuted.Packages[j], permuted.Packages[i]
		})
		if got := read(permuted); !reflect.DeepEqual(got, base) {
			t.Fatal("package order changed the content identity")
		}
		for i, pkg := range inventory.Packages {
			// Both files of every package, not just the audited subset.
			for _, name := range pkg.Files {
				path := filepath.Join(pkg.Dir, name)
				original, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				changedSource := append(slices.Clone(original), '\n', '/', '/', byte('a'+r.Intn(26)), '\n')
				if err := os.WriteFile(path, changedSource, 0o600); err != nil {
					t.Fatal(err)
				}
				changed := read(inventory)
				if changed.Content == base.Content {
					t.Fatalf("package %d file %s missing from content identity", i, name)
				}
				if !pkg.Audited && !reflect.DeepEqual(changed.Packages, base.Packages) {
					t.Fatal("non-audited edit changed the audited projection")
				}
				if err := os.WriteFile(path, original, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestHasherSuppliesCompleteMemoDependencies(t *testing.T) {
	caller := AnalysisScope{ProofStrategy: "proof", FactStrategy: "facts", Toolchain: "tc", BuildConfig: "bc"}
	first := (&Hasher{source: sourceDigests{Content: "source-a", Policy: "policy-a"}}).SetAnalysisScope(caller)
	for _, source := range []sourceDigests{{Content: "source-b", Policy: "policy-a"}, {Content: "source-a", Policy: "policy-b"}} {
		// Even a previously completed caller scope cannot lend its dependency.
		moved := (&Hasher{source: source}).SetAnalysisScope(first)
		if moved.Proofs() == first.Proofs() || moved.Facts() == first.Facts() || moved.TestingScan() == first.TestingScan() || moved.Scan() == first.Scan() {
			t.Fatal("hasher dependency did not replace caller scope")
		}
	}
	for _, clear := range []func(*AnalysisScope){
		func(s *AnalysisScope) { s.Toolchain = "" },
		func(s *AnalysisScope) { s.BuildConfig = "" },
		func(s *AnalysisScope) { s.toolchainContent = "" },
		func(s *AnalysisScope) { s.admissionPolicy = "" },
	} {
		partial := first
		clear(&partial)
		if partial.Proofs() != "" || partial.Facts() != "" || partial.TestingScan() != "" || partial.Scan() != "" {
			t.Fatal("partial dependency set armed a memo")
		}
	}
}

func TestAdmissionPolicyTracksInventoryNotLabels(t *testing.T) {
	original := maps.Clone(auditedLinknameTargets)
	t.Cleanup(func() { auditedLinknameTargets = original })
	base := admissionPolicy()
	if base == "" {
		t.Fatal("empty policy identity")
	}
	auditedLinknameTargets["runtime.extraTargetForTest"] = true
	if admissionPolicy() == base {
		t.Fatal("changed admission inventory did not move policy")
	}
	if (&Hasher{}).AdmissionPolicy() != "" {
		t.Fatal("an unconstructed hasher claimed a policy dependency")
	}
}

func TestPositionBearingProofMemoTracksSourceSpelling(t *testing.T) {
	if testing.Short() {
		t.Skip("derives a position-bearing refusal across a layout edit")
	}
	cache, dir := t.TempDir(), t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	const source = "package escape\nimport \"flag\"\nvar quiet bool\nfunc register(p *bool) { flag.BoolVar(p, \"memo.quiet\", false, \"fixture\") }\nfunc init() { register(&quiet) }\nfunc Prod() int { return 7 }\n"
	writeTree(t, dir, map[string]string{
		"go.mod":             "module example.com/positions\n\ngo 1.27\n",
		"escape/escape.go":   source,
		"consumer/p.go":      "package consumer\nimport \"example.com/positions/escape\"\nfunc Prod() int { return escape.Prod() }\n",
		"consumer/p_test.go": "package consumer\nimport \"testing\"\nfunc TestProd(t *testing.T) { Prod() }\n",
	})
	env := listingEnv("", "off")
	subject := Subject{Package: "example.com/positions/consumer", Symbol: "TestProd"}
	read := func() (Closure, Observability, bool) {
		t.Helper()
		h, err := NewAt(t.Context(), gotool.NewEnvReader(gotool.Runner{}, dir, env))
		if err != nil {
			t.Fatal(err)
		}
		h.SetAnalysisScope(AnalysisScope{ProofStrategy: "position-test", Toolchain: "toolchain", BuildConfig: "build"})
		cls, _, err := h.ComputeMaximalBatch([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		return cls[subject], proofs[subject], h.ServedSummary()["observability proof"][subject.Package]
	}
	before, oldProof, served := read()
	if served || oldProof.Observable || !strings.Contains(oldProof.Reason, "escape.go:4:") {
		t.Fatalf("position control: %+v served=%t", oldProof, served)
	}
	if _, unchanged, served := read(); !served || unchanged != oldProof {
		t.Fatal("unchanged proof did not serve identically")
	}
	writeTree(t, dir, map[string]string{"escape/escape.go": strings.Replace(source, "func register", "\n\nfunc register", 1)})
	after, warm, served := read()
	if before.Hash != after.Hash || before.TestVariants != after.TestVariants {
		t.Fatal("layout edit moved public canonical source equivalence")
	}
	if served || warm == oldProof || !strings.Contains(warm.Reason, "escape.go:6:") {
		t.Fatalf("stale position served=%t: %+v", served, warm)
	}
	if err := os.RemoveAll(filepath.Join(cache, "gofresh")); err != nil {
		t.Fatal(err)
	}
	_, cold, served := read()
	if served || cold != warm {
		t.Fatalf("discarded-cache proof differs: warm=%+v cold=%+v", warm, cold)
	}
}
