package closure

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOutcomeInventorySeparatesAdmissionFromDerivation(t *testing.T) {
	if testing.Short() {
		t.Skip("builds whole-program SSA and proves outcome inventories")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the immutable environment outcome method is audited for Linux")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/outcomes\n\ngo 1.26\n")
	cases := []struct {
		name, source string
		observable   bool
		supported    bool
	}{
		{"empty", `import "testing"
func TestSubject(t *testing.T) { if 1 + 1 != 2 { t.Fatal("arithmetic") } }`, true, true},
		{"pure", `import "testing"
func TestSubject(t *testing.T) {}`, true, true},
		{"getenv", `import ("os"; "testing")
func TestSubject(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE") }`, true, true},
		{"lookup", `import ("os"; "testing")
func TestSubject(t *testing.T) { _, _ = os.LookupEnv("OUTCOME_VALUE") }`, true, true},
		{"failure", `import ("os"; "testing")
func TestSubject(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE"); t.Error("ordinary failure") }`, true, true},
		{"pacing", `import ("os"; "testing")
func BenchmarkSubject(b *testing.B) { b.ResetTimer(); b.StopTimer(); b.StartTimer(); for b.Loop() { _ = os.Getenv("OUTCOME_VALUE") }; _ = b.N }`, true, true},
		{"subtest", `import ("os"; "testing")
func TestSubject(t *testing.T) { t.Run("child", func(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE") }) }`, true, true},
		{"subtestfile", `import ("os"; "testing")
func TestSubject(t *testing.T) { t.Run("child", func(t *testing.T) { _, _ = os.ReadFile("input.txt") }) }`, true, false},
		{"file", `import ("os"; "testing")
func TestSubject(t *testing.T) { _, _ = os.ReadFile("input.txt") }`, true, false},
		{"mixed", `import ("os"; "testing")
func TestSubject(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE"); _, _ = os.ReadFile("input.txt") }`, true, false},
		{"mainenv", `import ("os"; "testing")
func TestMain(m *testing.M) { _ = os.Getenv("OUTCOME_VALUE"); os.Exit(m.Run()) }
func TestSubject(t *testing.T) {}`, true, true},
		{"mainfile", `import ("os"; "testing")
func TestMain(m *testing.M) { _, _ = os.ReadFile("input.txt"); os.Exit(m.Run()) }
func TestSubject(t *testing.T) {}`, true, false},
		{"initenv", `import ("os"; "testing")
var value = os.Getenv("OUTCOME_VALUE")
func TestSubject(t *testing.T) { _ = value }`, false, false},
		{"mutation", `import ("os"; "testing")
func TestSubject(t *testing.T) { _ = os.Setenv("OUTCOME_VALUE", "changed"); _ = os.Getenv("OUTCOME_VALUE") }`, false, false},
		{"siblingmutation", `import ("os"; "testing")
func TestOther(t *testing.T) { _ = os.Setenv("OUTCOME_VALUE", "changed") }
func TestSubject(t *testing.T) { _ = os.Getenv("OUTCOME_VALUE") }`, false, false},
		{"cleanupenv", `import ("os"; "testing")
func TestSubject(t *testing.T) { t.Cleanup(func() { _ = os.Getenv("OUTCOME_VALUE") }) }`, false, false},
		{"cleanupfile", `import ("os"; "testing")
func TestSubject(t *testing.T) { t.Cleanup(func() { _, _ = os.ReadFile("input.txt") }) }`, false, false},
	}
	var subjects []Subject
	for _, tc := range cases {
		if err := os.MkdirAll(filepath.Join(dir, tc.name), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, tc.name+"/subject_test.go", "package "+tc.name+"\n"+tc.source+"\n")
		symbol := "TestSubject"
		if tc.name == "pacing" {
			symbol = "BenchmarkSubject"
		}
		subjects = append(subjects, Subject{Package: "example.com/outcomes/" + tc.name, Symbol: symbol})
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !h.SelectionAudited() {
		t.Fatalf("test requires audited toolchain: %s", h.SelectionNotice())
	}
	scope := AnalysisScope{ProofStrategy: "outcome-inventory-test@1", Toolchain: "test-selection"}
	h.SetAnalysisScope(scope)
	cold, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for i, tc := range cases {
		proof := cold[subjects[i]]
		wantMethod := ""
		if tc.supported {
			wantMethod = ImmutableEnvironmentOutcomes
		}
		if proof.Observable != tc.observable || proof.OutcomeMethod != wantMethod {
			t.Errorf("%s = %+v; want observable=%t method=%q", tc.name, proof, tc.observable, wantMethod)
		}
	}
	warmHasher, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	warmHasher.SetAnalysisScope(scope)
	warmHasher.OnProgress(func(phase, pkg string) {
		if phase == "load" || phase == "prove" {
			t.Errorf("warm inventory recomputed %s for %s", phase, pkg)
		}
	})
	warm, err := warmHasher.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range subjects {
		if warm[subject] != cold[subject] {
			t.Errorf("warm %s = %+v; cold %+v", subject.Package, warm[subject], cold[subject])
		}
	}
	// The source model, not the analyzer's host platform, selects the method.
	other, err := newAtEnv(context.Background(), dir, environmentWith("GOOS=plan9", "GOARCH=amd64"))
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := other.ComputeObservabilityBatch(subjects[:3])
	if err != nil {
		t.Fatal(err)
	}
	for subject, proof := range proofs {
		if proof.OutcomeMethod != "" {
			t.Errorf("unaudited outcome platform granted %s: %+v", subject.Symbol, proof)
		}
	}
	// Keep the analyzed Linux snapshot and an empty effect set; independently
	// withdraw the audit verdict so neither the platform guard nor an ordinary
	// external-effect refusal can hide a missing outcome-audit prerequisite.
	unaudited, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	unaudited.selectionResolved = false
	pure := Subject{Package: "example.com/outcomes/pure", Symbol: "TestSubject"}
	unsupported, err := unaudited.ComputeObservabilityBatch([]Subject{pure})
	if err != nil {
		t.Fatal(err)
	}
	if proof := unsupported[pure]; !proof.Observable || proof.OutcomeMethod != "" {
		t.Fatalf("empty effects under unaudited Linux selection = %+v; want observable without outcome support", proof)
	}
}

func FuzzOutcomeInventoryRejectsUnsupportedEffects(f *testing.F) {
	f.Add([]byte{0, 1, 0})
	f.Add([]byte{0, 2, 1})
	f.Add([]byte{3})
	f.Add([]byte{})
	f.Add([]byte{4, 5, 6})
	f.Add([]byte{4, 7, 6})
	f.Fuzz(func(t *testing.T, grammar []byte) {
		var effects []externalEffect
		want := ImmutableEnvironmentOutcomes
		for _, b := range grammar {
			var effect externalEffect
			switch b % 8 {
			case 0:
				effect, _ = classBEffect("os", "Getenv")
				effect.observable = true
			case 1:
				effect, _ = classBEffect("os", "LookupEnv")
				effect.observable = true
			case 2:
				effect, _ = classBEffect("os", "ReadFile")
				effect.observable = true
				want = ""
			case 3:
				effect, _ = classBEffect("os", "Getenv")
				want = ""
			case 4:
				effect = harnessLoggingEffect("Error")
			case 5:
				pacing := []string{"Loop", "ResetTimer", "StartTimer", "StopTimer", "B.N"}
				effect = harnessPacingEffect(pacing[int(b/8)%len(pacing)])
			case 6:
				effect = harnessSubtestDriverEffect()
			case 7:
				effect, _ = classBEffect("testing", "TempDir")
				effect.observable = true
				want = ""
			}
			effects = append(effects, effect)
		}
		for split := 0; split <= len(effects); split++ {
			if got := immutableEnvironmentMethod(effects[:split], effects[split:]); got != want {
				t.Fatalf("partition %d of %v gave %q; want %q", split, grammar, got, want)
			}
		}
	})
}
