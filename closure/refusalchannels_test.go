package closure

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Every ambient-effect reason — a network, plugin, or native reach,
// symbol-level or package-level, opaque or named — carries the
// subject-level discharge channel, composed by the constructors so no
// site can omit it; the kinds whose lift lives elsewhere (the
// observation bracket, the toolchain audit) carry none
// (REQ-closure-refusal-channels).
func TestAmbientEffectReasonsNameTheirDischargeChannel(t *testing.T) {
	const channel = " (dischargeable by restructuring the subject away from the reach, or by " + PurityResponsibility + ")"
	carrying := []externalEffect{
		symbolExternalEffect(externalEffectNetwork, "net", "Dial", "reaches net.Dial (network I/O)"),
		symbolExternalEffect(externalEffectPlugin, "plugin", "Open", "reaches plugin.Open"),
		opaqueExternalEffect(externalEffectNative, "reaches cgo external library"),
		trueExternalEffect("syscall"),
		trueExternalEffect("net/http"),
		trueExternalEffect("plugin"),
	}
	for _, effect := range carrying {
		if !strings.HasSuffix(effect.reason, channel) {
			t.Fatalf("%v reason %q carries no discharge channel", effect.kind, effect.reason)
		}
		if strings.Count(effect.reason, "dischargeable") != 1 {
			t.Fatalf("%v reason %q composes the channel more than once", effect.kind, effect.reason)
		}
	}
	if got := trueExternalEffect("syscall").reason; got != "reaches syscall (external system call)"+channel {
		t.Fatalf("native package reason = %q", got)
	}
	bare := []externalEffect{
		symbolExternalEffect(externalEffectFileIO, "os", "File.Read", "reaches os.File.Read on an unattributed file handle (file I/O)"),
		symbolExternalEffect(externalEffectUnauditedStandard, "fmt", "State", "reaches unaudited standard operation fmt.State"),
		symbolExternalEffect(externalEffectFilesystemMutation, "os", "OpenFile", "reaches os.OpenFile (filesystem mutation)"),
		opaqueExternalEffect(externalEffectLinkage, "reaches go:linkname (opaque linkage)"),
	}
	for _, effect := range bare {
		if strings.Contains(effect.reason, "dischargeable") {
			t.Fatalf("%v reason %q names a channel it does not afford", effect.kind, effect.reason)
		}
	}
}

// The observability tier attributes an unaudited selection at the
// batch's return — past the memo, so a cold pass and a warm pass served
// from the memo render the same single attribution — and an audited
// selection attributes nothing (REQ-closure-refusal-channels,
// REQ-closure-observability-memo).
func TestObservabilityRefusalAttributesTheUnauditedSelection(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  "module example.com/attributed\n\ngo 1.26\n",
		"read.go": "package attributed\n\nimport \"os\"\n\nfunc Read(name string) int {\n\tb, _ := os.ReadFile(name)\n\treturn len(b)\n}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	subject := Subject{Package: "example.com/attributed", Symbol: "Read"}
	axis := " (judged under an unaudited toolchain selection: selection \"dst\" under " + runtime.Version() + " is unwalked)"
	var cold Observability
	for pass, want := range []int{1, 0} {
		h, err := NewAt(dir, "-tags=dst")
		if err != nil {
			t.Fatal(err)
		}
		h.SetAnalysisScope(AnalysisScope{ProofStrategy: "p", Toolchain: "t", BuildConfig: "dst"})
		loads := 0
		h.OnProgress(func(phase, _ string) {
			if phase == "load" || phase == "prove" {
				loads++
			}
		})
		proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		if (loads == 0) != (want == 0) {
			t.Fatalf("pass %d emitted %d load/prove events, want %s", pass, loads, map[int]string{1: "a cold derivation", 0: "a memo serve"}[want])
		}
		proof := proofs[subject]
		if proof.Observable || !strings.HasSuffix(proof.Reason, axis) || strings.Count(proof.Reason, "judged under") != 1 {
			t.Fatalf("pass %d under dst: %+v, want the refusal with the axis appended once", pass, proof)
		}
		if pass == 0 {
			cold = proof
		} else if proof != cold {
			t.Fatalf("warm proof %+v differs from cold %+v", proof, cold)
		}
	}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if proof := proofs[subject]; strings.Contains(proof.Reason, "judged under") {
		t.Fatalf("audited selection attributed: %+v", proof)
	}
}
