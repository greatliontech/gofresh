package closure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/shapecorpus"
)

// TestLanguageShapeCanaries runs the fleet's shared shape corpus
// (shapecorpus) through this frontend — load, precise analysis,
// observability — pinning each entry's DISPOSITION, not merely the
// absence of one failure string: a probe showed the
// any-disposition tolerance green over an unjudged shape, so a
// release flipping a disposition in either direction is a red canary
// here. Runs under the CI matrix's next-rc leg like every test.
func TestLanguageShapeCanaries(t *testing.T) {
	for _, entry := range shapecorpus.Entries() {
		t.Run(entry.Name, func(t *testing.T) {
			dir := t.TempDir()
			for file, content := range entry.TestFiles() {
				if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			h, err := NewAt(dir)
			if err != nil {
				t.Errorf("canary load: %v", err)
				return
			}
			subject := Subject{Package: "example.com/shape", Symbol: "Subject"}
			if _, err := computeTier2Result(h, subject.Package, subject.Symbol); err != nil {
				t.Errorf("canary precise analysis: %v", err)
				return
			}
			proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
			if err != nil {
				t.Errorf("canary observability: %v", err)
				return
			}
			proof, ok := proofs[subject]
			if !ok {
				t.Errorf("canary produced no disposition: %+v", proofs)
				return
			}
			if proof.Observable != entry.SubjectObservable {
				t.Errorf("disposition = %+v, corpus pins observable=%v", proof, entry.SubjectObservable)
			}
			if entry.SubjectReason != "" && !strings.Contains(proof.Reason, entry.SubjectReason) {
				t.Errorf("refusal reason %q does not carry the pinned cause %q", proof.Reason, entry.SubjectReason)
			}
			if strings.Contains(proof.Reason, "unsupported analysis shape") {
				t.Errorf("canary refused on an analysis-class failure: %+v", proof)
			}
		})
	}
}
