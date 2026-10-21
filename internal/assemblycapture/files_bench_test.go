package assemblycapture

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// BenchmarkInputValidation measures complete content validation against a retained
// observation, including namespace watches and the independent read budget.
func BenchmarkInputValidation(b *testing.B) {
	if runtime.GOOS != "linux" {
		b.Skip("input observation watches require Linux")
	}
	path := filepath.Join(b.TempDir(), "input")
	data := bytes.Repeat([]byte("observed input\n"), (8<<20)/len("observed input\n"))
	if err := os.WriteFile(path, data, 0600); err != nil {
		b.Fatal(err)
	}
	limits, err := (Limits{}).normalized()
	if err != nil {
		b.Fatal(err)
	}
	inputs, err := newInputSet(b.Context(), &meter{ctx: b.Context(), limits: limits})
	if err != nil {
		b.Fatal(err)
	}
	defer inputs.close()
	if _, err := inputs.read(path); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		inputs.m = &meter{ctx: b.Context(), limits: limits}
		if err := inputs.validate(); err != nil {
			b.Fatal(err)
		}
	}
}
