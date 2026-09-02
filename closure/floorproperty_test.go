package closure

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// floorModule writes a small generated module whose shape is a pure
// function of the seed: a chain of packages with cross-imports, bodies
// with and without external effects, and test files on some packages.
func floorModule(t testing.TB, seed uint64) (string, []Subject) {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/floor\n\ngo 1.26\n")
	packages := int(seed%3) + 2
	var subjects []Subject
	for i := 0; i < packages; i++ {
		name := fmt.Sprintf("p%d", i)
		body := fmt.Sprintf("package %s\n\n", name)
		if i > 0 {
			body += fmt.Sprintf("import \"example.com/floor/p%d\"\n\n", i-1)
		}
		if seed>>(uint(i))&1 == 1 {
			body += "import \"os\"\n\nfunc init() { _ = os.Args }\n\n"
		}
		if i > 0 {
			body += fmt.Sprintf("func F() int { return p%d.F() + %d }\n", i-1, i)
		} else {
			body += fmt.Sprintf("func F() int { return %d }\n", int(seed%97))
		}
		write(name+"/"+name+".go", body)
		if seed>>(uint(i+3))&1 == 1 {
			write(name+"/"+name+"_test.go", fmt.Sprintf("package %s\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) { _ = F() }\n", name))
		}
		subjects = append(subjects, Subject{Package: "example.com/floor/" + name, Symbol: "F"})
	}
	return dir, subjects
}

// FuzzMaximalClosureFloor pins REQ-closure-floor as a property: the shared,
// memoized batch derivation never narrows below independent fresh
// derivation — hashes, compartments, and source sets are equal per subject —
// and the hash is sensitive to every mutable closure file (editing any
// package on the subject's import chain moves the subject's hash).
func FuzzMaximalClosureFloor(f *testing.F) {
	if testing.Short() {
		f.Skip("builds a module fixture and runs the engine over it")
	}
	f.Add(uint64(0))
	f.Add(uint64(7))
	f.Add(uint64(42))
	f.Add(uint64(255))
	f.Fuzz(func(t *testing.T, seed uint64) {
		dir, subjects := floorModule(t, seed)
		batchHasher, err := NewAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		batched, batchedSources, err := batchHasher.ComputeMaximalBatchWithSources(subjects)
		if err != nil {
			t.Fatal(err)
		}
		for _, subject := range subjects {
			fresh, err := NewAt(dir)
			if err != nil {
				t.Fatal(err)
			}
			independent, independentSources, err := fresh.ComputeMaximalBatchWithSources([]Subject{subject})
			if err != nil {
				t.Fatal(err)
			}
			if batched[subject] != independent[subject] {
				t.Fatalf("seed %d: batched %v = %+v, independent %+v", seed, subject, batched[subject], independent[subject])
			}
			if !reflect.DeepEqual(batchedSources[subject], independentSources[subject]) {
				t.Fatalf("seed %d: batched sources %v, independent %v", seed, batchedSources[subject], independentSources[subject])
			}
		}
		// Never-narrow sensitivity: editing the root package moves every
		// subject downstream of it (all subjects import transitively).
		last := subjects[len(subjects)-1]
		before := batched[last].Hash
		rootFile := filepath.Join(dir, "p0", "p0.go")
		content, err := os.ReadFile(rootFile)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rootFile, append(content, []byte("\nfunc edited() {}\n")...), 0o644); err != nil {
			t.Fatal(err)
		}
		edited, err := NewAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		after, err := edited.ComputeMaximalBatch([]Subject{last})
		if err != nil {
			t.Fatal(err)
		}
		if after[last].Hash == before {
			t.Fatalf("seed %d: a dependency edit did not move the downstream subject's hash", seed)
		}
	})
}
