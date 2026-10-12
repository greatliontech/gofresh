package closure

import "testing"

func TestStandardInventoryCoversPGOCopiesWithoutLosingSourceChecks(t *testing.T) {
	h := &Hasher{source: sourceDigests{Content: "present", inventory: map[string]listedPackage{
		"internal/example": {Dir: "/goroot/src/internal/example", Files: []string{"body.go", "data.bin", "fast.s"}},
	}}}
	for _, identity := range []struct{ path, forTest string }{
		{"internal/example", ""},
		{"internal/example [example.com/p.test]", "example.com/p"},
		{"internal/example [example.com/main]", ""},
	} {
		t.Run(identity.path, func(t *testing.T) {
			base := listPkg{ImportPath: identity.path, ForTest: identity.forTest, Standard: true,
				Dir: "/goroot/src/internal/example", GoFiles: []string{"body.go"}, SFiles: []string{"fast.s"}, EmbedFiles: []string{"data.bin"}}
			if err := h.standardInventoryCovers([]listPkg{base}); err != nil {
				t.Fatalf("same selected source refused: %v", err)
			}
			for name, change := range map[string]func(*listPkg){
				"unknown source": func(p *listPkg) { p.ImportPath = "internal/unknown [example.com/p.test]" },
				"directory":      func(p *listPkg) { p.Dir = "/different/internal/example" },
				"test source":    func(p *listPkg) { p.GoFiles = []string{"body.go", "body_test.go"} },
				"missing source": func(p *listPkg) { p.GoFiles = nil },
				"assembly":       func(p *listPkg) { p.SFiles = []string{"other.s"} },
				"embed":          func(p *listPkg) { p.EmbedFiles = []string{"other.bin"} },
			} {
				t.Run(name, func(t *testing.T) {
					changed := base
					change(&changed)
					// A matching copy never covers a later mismatching copy.
					if err := h.standardInventoryCovers([]listPkg{base, changed}); err == nil {
						t.Fatal("uncovered source inherited another build copy's inventory")
					}
				})
			}
		})
	}
}
