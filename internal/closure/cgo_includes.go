package closure

import (
	"fmt"

	"github.com/greatliontech/gofresh/internal/cprep"
)

func cgoPkgConfig(p *listPkg) cprep.CgoPkgConfig {
	if p == nil {
		return cprep.CgoPkgConfig{}
	}
	return cprep.CgoPkgConfig{
		Dir:         p.Dir,
		CgoCPPFLAGS: p.CgoCPPFLAGS,
		CgoCFLAGS:   p.CgoCFLAGS,
		CgoCXXFLAGS: p.CgoCXXFLAGS,
		CgoFFLAGS:   p.CgoFFLAGS,
	}
}

func cgoIncludeRootOutsideDir(p *listPkg, modCache string) string {
	return cprep.CgoIncludeRootOutsideDir(cgoPkgConfig(p), modCache)
}

func cgoEscapingInclude(p *listPkg, files []string) (string, error) {
	return cgoEscapingIncludeWith(p, files, readBytes)
}

func cgoEscapingIncludeWith(p *listPkg, files []string, read func(string) (fileBytes, error)) (string, error) {
	return cprep.CgoEscapingIncludeWith(cgoPkgConfig(p), files, func(path string) ([]byte, error) {
		fb, err := read(path)
		if err != nil {
			return nil, err
		}
		return fb.content, nil
	})
}

// ValidateMutableCgoIncludes verifies that p's cgo include roots stay inside
// p.Dir (or modCache), enumerates all package directory files under check, and
// verifies no #include directive escapes p.Dir.
func (h *Hasher) ValidateMutableCgoIncludes(check func() error, p *listPkg) ([]string, error) {
	modCache := ""
	read := readBytes
	if h != nil {
		modCache = h.modCache
		read = h.readFile
	}
	if root := cgoIncludeRootOutsideDir(p, modCache); root != "" {
		return nil, fmt.Errorf("closure: cgo include root outside package dir: %s", root)
	}
	files, err := allPackageFiles(check, p.Dir)
	if err != nil {
		return nil, err
	}
	if include, err := cgoEscapingIncludeWith(p, files, read); err != nil {
		return nil, err
	} else if include != "" {
		return nil, fmt.Errorf("closure: cgo include escapes package dir: %s", include)
	}
	return files, nil
}
