package closure

import (
	"github.com/greatliontech/gofresh/internal/closure/internal/cprep"
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
