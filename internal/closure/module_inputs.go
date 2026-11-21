package closure

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/greatliontech/gofresh/internal/gotool"
)

type moduleInputOptions struct {
	freshDisk          bool
	requireMainModule  bool
	emitUnmodelledDiag bool
	diagPkgPath        string
	pkgPaths           []string
}

func hasExplicitModfileFlag(goflagsEnv string, explicit []string) bool {
	goFlags, err := gotool.QuotedFields(goflagsEnv)
	if err != nil {
		return true
	}
	for _, flag := range append(goFlags, explicit...) {
		name := strings.TrimLeft(flag, "-")
		if name == "modfile" || strings.HasPrefix(name, "modfile=") {
			return true
		}
	}
	return false
}

func isDirWithin(child, parent string) bool {
	child = filepath.Clean(child)
	parent = filepath.Clean(parent)
	if child == parent {
		return true
	}
	if strings.HasSuffix(parent, string(filepath.Separator)) {
		return strings.HasPrefix(child, parent)
	}
	return strings.HasPrefix(child, parent+string(filepath.Separator))
}

// collectModuleInputs records every module/workspace resolution file and
// genuinely absent go.mod/go.work sentinel consulted by listed under h's
// working directory and environment snapshot.
//
// Soundness invariants:
//   - Intermediate directories between h.dir and the outermost containing main
//     module directory are inspected rather than assumed absent: if d/go.mod
//     exists (such as a nested workspace submodule), recordModule(d) records
//     its bytes, go.sum, vendor/modules.txt, and recursive local replacements
//     in modFiles rather than absentPaths.
//   - A path where readOne returns os.IsNotExist is recorded in absentPaths
//     only when os.Lstat also returns os.IsNotExist, failing closed on dangling
//     symlinks where os.ReadFile returns IsNotExist while os.Lstat succeeds.
//   - Local replacements in both go.mod and go.work recurse via recordModule so
//     transitive replacement chains and their go.sum/vendor files are captured.
func (h *Hasher) collectModuleInputs(opts moduleInputOptions, listed [][]listPkg) (modFiles map[string]string, absentPaths []string, ok bool) {
	if h == nil || h.snapshot == nil {
		return nil, nil, false
	}
	if hasExplicitModfileFlag(h.snapshot.Value("GOFLAGS"), h.buildFlags) {
		return nil, nil, false
	}
	readOne := h.readFile
	if opts.freshDisk {
		readOne = readBytes
	}
	modFiles = map[string]string{}
	modContents := map[string][]byte{}
	absentFiles := map[string]bool{}
	recordFile := func(path string) ([]byte, bool) {
		path = filepath.Clean(path)
		if absentFiles[path] {
			return nil, true
		}
		if content, have := modContents[path]; have {
			return content, true
		}
		fb, err := readOne(path)
		if err != nil {
			if os.IsNotExist(err) {
				if _, lstatErr := os.Lstat(path); os.IsNotExist(lstatErr) {
					absentFiles[path] = true
					return nil, true
				}
			}
			return nil, false
		}
		modFiles[path] = fb.digest()
		modContents[path] = fb.content
		return fb.content, true
	}

	seenModules := map[string]bool{}
	var recordModule func(dir string) bool
	recordModule = func(dir string) bool {
		dir = filepath.Clean(dir)
		if dir == "" || seenModules[dir] {
			return true
		}
		seenModules[dir] = true
		goMod := filepath.Join(dir, "go.mod")
		content, fileOK := recordFile(goMod)
		if !fileOK {
			return false
		}
		if _, fileOK = recordFile(filepath.Join(dir, "go.sum")); !fileOK {
			return false
		}
		if _, fileOK = recordFile(filepath.Join(dir, "vendor", "modules.txt")); !fileOK {
			return false
		}
		if content == nil {
			return true
		}
		f, err := modfile.Parse(goMod, content, nil)
		if err != nil {
			if opts.emitUnmodelledDiag {
				h.emitDiagnostic("listing-unmodelled", opts.diagPkgPath, goMod+": "+err.Error()+"; the listing is spawned every pass")
			}
			return false
		}
		for _, r := range f.Replace {
			if r.New.Version != "" {
				continue
			}
			target := r.New.Path
			if !filepath.IsAbs(target) {
				target = filepath.Join(dir, target)
			}
			if !recordModule(target) {
				return false
			}
		}
		return true
	}

	seenMain := map[string]bool{}
	var mainDirs []string
	addMainDir := func(d string) {
		d = filepath.Clean(d)
		if d != "" && !seenMain[d] {
			seenMain[d] = true
			mainDirs = append(mainDirs, d)
		}
	}

	for i, pkgs := range listed {
		pkgPath := ""
		if i < len(opts.pkgPaths) {
			pkgPath = opts.pkgPaths[i]
		}
		for _, p := range pkgs {
			isGenTestMain := (pkgPath != "" && p.IsGeneratedTestMainFor(pkgPath)) ||
				(pkgPath == "" && p.Name == "main" && strings.HasSuffix(p.ImportPath, ".test"))
			if p.Standard || p.Module == nil || h.pinnedPackage(&p) || isGenTestMain {
				continue
			}
			if p.Module.Dir != "" {
				cleanModDir := filepath.Clean(p.Module.Dir)
				if p.Module.Main {
					addMainDir(cleanModDir)
				}
				if !recordModule(cleanModDir) {
					return nil, nil, false
				}
			}
			if p.Module.GoMod != "" && p.Module.GoMod != os.DevNull {
				goModDir := filepath.Clean(filepath.Dir(p.Module.GoMod))
				if p.Module.Main {
					addMainDir(goModDir)
				}
				if !recordModule(goModDir) {
					return nil, nil, false
				}
			}
		}
	}

	if gomod := h.snapshot.Value("GOMOD"); gomod != "" && gomod != os.DevNull {
		gomod = filepath.Clean(gomod)
		gomodDir := filepath.Dir(gomod)
		if !recordModule(gomodDir) {
			return nil, nil, false
		}
		if _, exists := modContents[gomod]; exists {
			addMainDir(gomodDir)
		}
	}

	dir := filepath.Clean(h.dir)
	if !filepath.IsAbs(dir) {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, nil, false
		}
		dir = abs
	}
	evalDir := dir
	if resolved, err := filepath.EvalSymlinks(dir); err == nil && resolved != "" {
		evalDir = filepath.Clean(resolved)
	}

	switch work := h.snapshot.Value("GOWORK"); work {
	case "off":
	case "":
		walkAbsentGoWork := func(start string) bool {
			for d := start; ; d = filepath.Dir(d) {
				content, fileOK := recordFile(filepath.Join(d, "go.work"))
				if !fileOK || content != nil {
					return false
				}
				if filepath.Dir(d) == d {
					return true
				}
			}
		}
		if !walkAbsentGoWork(dir) || (evalDir != dir && !walkAbsentGoWork(evalDir)) {
			return nil, nil, false
		}
	default:
		work = filepath.Clean(work)
		content, fileOK := recordFile(work)
		if !fileOK {
			return nil, nil, false
		}
		if content == nil {
			if opts.emitUnmodelledDiag {
				h.emitDiagnostic("listing-unmodelled", opts.diagPkgPath, work+": the workspace file the environment resolved is absent; the listing is spawned every pass")
			}
			return nil, nil, false
		}
		if _, fileOK = recordFile(strings.TrimSuffix(work, ".work") + ".work.sum"); !fileOK {
			return nil, nil, false
		}
		workDir := filepath.Dir(work)
		if _, fileOK = recordFile(filepath.Join(workDir, "vendor", "modules.txt")); !fileOK {
			return nil, nil, false
		}
		wf, err := modfile.ParseWork(work, content, nil)
		if err != nil {
			if opts.emitUnmodelledDiag {
				h.emitDiagnostic("listing-unmodelled", opts.diagPkgPath, work+": "+err.Error()+"; the listing is spawned every pass")
			}
			return nil, nil, false
		}
		for _, use := range wf.Use {
			target := use.Path
			if !filepath.IsAbs(target) {
				target = filepath.Join(workDir, target)
			}
			target = filepath.Clean(target)
			if !recordModule(target) {
				return nil, nil, false
			}
			if _, exists := modContents[filepath.Join(target, "go.mod")]; exists {
				addMainDir(target)
			}
		}
		for _, r := range wf.Replace {
			if r.New.Version != "" {
				continue
			}
			target := r.New.Path
			if !filepath.IsAbs(target) {
				target = filepath.Join(workDir, target)
			}
			if !recordModule(target) {
				return nil, nil, false
			}
		}
	}

	mainDir := ""
	walkStartDir := dir
	for _, candidate := range mainDirs {
		if isDirWithin(dir, candidate) && (mainDir == "" || len(candidate) < len(mainDir)) {
			mainDir = candidate
			walkStartDir = dir
		}
	}
	if mainDir == "" && evalDir != dir {
		for _, candidate := range mainDirs {
			evalCand := candidate
			if rc, err := filepath.EvalSymlinks(candidate); err == nil && rc != "" {
				evalCand = filepath.Clean(rc)
			}
			if isDirWithin(evalDir, evalCand) && (mainDir == "" || len(evalCand) < len(mainDir)) {
				mainDir = evalCand
				walkStartDir = evalDir
			}
		}
	}
	if mainDir == "" {
		if opts.requireMainModule {
			return nil, nil, false
		}
	} else {
		if _, fileOK := recordFile(filepath.Join(mainDir, "vendor", "modules.txt")); !fileOK {
			return nil, nil, false
		}
		for d := walkStartDir; ; d = filepath.Dir(d) {
			content, fileOK := recordFile(filepath.Join(d, "go.mod"))
			if !fileOK {
				return nil, nil, false
			}
			if content != nil {
				if !recordModule(d) {
					return nil, nil, false
				}
			}
			if d == mainDir || filepath.Dir(d) == d {
				break
			}
		}
	}

	absentPaths = make([]string, 0, len(absentFiles))
	for path := range absentFiles {
		absentPaths = append(absentPaths, path)
	}
	sort.Strings(absentPaths)
	return modFiles, absentPaths, true
}
