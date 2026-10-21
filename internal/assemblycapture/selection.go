package assemblycapture

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/buildflags"
	"golang.org/x/mod/modfile"
)

// Request is the original root compilation selection. Flags are ordered Go
// command flags, never replacement compiler options. Tests selects go test -c.
type Request struct {
	Dir               string
	Env, Flags, Roots []string
	Tests             bool
}

// Package is a selection projection; ID retains Go's test and PGO decorations.
// Imports maps source import strings to exact selected package instances.
type Package struct {
	ID, Path, Name, Dir, ForTest          string
	Standard, Root                        bool
	GoFiles, Assembly, Opaque, EmbedFiles []string
	Imports                               map[string]string
}

type listedModule struct {
	Path, Dir, GoMod, GoVersion string
	Main                        bool
	Replace                     *listedModule
}
type listedPackage struct {
	ImportPath, Name, Dir, ForTest                                                                                                                string
	Standard, DepOnly, Incomplete                                                                                                                 bool
	GoFiles, CompiledGoFiles, CgoFiles, CFiles, CXXFiles, MFiles, HFiles, FFiles, SFiles, SwigFiles, SwigCXXFiles, SysoFiles, EmbedFiles, Imports []string
	ImportMap                                                                                                                                     map[string]string
	Module                                                                                                                                        *listedModule
	Error                                                                                                                                         *struct{ Err string }
}

// Selection is a load-time source/build observation. BeginSelection establishes
// its first observation before parsing; Seal completes the agreement with the
// exact parser inputs. An unsealed selection cannot acquire assembly evidence.
type Selection struct {
	runner      gotool.Runner
	request     Request
	goenv       map[string]string
	goIdentity  string
	listed      []listedPackage
	packages    map[string]Package
	files       map[string]fileObservation
	directories map[string][]string
	parsed      map[string][]byte
	rootIDs     []string
	sealed      bool
}

func contained(r gotool.Runner) gotool.Runner {
	if r.Containment == nil {
		r.Containment = &gotool.Containment{}
	}
	return r
}

// BeginSelection observes the original request and every selected input before
// the typed loader consumes it. It performs no assembly semantic interpretation.
func BeginSelection(ctx context.Context, runner gotool.Runner, request Request) (*Selection, error) {
	if ctx == nil {
		return nil, fmt.Errorf("assembly capture: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := gotool.CanonicalDir(request.Dir)
	if err != nil {
		return nil, err
	}
	env, err := gotool.EnvForCommand(request.Env, dir)
	if err != nil {
		return nil, err
	}
	if _, err := gotool.EnvForPackages(env); err != nil {
		return nil, err
	}
	request = Request{Dir: dir, Env: env, Flags: slices.Clone(request.Flags), Roots: slices.Clone(request.Roots), Tests: request.Tests}
	if len(request.Roots) == 0 {
		return nil, fmt.Errorf("assembly capture: root request absent")
	}
	s := &Selection{runner: contained(runner), request: request, packages: map[string]Package{}, files: map[string]fileObservation{}, directories: map[string][]string{}}
	snapshot, err := s.runner.TakeEnvSnapshot(ctx, dir, env)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(snapshot.JSON, &s.goenv); err != nil {
		return nil, err
	}
	s.goIdentity = snapshot.Identity()
	if err = s.validateRequest(); err != nil {
		return nil, err
	}
	s.listed, err = s.list(ctx)
	if err != nil {
		return nil, err
	}
	limits, _ := (Limits{}).normalized()
	m := &meter{ctx: ctx, limits: limits}
	if err = s.collect(ctx, m); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Selection) validateRequest() error {
	flags, err := buildflags.Fields(s.goenv["GOFLAGS"])
	if err != nil {
		return err
	}
	flags = append(flags, s.request.Flags...)
	for i := 0; i < len(flags); i++ {
		name, _, _ := strings.Cut(strings.TrimLeft(flags[i], "-"), "=")
		switch name {
		case "toolexec":
			return fmt.Errorf("assembly capture: preexisting -toolexec is unsupported")
		case "overlay":
			return fmt.Errorf("assembly capture: overlay-backed typed selection is unsupported")
		case "n":
			return fmt.Errorf("assembly capture: nonexecuting -n request is unsupported")
		case "o":
			if !strings.Contains(flags[i], "=") {
				i++
				if i >= len(flags) {
					return fmt.Errorf("assembly capture: missing output destination")
				}
			}
		case "compiler":
			value, ok := strings.CutPrefix(flags[i], "-compiler=")
			if !ok && i+1 < len(flags) {
				i++
				value = flags[i]
			}
			if value != "gc" {
				return fmt.Errorf("assembly capture: unsupported compiler selection")
			}
		}
	}
	return nil
}

func (s *Selection) list(ctx context.Context) ([]listedPackage, error) {
	args := []string{"-json", "-deps", "-compiled"}
	if s.request.Tests {
		args = append(args, "-test")
	}
	args = append(args, s.LoadFlags()...)
	args = append(args, s.request.Roots...)
	out, err := s.runner.List(ctx, s.request.Dir, s.request.Env, args...)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(out))
	var result []listedPackage
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var p listedPackage
		if err := d.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if p.Error != nil || p.Incomplete || p.ImportPath == "" {
			return nil, fmt.Errorf("assembly capture: incomplete selected package %s: %v", p.ImportPath, p.Error)
		}
		result = append(result, p)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("assembly capture: empty selected graph")
	}
	slices.SortFunc(result, func(a, b listedPackage) int { return strings.Compare(a.ImportPath, b.ImportPath) })
	return result, nil
}

func namesInDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		// Membership, kind and symlink resolution can change selection.
		kind := e.Type().String()
		target := ""
		if e.Type()&os.ModeSymlink != 0 {
			target, err = os.Readlink(filepath.Join(dir, e.Name()))
			if err != nil {
				return nil, err
			}
		}
		names = append(names, e.Name()+"\x00"+kind+"\x00"+target)
	}
	return names, nil
}

func (s *Selection) collect(ctx context.Context, m *meter) error {
	add := func(path string) ([]byte, error) {
		if path == "" || path == "off" || path == os.DevNull {
			return nil, nil
		}
		path = absolute(s.request.Dir, path)
		if old, ok := s.files[path]; ok {
			return old.data, nil
		}
		o, err := readObservation(ctx, path, m)
		if err != nil {
			return nil, err
		}
		s.files[path] = o
		return o.data, nil
	}
	modules := map[string]bool{}
	var module func(string) error
	module = func(path string) error {
		if path == "" || modules[path] {
			return nil
		}
		modules[path] = true
		data, err := add(path)
		if err != nil {
			return err
		}
		if _, err = add(filepath.Join(filepath.Dir(path), "go.sum")); err != nil {
			return err
		}
		if _, err = add(filepath.Join(filepath.Dir(path), "vendor", "modules.txt")); err != nil {
			return err
		}
		if data == nil {
			return nil
		}
		f, err := modfile.Parse(path, data, nil)
		if err != nil {
			return err
		}
		for _, r := range f.Replace {
			if r.New.Version == "" {
				if err = module(filepath.Join(absolute(filepath.Dir(path), r.New.Path), "go.mod")); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, p := range s.listed {
		if _, exists := s.packages[p.ImportPath]; exists {
			return fmt.Errorf("assembly capture: duplicate package instance %s", p.ImportPath)
		}
		path, _, _ := strings.Cut(p.ImportPath, " [")
		view := Package{ID: p.ImportPath, Path: path, Name: p.Name, Dir: p.Dir, ForTest: p.ForTest, Standard: p.Standard, Root: !p.DepOnly, Imports: map[string]string{}}
		for _, id := range p.Imports {
			view.Imports[id] = id
		}
		for raw, id := range p.ImportMap {
			delete(view.Imports, id)
			view.Imports[raw] = id
		}
		goFiles := p.CompiledGoFiles
		if len(goFiles) == 0 {
			goFiles = p.GoFiles
		}
		for _, f := range goFiles {
			view.GoFiles = append(view.GoFiles, absolute(p.Dir, f))
		}
		for _, f := range p.SFiles {
			view.Assembly = append(view.Assembly, absolute(p.Dir, f))
		}
		for _, list := range [][]string{p.CgoFiles, p.CFiles, p.CXXFiles, p.MFiles, p.FFiles, p.SwigFiles, p.SwigCXXFiles, p.SysoFiles} {
			for _, f := range list {
				view.Opaque = append(view.Opaque, absolute(p.Dir, f))
			}
		}
		for _, f := range p.EmbedFiles {
			view.EmbedFiles = append(view.EmbedFiles, absolute(p.Dir, f))
		}
		s.packages[p.ImportPath] = view
		if p.Dir != "" {
			if _, ok := s.directories[p.Dir]; !ok {
				names, err := namesInDir(p.Dir)
				if err != nil {
					return err
				}
				s.directories[p.Dir] = names
			}
		}
		for _, list := range [][]string{view.GoFiles, view.Assembly, view.Opaque, view.EmbedFiles} {
			for _, f := range list {
				if _, err := add(f); err != nil {
					return err
				}
			}
		}
		for _, f := range p.HFiles {
			if _, err := add(absolute(p.Dir, f)); err != nil {
				return err
			}
		}
		for mod := p.Module; mod != nil; mod = mod.Replace {
			if err := module(mod.GoMod); err != nil {
				return err
			}
		}
		if p.Name == "main" {
			if _, err := add(filepath.Join(p.Dir, "default.pgo")); err != nil {
				return err
			}
		}
	}
	if err := module(s.goenv["GOMOD"]); err != nil {
		return err
	}
	for _, key := range []string{"GOENV", "GOWORK"} {
		if _, err := add(s.goenv[key]); err != nil {
			return err
		}
	}
	if work := s.goenv["GOWORK"]; work != "" && work != "off" {
		data, err := add(work)
		if err != nil {
			return err
		}
		if data == nil {
			return fmt.Errorf("assembly capture: selected workspace missing")
		}
		wf, err := modfile.ParseWork(work, data, nil)
		if err != nil {
			return err
		}
		for _, use := range wf.Use {
			if err = module(filepath.Join(absolute(filepath.Dir(work), use.Path), "go.mod")); err != nil {
				return err
			}
		}
		for _, r := range wf.Replace {
			if r.New.Version == "" {
				if err = module(filepath.Join(absolute(filepath.Dir(work), r.New.Path), "go.mod")); err != nil {
					return err
				}
			}
		}
		if _, err = add(work + ".sum"); err != nil {
			return err
		}
		if _, err = add(filepath.Join(filepath.Dir(work), "vendor", "modules.txt")); err != nil {
			return err
		}
	}
	for dir := s.request.Dir; ; dir = filepath.Dir(dir) {
		for _, name := range []string{"go.mod", "go.work"} {
			if _, err := add(filepath.Join(dir, name)); err != nil {
				return err
			}
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	flags, err := buildflags.Fields(s.goenv["GOFLAGS"])
	if err != nil {
		return err
	}
	flags = append(flags, s.request.Flags...)
	for i := 0; i < len(flags); i++ {
		key, value, eq := strings.Cut(strings.TrimLeft(flags[i], "-"), "=")
		if key != "pgo" && key != "modfile" {
			continue
		}
		if !eq {
			i++
			if i == len(flags) {
				return fmt.Errorf("assembly capture: missing flag value")
			}
			value = flags[i]
		}
		if value != "auto" && value != "off" {
			if key == "modfile" {
				if err = module(absolute(s.request.Dir, value)); err != nil {
					return err
				}
			} else if _, err = add(value); err != nil {
				return err
			}
		}
	}
	for _, path := range []string{filepath.Join(s.goenv["GOROOT"], "bin", "go"), filepath.Join(s.goenv["GOTOOLDIR"], "compile"), filepath.Join(s.goenv["GOTOOLDIR"], "asm"), filepath.Join(s.goenv["GOTOOLDIR"], "preprofile")} {
		if _, err := add(path); err != nil {
			return err
		}
	}
	launcher, err := exec.LookPath("go")
	if err != nil {
		return err
	}
	if _, err = add(launcher); err != nil {
		return err
	}
	return s.collectFlagInputs(add)
}

// Packages returns owned projections of the complete selection graph.
func (s *Selection) Packages() []Package {
	if s == nil {
		return nil
	}
	var out []Package
	for _, p := range s.packages {
		p.GoFiles = slices.Clone(p.GoFiles)
		p.Assembly = slices.Clone(p.Assembly)
		p.Opaque = slices.Clone(p.Opaque)
		p.EmbedFiles = slices.Clone(p.EmbedFiles)
		p.Imports = maps.Clone(p.Imports)
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b Package) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// Request returns an owned copy of the original root request.
func (s *Selection) Request() Request {
	r := s.request
	r.Env = slices.Clone(r.Env)
	r.Flags = slices.Clone(r.Flags)
	r.Roots = slices.Clone(r.Roots)
	return r
}

// LoadFlags preserves every source/compilation option while omitting only the
// original materialization destination, which go list does not accept. The
// request still owns that destination; Acquire overrides it with its own output.
func (s *Selection) LoadFlags() []string {
	var flags []string
	for i := 0; i < len(s.request.Flags); i++ {
		arg := s.request.Flags[i]
		if arg == "-o" || arg == "--o" {
			i++
			continue
		}
		if strings.HasPrefix(arg, "-o=") || strings.HasPrefix(arg, "--o=") {
			continue
		}
		flags = append(flags, arg)
	}
	return flags
}

// Flags returns GOFLAGS followed by the ordered explicit build flags. Parsing
// was checked at construction; later callers cannot mutate the selection.
func (s *Selection) Flags() []string {
	flags, _ := buildflags.Fields(s.goenv["GOFLAGS"])
	return append(flags, s.request.Flags...)
}

// PackageJSON projects the owned go-list data for consumers with an existing
// package-metadata representation. It creates no new observation.
func (s *Selection) PackageJSON(id string) []byte {
	for _, p := range s.listed {
		if p.ImportPath == id {
			b, _ := json.Marshal(p)
			return b
		}
	}
	return nil
}

// Seal closes the load-time agreement. parsed contains the exact bytes handed
// to the parser, not bytes read retrospectively from AST file names.
func (s *Selection) Seal(ctx context.Context, parsed map[string][]byte, rootIDs []string) error {
	if s == nil || s.sealed {
		return fmt.Errorf("assembly capture: selection absent or already sealed")
	}
	// Implicit build dependencies (notably runtime for a minimal main) need
	// not appear in go/packages' typed source graph. Their complete selected
	// input bytes remain owned above and are checked against compiler actions;
	// only actual parser inputs acquire typed-source authority here.
	for path, got := range parsed {
		want, ok := s.files[path]
		if !ok || want.absent || !bytes.Equal(want.data, got) {
			return fmt.Errorf("assembly capture: typed parser bytes disagree: %s", path)
		}
	}
	var wantRoots []string
	for _, p := range s.packages {
		if p.Root {
			wantRoots = append(wantRoots, p.ID)
		}
	}
	wantRoots = slices.Sorted(slices.Values(wantRoots))
	gotRoots := slices.Sorted(slices.Values(rootIDs))
	if !slices.Equal(wantRoots, gotRoots) {
		return fmt.Errorf("assembly capture: typed root instances disagree: %v != %v", gotRoots, wantRoots)
	}
	if err := s.Validate(ctx); err != nil {
		return err
	}
	s.parsed = copyFiles(parsed)
	s.rootIDs = slices.Clone(rootIDs)
	s.sealed = true
	return nil
}

// SourceFiles returns the parser-owned Go bytes of one exact package instance.
func (s *Selection) SourceFiles(id string) map[string][]byte {
	if s == nil || !s.sealed {
		return nil
	}
	out := map[string][]byte{}
	for _, path := range s.packages[id].GoFiles {
		out[path] = slices.Clone(s.parsed[path])
	}
	return out
}

// Validate repeats independent configuration, graph, membership and content
// observations. It grants no retrospective action evidence.
func (s *Selection) Validate(ctx context.Context) error {
	limits, _ := (Limits{}).normalized()
	return s.validate(ctx, &meter{ctx: ctx, limits: limits})
}

func (s *Selection) validate(ctx context.Context, m *meter) error {
	if err := s.validateMetadata(ctx); err != nil {
		return err
	}
	for path, want := range s.files {
		matches, err := matchesObservation(ctx, path, want, m)
		if err != nil {
			return err
		}
		if !matches {
			return fmt.Errorf("assembly capture: selected input changed: %s", path)
		}
	}
	return ctx.Err()
}

func (s *Selection) validateMetadata(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	snapshot, err := s.runner.TakeEnvSnapshot(ctx, s.request.Dir, s.request.Env)
	if err != nil {
		return err
	}
	if snapshot.Identity() != s.goIdentity {
		return fmt.Errorf("assembly capture: selected go environment changed")
	}
	listed, err := s.list(ctx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(listed, s.listed) {
		return fmt.Errorf("assembly capture: selected package membership or import bindings changed")
	}
	for dir, want := range s.directories {
		got, err := namesInDir(dir)
		if err != nil {
			return err
		}
		if !slices.Equal(want, got) {
			return fmt.Errorf("assembly capture: selected directory membership changed: %s", dir)
		}
	}
	return ctx.Err()
}
