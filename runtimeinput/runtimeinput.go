// Package runtimeinputs records and re-hashes non-source inputs observed by a
// measured process through Go's testlog channel (spec REQ-inputs-guard).
package runtimeinput

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const manifestVersion = 1

const (
	pathRel = "rel"
	pathAbs = "abs"
)

// State is the current digest of a recorded runtime-input manifest.
type State struct {
	Manifest     string
	Digest       string
	Unverifiable bool
	Reason       string
	OK           bool
}

type manifest struct {
	Version      int      `json:"v"`
	Env          []string `json:"env,omitempty"`
	Paths        []pathID `json:"paths,omitempty"`
	Unverifiable []string `json:"unverifiable,omitempty"`
}

type pathID struct {
	Kind string `json:"k"`
	Path string `json:"p"`
}

// Incomplete constructs canonical evidence for a process whose runtime-input
// observation did not complete. It is mergeable but remains unverifiable.
func Incomplete(moduleDir, reason string) (State, error) {
	if strings.TrimSpace(reason) == "" {
		return State{}, fmt.Errorf("runtimeinputs: incomplete observation needs a reason")
	}
	encoded, err := encode(manifest{Version: manifestVersion, Unverifiable: []string{reason}})
	if err != nil {
		return State{}, err
	}
	return Current(encoded, moduleDir)
}

// Absolute revalidates state under moduleDir and returns equivalent evidence
// whose path identities are all absolute. This permits sound cross-module merge.
func Absolute(state State, moduleDir string) (State, error) {
	if !state.OK || state.Manifest == "" || state.Digest == "" {
		return State{}, fmt.Errorf("runtimeinputs: incomplete state for absolute identities")
	}
	current, err := Current(state.Manifest, moduleDir)
	if err != nil {
		return State{}, err
	}
	if current != state {
		return State{}, fmt.Errorf("runtimeinputs: state moved before absolute identity conversion")
	}
	m, err := decode(state.Manifest)
	if err != nil {
		return State{}, err
	}
	if current.Unverifiable && current.Reason != "" {
		seen := make(map[string]bool, len(m.Unverifiable)+1)
		for _, reason := range m.Unverifiable {
			seen[reason] = true
		}
		addUnverifiable(&m, seen, current.Reason)
	}
	moduleDir, err = filepath.Abs(moduleDir)
	if err != nil {
		return State{}, fmt.Errorf("runtimeinputs: module dir: %w", err)
	}
	for i, id := range m.Paths {
		path, err := materializePath(moduleDir, id)
		if err != nil {
			return State{}, err
		}
		m.Paths[i] = pathID{Kind: pathAbs, Path: path}
	}
	encoded, err := encode(m)
	if err != nil {
		return State{}, err
	}
	return Current(encoded, moduleDir)
}

// FromTestLog builds a runtime-input manifest from a Go testlog stream and
// computes its digest against the current filesystem and environment.
func FromTestLog(log []byte, moduleDir, packageDir string) (State, error) {
	moduleDir, err := filepath.Abs(moduleDir)
	if err != nil {
		return State{}, err
	}
	packageDir, err = filepath.Abs(packageDir)
	if err != nil {
		return State{}, err
	}

	m := manifest{Version: manifestVersion}
	envSeen := map[string]bool{}
	pathSeen := map[pathID]bool{}
	unverifiableSeen := map[string]bool{}
	cwd := packageDir

	s := bufio.NewScanner(strings.NewReader(string(log)))
	for s.Scan() {
		line := strings.TrimRight(s.Text(), "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		op, name, ok := strings.Cut(line, " ")
		if !ok || name == "" {
			addUnverifiable(&m, unverifiableSeen, "malformed testlog line")
			continue
		}
		switch op {
		case "getenv":
			if !utf8.ValidString(name) {
				addUnverifiable(&m, unverifiableSeen, "non-UTF-8 environment name")
				continue
			}
			if !envSeen[name] {
				envSeen[name] = true
				m.Env = append(m.Env, name)
			}
		case "open":
			p := resolvePath(cwd, name)
			id, reason := classifyPath(moduleDir, p)
			if reason != "" {
				addUnverifiable(&m, unverifiableSeen, reason)
				continue
			}
			if !pathSeen[id] {
				pathSeen[id] = true
				m.Paths = append(m.Paths, id)
			}
		case "stat":
			p := resolvePath(cwd, name)
			id, reason := classifyPath(moduleDir, p)
			if reason != "" {
				addUnverifiable(&m, unverifiableSeen, reason)
				continue
			}
			if !pathSeen[id] {
				pathSeen[id] = true
				m.Paths = append(m.Paths, id)
			}
			addUnverifiable(&m, unverifiableSeen, "stat metadata input: "+id.displayPath())
		case "chdir":
			p := resolvePath(cwd, name)
			id, reason := classifyPath(moduleDir, p)
			if reason != "" {
				addUnverifiable(&m, unverifiableSeen, reason)
			} else if !pathSeen[id] {
				pathSeen[id] = true
				m.Paths = append(m.Paths, id)
			}
			cwd = p
		default:
			addUnverifiable(&m, unverifiableSeen, "unrecognized testlog op: "+op)
		}
	}
	if err := s.Err(); err != nil {
		return State{}, err
	}
	sortManifest(&m)
	encoded, err := encode(m)
	if err != nil {
		return State{}, err
	}
	st, err := Current(encoded, moduleDir)
	if err != nil {
		return State{}, err
	}
	return st, nil
}

// Merge revalidates independently completed runtime-input states against one current
// module view, then returns their deterministic manifest union. Passing no states
// deliberately produces the encoded observation-free manifest; structurally
// unfinished, moved, or malformed states are rejected. A finalized state from
// Incomplete is accepted as explicit unverifiable evidence.
func Merge(moduleDir string, states ...State) (State, error) {
	merged := manifest{Version: manifestVersion}
	envSeen := map[string]bool{}
	pathSeen := map[pathID]bool{}
	unverifiableSeen := map[string]bool{}
	for i, input := range states {
		if !input.OK || input.Manifest == "" || input.Digest == "" {
			return State{}, fmt.Errorf("runtimeinputs: merge input %d is incomplete", i)
		}
		current, err := Current(input.Manifest, moduleDir)
		if err != nil {
			return State{}, fmt.Errorf("runtimeinputs: merge input %d: %w", i, err)
		}
		if current != input {
			return State{}, fmt.Errorf("runtimeinputs: merge input %d moved", i)
		}
		m, err := decode(input.Manifest)
		if err != nil {
			return State{}, fmt.Errorf("runtimeinputs: merge input %d: %w", i, err)
		}
		for _, name := range m.Env {
			if !envSeen[name] {
				envSeen[name] = true
				merged.Env = append(merged.Env, name)
			}
		}
		for _, id := range m.Paths {
			if !pathSeen[id] {
				pathSeen[id] = true
				merged.Paths = append(merged.Paths, id)
			}
		}
		for _, reason := range m.Unverifiable {
			addUnverifiable(&merged, unverifiableSeen, reason)
		}
	}
	result, err := encode(merged)
	if err != nil {
		return State{}, err
	}
	return Current(result, moduleDir)
}

// Current recomputes the runtime-input digest for an encoded manifest.
func Current(encoded, moduleDir string) (State, error) {
	m, err := decode(encoded)
	if err != nil {
		return State{OK: false}, err
	}
	moduleDir, err = filepath.Abs(moduleDir)
	if err != nil {
		return State{}, err
	}

	h := sha256.New()
	fprintf(h, "version %d\n", m.Version)
	for _, name := range m.Env {
		value, ok := os.LookupEnv(name)
		valueHash := sha256.Sum256([]byte(value))
		fprintf(h, "env %s %t %x\n", name, ok, valueHash)
	}
	unverifiable := len(m.Unverifiable) > 0
	reason := firstReason(m.Unverifiable)
	for _, id := range m.Paths {
		path, err := materializePath(moduleDir, id)
		if err != nil {
			return State{}, err
		}
		pathUnverifiable, pathReason, err := hashPath(h, id, path, moduleDir)
		if err != nil {
			return State{}, err
		}
		if pathUnverifiable {
			unverifiable = true
			if reason == "" {
				reason = pathReason
			}
		}
	}
	for _, reason := range m.Unverifiable {
		fprintf(h, "unverifiable %s\n", reason)
	}
	sum := h.Sum(nil)
	return State{
		Manifest:     encoded,
		Digest:       hex.EncodeToString(sum)[:32],
		Unverifiable: unverifiable,
		Reason:       reason,
		OK:           true,
	}, nil
}

func resolvePath(cwd, name string) string {
	if filepath.IsAbs(name) {
		return filepath.Clean(name)
	}
	return filepath.Clean(filepath.Join(cwd, name))
}

func classifyPath(moduleDir, p string) (pathID, string) {
	if !utf8.ValidString(p) {
		return pathID{}, "non-UTF-8 runtime input path"
	}
	if rel, ok := relUnder(moduleDir, p); ok {
		return pathID{Kind: pathRel, Path: filepath.ToSlash(rel)}, ""
	}
	info, err := os.Stat(p)
	if err == nil && info.IsDir() {
		return pathID{}, "external directory input: " + p
	}
	if err != nil && !os.IsNotExist(err) {
		return pathID{}, "unhashable runtime input: " + p
	}
	return pathID{Kind: pathAbs, Path: filepath.Clean(p)}, ""
}

func relUnder(root, p string) (string, bool) {
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return rel, true
}

func materializePath(moduleDir string, id pathID) (string, error) {
	switch id.Kind {
	case pathRel:
		path := filepath.Clean(filepath.Join(moduleDir, filepath.FromSlash(id.Path)))
		if _, ok := relUnder(moduleDir, path); !ok {
			return "", fmt.Errorf("runtimeinputs: relative path escapes module: %q", id.Path)
		}
		return path, nil
	case pathAbs:
		if !filepath.IsAbs(id.Path) {
			return "", fmt.Errorf("runtimeinputs: absolute path input is relative: %q", id.Path)
		}
		return filepath.Clean(id.Path), nil
	default:
		return "", fmt.Errorf("runtimeinputs: unknown path kind %q", id.Kind)
	}
}

func hashPath(h hash.Hash, id pathID, p, moduleDir string) (bool, string, error) {
	info, err := os.Stat(p)
	if os.IsNotExist(err) {
		fprintf(h, "path %s %s missing\n", id.Kind, id.Path)
		return false, "", nil
	}
	if err != nil {
		fprintf(h, "path %s %s unhashable\n", id.Kind, id.Path)
		return true, "unhashable runtime input: " + p, nil
	}
	target := p
	if id.Kind == pathRel {
		var external bool
		target, external, err = resolvedTarget(p, moduleDir)
		if err != nil {
			fprintf(h, "path %s %s unhashable-target\n", id.Kind, id.Path)
			return true, "unhashable runtime input: " + p, nil
		}
		if external {
			if info.IsDir() {
				fprintf(h, "path %s %s external-dir\n", id.Kind, id.Path)
				return true, "external directory input: " + p, nil
			}
			fprintf(h, "path %s %s external-target\n", id.Kind, id.Path)
			return true, "external runtime input target: " + p, nil
		}
	}
	mode := info.Mode()
	switch {
	case mode.IsRegular():
		writeStat(h, info)
		sum, err := fileHash(target)
		if err != nil {
			fprintf(h, "path %s %s unhashable\n", id.Kind, id.Path)
			return true, "unhashable runtime input: " + p, nil
		}
		fprintf(h, "path %s %s file %x\n", id.Kind, id.Path, sum)
		return false, "", nil
	case info.IsDir() && id.Kind == pathRel:
		sum, unv, reason, err := dirHash(target)
		if err != nil {
			return false, "", err
		}
		fprintf(h, "path %s %s dir %x\n", id.Kind, id.Path, sum)
		return unv, reason, nil
	case info.IsDir():
		fprintf(h, "path %s %s external-dir\n", id.Kind, id.Path)
		return true, "external directory input: " + p, nil
	default:
		fprintf(h, "path %s %s unhashable-mode %s\n", id.Kind, id.Path, mode.String())
		return true, "unhashable runtime input: " + p, nil
	}
}

func (id pathID) displayPath() string {
	if id.Kind == pathRel {
		return id.Path
	}
	return filepath.Clean(id.Path)
}

func resolvedTarget(path, moduleDir string) (string, bool, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false, err
	}
	moduleRoot, err := filepath.EvalSymlinks(moduleDir)
	if err != nil {
		moduleRoot = moduleDir
	}
	if _, ok := relUnder(moduleRoot, resolved); !ok {
		return resolved, true, nil
	}
	return resolved, false, nil
}

func writeStat(h hash.Hash, info os.FileInfo) {
	fprintf(h, "stat %d %x %d %t\n", info.Size(), uint64(info.Mode()), info.ModTime().UnixNano(), info.IsDir())
}

func fileHash(path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, err
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

func dirHash(root string) ([32]byte, bool, string, error) {
	h := sha256.New()
	unverifiable := false
	reason := ""
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			unverifiable = true
			if reason == "" {
				reason = "unhashable runtime directory: " + path
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		info, err := d.Info()
		if err != nil {
			unverifiable = true
			if reason == "" {
				reason = "unhashable runtime directory: " + path
			}
			return nil
		}
		switch {
		case d.IsDir():
			fprintf(h, "dir %s/ ", rel)
			writeStat(h, info)
		case info.Mode().IsRegular():
			writeStat(h, info)
			sum, err := fileHash(path)
			if err != nil {
				unverifiable = true
				if reason == "" {
					reason = "unhashable runtime directory file: " + path
				}
				return nil
			}
			fprintf(h, "file %s %x\n", rel, sum)
		case info.Mode()&os.ModeSymlink != 0:
			writeStat(h, info)
			target, err := os.Readlink(path)
			if err != nil {
				unverifiable = true
				if reason == "" {
					reason = "unhashable runtime directory symlink: " + path
				}
				return nil
			}
			fprintf(h, "symlink %s %s\n", rel, target)
		default:
			unverifiable = true
			if reason == "" {
				reason = "unhashable runtime directory entry: " + path
			}
			fprintf(h, "unhashable %s %s\n", rel, info.Mode().String())
		}
		return nil
	})
	if err != nil {
		return [32]byte{}, false, "", err
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, unverifiable, reason, nil
}

func addUnverifiable(m *manifest, seen map[string]bool, reason string) {
	if !seen[reason] {
		seen[reason] = true
		m.Unverifiable = append(m.Unverifiable, reason)
	}
}

func firstReason(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	return reasons[0]
}

func sortManifest(m *manifest) {
	sort.Strings(m.Env)
	m.Env = compact(m.Env)
	sort.Slice(m.Paths, func(i, j int) bool {
		if m.Paths[i].Kind != m.Paths[j].Kind {
			return m.Paths[i].Kind < m.Paths[j].Kind
		}
		return m.Paths[i].Path < m.Paths[j].Path
	})
	m.Paths = compact(m.Paths)
	sort.Strings(m.Unverifiable)
	m.Unverifiable = compact(m.Unverifiable)
}

func compact[T comparable](values []T) []T {
	if len(values) == 0 {
		return nil
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func encode(m manifest) (string, error) {
	sortManifest(&m)
	if err := validateManifest(m); err != nil {
		return "", err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ModuleRelPaths decodes an encoded manifest and returns the module-relative
// (slash-form) paths of its module-local file/directory inputs. These are the
// observed inputs whose Git-representable state at the recording's commit determines
// whether the recording is faithful to it (REQ-fresh-fingerprint-data,
// REQ-inputs-guard); external (absolute) inputs and environment
// variables are excluded (an external input is out of the module's git scope).
func ModuleRelPaths(encoded string) ([]string, error) {
	m, err := decode(encoded)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range m.Paths {
		if p.Kind == pathRel {
			out = append(out, p.Path)
		}
	}
	return out, nil
}

// Paths returns every path identity in a canonical manifest as an absolute path,
// preserving manifest order. Module-relative identities are rooted at moduleDir;
// external identities remain absolute.
func Paths(encoded, moduleDir string) ([]string, error) {
	m, err := decode(encoded)
	if err != nil {
		return nil, err
	}
	moduleDir, err = filepath.Abs(moduleDir)
	if err != nil {
		return nil, fmt.Errorf("runtimeinputs: module dir: %w", err)
	}
	out := make([]string, 0, len(m.Paths))
	for _, id := range m.Paths {
		path, err := materializePath(moduleDir, id)
		if err != nil {
			return nil, err
		}
		out = append(out, path)
	}
	return out, nil
}

func decode(s string) (manifest, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return manifest{}, fmt.Errorf("runtimeinputs: decode manifest: %w", err)
	}
	if base64.RawURLEncoding.EncodeToString(b) != s {
		return manifest{}, fmt.Errorf("runtimeinputs: non-canonical base64url manifest")
	}
	if !utf8.Valid(b) {
		return manifest{}, fmt.Errorf("runtimeinputs: manifest is not valid UTF-8")
	}
	var m manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return manifest{}, fmt.Errorf("runtimeinputs: parse manifest: %w", err)
	}
	if err := requireJSONEnd(dec); err != nil {
		return manifest{}, err
	}
	if m.Version != manifestVersion {
		return manifest{}, fmt.Errorf("runtimeinputs: unsupported manifest version %d", m.Version)
	}
	if err := validateManifest(m); err != nil {
		return manifest{}, err
	}
	sortManifest(&m)
	canonical, err := json.Marshal(m)
	if err != nil {
		return manifest{}, err
	}
	if !bytes.Equal(canonical, b) {
		return manifest{}, fmt.Errorf("runtimeinputs: non-canonical manifest encoding")
	}
	return m, nil
}

func validateManifest(m manifest) error {
	for _, name := range m.Env {
		if name == "" || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\r\n") {
			return fmt.Errorf("runtimeinputs: invalid env name %q", name)
		}
	}
	for _, id := range m.Paths {
		if id.Path == "" || !utf8.ValidString(id.Path) || strings.ContainsAny(id.Path, "\x00\r\n") {
			return fmt.Errorf("runtimeinputs: invalid path %q", id.Path)
		}
		switch id.Kind {
		case pathRel:
			if filepath.IsAbs(id.Path) {
				return fmt.Errorf("runtimeinputs: relative path input is absolute: %q", id.Path)
			}
			clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(id.Path)))
			if clean == ".." || strings.HasPrefix(clean, "../") {
				return fmt.Errorf("runtimeinputs: relative path escapes module: %q", id.Path)
			}
			if clean != id.Path {
				return fmt.Errorf("runtimeinputs: relative path input is not canonical: %q", id.Path)
			}
		case pathAbs:
			if !filepath.IsAbs(id.Path) {
				return fmt.Errorf("runtimeinputs: absolute path input is relative: %q", id.Path)
			}
			if filepath.Clean(id.Path) != id.Path {
				return fmt.Errorf("runtimeinputs: absolute path input is not canonical: %q", id.Path)
			}
		default:
			return fmt.Errorf("runtimeinputs: unknown path kind %q", id.Kind)
		}
	}
	for _, reason := range m.Unverifiable {
		if reason == "" || !utf8.ValidString(reason) || strings.ContainsAny(reason, "\x00\r\n") {
			return fmt.Errorf("runtimeinputs: invalid unverifiable reason %q", reason)
		}
	}
	return nil
}

func requireJSONEnd(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("runtimeinputs: parse manifest: trailing JSON value")
		}
		return fmt.Errorf("runtimeinputs: parse manifest: %w", err)
	}
	return nil
}

func fprintf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}
