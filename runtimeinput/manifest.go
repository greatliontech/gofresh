package runtimeinput

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/jsonrecord"
	"github.com/greatliontech/gofresh/internal/outcome"
)

// Version 4 separates demonstrated producing-span movement from inferred
// unverifiability. Earlier manifests cannot establish that distinction.
const manifestVersion = 4

const (
	pathRel = "rel"
	pathAbs = "abs"
)

type manifest struct {
	Version      int         `json:"v"`
	Outcome      string      `json:"outcome,omitempty"`
	Subjects     []string    `json:"subjects,omitempty"`
	Env          []envInput  `json:"env,omitempty"`
	Paths        []pathInput `json:"paths,omitempty"`
	BracketMoved bool        `json:"bracketMoved,omitempty"`
	Unverifiable []string    `json:"unverifiable,omitempty"`
}

// envInput is one observed environment identity with the digest of the value
// the producing run saw — names and digests only, values never in clear text.
type envInput struct {
	Name   string `json:"n"`
	Digest string `json:"d"`
}

type pathID struct {
	Kind string `json:"k"`
	Path string `json:"p"`
}

// displayPath is the identity's one spelling in a clause: a
// module-relative identity by its slash-relative path — a clause is
// then a function of the tree's content, the same from any checkout —
// and an absolute identity by its own clean spelling, which IS that
// object's identity (REQ-inputs-refusal-attribution's spelling rule).
func (id pathID) displayPath() string {
	if id.Kind == pathRel {
		return id.Path
	}
	return filepath.Clean(id.Path)
}

// pathInput is one observed path identity with the digest of the object state
// the producing run saw. The identity is the embedded pathID alone — the
// digest is evidence about it, never part of its key. Metadata marks a
// metadata-bound entry — one a recorded stat observed — whose digest binds
// the full object state, modification times included; an unmarked entry was
// only ever opened, so its digest binds exactly the surface an open can
// expose (content, mode, size — never mtime), and the persisted identity
// stays portable across checkouts whose file times differ
// (REQ-inputs-observation-class).
type pathInput struct {
	pathID
	Digest   string `json:"d"`
	Metadata bool   `json:"m,omitempty"`
}

// Current recomputes the runtime-input digest for an encoded manifest
// under moduleDir and env, with caller-owned cancellation.
func Current(ctx context.Context, encoded, moduleDir string, env []string) (State, error) {
	if ctx == nil {
		return State{OK: false}, errors.New("runtimeinputs: nil context")
	}
	if err := ctx.Err(); err != nil {
		return State{OK: false}, err
	}
	normalized, err := normalizeEnvironment(env)
	if err != nil {
		return State{OK: false}, err
	}
	return currentWithNormalizedEnvContext(ctx, encoded, moduleDir, normalized)
}

func normalizeEnvironment(env []string) ([]string, error) {
	normalized, err := gotool.NormalizeEnv(env)
	if err != nil {
		return nil, fmt.Errorf("runtimeinputs: %w", err)
	}
	return normalized, nil
}

func currentWithNormalizedEnvContext(ctx context.Context, encoded, moduleDir string, env []string) (State, error) {
	if err := ctx.Err(); err != nil {
		return State{OK: false}, err
	}
	m, err := decode(encoded)
	if err != nil {
		return State{OK: false}, err
	}
	return stateFromManifest(ctx, m, moduleDir, env)
}

// envEntryDigest digests one environment input: presence and value, names
// only ever disclosed.
func envEntryDigest(env []string, name string) string {
	value, ok := gotool.LookupEnv(env, name)
	valueHash := sha256.Sum256([]byte(value))
	sum := sha256.Sum256(fmt.Appendf(nil, "%t %x", ok, valueHash))
	return hex.EncodeToString(sum[:])[:32]
}

// pathEntryDigest digests one path input's observed object state through the
// same framed stream hashPath has always produced, into its own hasher.
func pathEntryDigest(ctx context.Context, id pathID, path, moduleDir string, metadata bool) (string, bool, string, error) {
	h := sha256.New()
	unverifiable, reason, err := hashPath(ctx, h, id, path, moduleDir, nil, nil, true, metadata, nil)
	if err != nil {
		return "", false, "", err
	}
	return hex.EncodeToString(h.Sum(nil))[:32], unverifiable, reason, nil
}

// populateManifestDigests computes every input's current digest in canonical
// order and writes it into m's entries. Separating digest computation from
// finalizeManifestState allows fromTestLog to update m.BracketMoved and
// m.Unverifiable after bracket revalidation without re-reading any input after
// the bracket closes (REQ-inputs-value-binding).
func populateManifestDigests(ctx context.Context, m *manifest, moduleDir string, env []string) (bool, string, error) {
	// The fold runs in canonical order regardless of the caller's collection
	// order — encode re-sorts anyway, and a fold that disagreed with the
	// encoded order would silently decouple digest from manifest.
	sortManifest(m)
	moduleDir, err := filepath.Abs(moduleDir)
	if err != nil {
		return false, "", err
	}
	for i, entry := range m.Env {
		if err := ctx.Err(); err != nil {
			return false, "", err
		}
		m.Env[i].Digest = envEntryDigest(env, entry.Name)
	}
	var unverifiable bool
	var reason string
	for i, entry := range m.Paths {
		if err := ctx.Err(); err != nil {
			return false, "", err
		}
		path, err := materializePath(moduleDir, entry.pathID)
		if err != nil {
			return false, "", err
		}
		// Manifest hashing never filters: exclusion is per identity, never per
		// content (REQ-inputs-exclusions), so a recorded directory identity
		// digests everything its hash walks.
		d, pathUnverifiable, pathReason, err := pathEntryDigest(ctx, entry.pathID, path, moduleDir, entry.Metadata)
		if err != nil {
			return false, "", err
		}
		m.Paths[i].Digest = d
		if pathUnverifiable {
			unverifiable = true
			if reason == "" {
				reason = pathReason
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return false, "", err
	}
	return unverifiable, reason, nil
}

// finalizeManifestState encodes m with its already-populated entry digests and
// computes the combined manifest digest in memory.
func finalizeManifestState(m manifest, pathUnverifiable bool, pathReason string) (State, error) {
	sortManifest(&m)
	unverifiable := len(m.Unverifiable) > 0 || pathUnverifiable
	reason := firstReason(m.Unverifiable)
	if reason == "" {
		reason = pathReason
	}
	encoded, err := encode(m)
	if err != nil {
		return State{}, err
	}
	return State{
		Manifest:     encoded,
		Digest:       manifestDigest(m),
		BracketMoved: m.BracketMoved,
		Unverifiable: unverifiable,
		Reason:       reason,
		OK:           true,
	}, nil
}

// stateFromManifest computes every input's current digest, writes it into the
// manifest's entries, folds the combined digest over identities and entry
// digests, and encodes — construction and check share it, so a recorded
// manifest whose inputs are unmoved re-encodes byte-identically
// (REQ-inputs-guard) and per-input attribution falls out of comparing a
// recorded entry's digest with the recomputed one.
func stateFromManifest(ctx context.Context, m manifest, moduleDir string, env []string) (State, error) {
	pathUnverifiable, pathReason, err := populateManifestDigests(ctx, &m, moduleDir, env)
	if err != nil {
		return State{OK: false}, err
	}
	return finalizeManifestState(m, pathUnverifiable, pathReason)
}

func manifestDigest(m manifest) string {
	h := sha256.New()
	fprintf(h, "version %d\n", m.Version)
	if m.Outcome != "" {
		fprintf(h, "outcome %s\n", m.Outcome)
		for _, subject := range m.Subjects {
			fprintf(h, "subject %s\n", subject)
		}
	}
	for _, entry := range m.Env {
		fprintf(h, "env %s %s\n", entry.Name, entry.Digest)
	}
	for _, entry := range m.Paths {
		fprintf(h, "path %s %s %s\n", entry.Kind, entry.Path, entry.Digest)
	}
	if m.BracketMoved {
		fprintf(h, "bracket-moved\n")
	}
	for _, reason := range m.Unverifiable {
		fprintf(h, "unverifiable %s\n", reason)
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
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
	sort.Strings(m.Subjects)
	m.Subjects = compact(m.Subjects)
	sort.Slice(m.Env, func(i, j int) bool { return m.Env[i].Name < m.Env[j].Name })
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

// Description is a validated manifest's observable identity set: what a run
// was recorded to observe, disclosed as identities only — environment values
// are never stored or reported in clear text (REQ-inputs-path-identities).
type Description struct {
	EnvNames     []string // observed environment-variable names, manifest order
	Paths        []string // materialized absolute path identities, manifest order
	Unverifiable []string // unverifiable observation dispositions, manifest order
}

// Describe decodes a canonical manifest into its identity set, materializing
// path identities under moduleDir exactly as Paths does. It names what a run
// was recorded to observe; MovedInputs names which of it moved.
func Describe(encoded, moduleDir string) (Description, error) {
	m, err := decode(encoded)
	if err != nil {
		return Description{}, err
	}
	paths, err := materializePaths(m.Paths, moduleDir)
	if err != nil {
		return Description{}, err
	}
	d := Description{
		Paths:        paths,
		Unverifiable: append([]string(nil), m.Unverifiable...),
	}
	for _, entry := range m.Env {
		d.EnvNames = append(d.EnvNames, entry.Name)
	}
	return d, nil
}

// MovedInputs names every input in a recorded manifest whose current digest
// differs from the recorded one — the attribution behind a runtime-input
// digest mismatch (REQ-inputs-guard): environment inputs as "env <name>"
// (values never disclosed), path inputs by their display identity. An empty
// result with a moved combined digest cannot occur: beyond the entries, the
// combined digest folds only recorded-verbatim data (the version and the
// unverifiable reasons), which cannot move at check time.
func MovedInputs(ctx context.Context, encoded, moduleDir string, env []string) ([]string, error) {
	if ctx == nil {
		return nil, errors.New("runtimeinputs: nil context")
	}
	m, err := decode(encoded)
	if err != nil {
		return nil, err
	}
	normalized, err := normalizeEnvironment(env)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(moduleDir)
	if err != nil {
		return nil, fmt.Errorf("runtimeinputs: module dir: %w", err)
	}
	var moved []string
	for _, entry := range m.Env {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if envEntryDigest(normalized, entry.Name) != entry.Digest {
			moved = append(moved, "env "+entry.Name)
		}
	}
	for _, entry := range m.Paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path, err := materializePath(abs, entry.pathID)
		if err != nil {
			return nil, err
		}
		d, _, _, err := pathEntryDigest(ctx, entry.pathID, path, abs, entry.Metadata)
		if err != nil {
			return nil, err
		}
		if d != entry.Digest {
			moved = append(moved, "path "+entry.displayPath())
		}
	}
	return moved, nil
}

// Paths returns every path identity in a canonical manifest as an absolute path,
// preserving manifest order. Module-relative identities are rooted at moduleDir;
// external identities remain absolute.
func Paths(encoded, moduleDir string) ([]string, error) {
	m, err := decode(encoded)
	if err != nil {
		return nil, err
	}
	return materializePaths(m.Paths, moduleDir)
}

func materializePaths(entries []pathInput, moduleDir string) ([]string, error) {
	abs, err := filepath.Abs(moduleDir)
	if err != nil {
		return nil, fmt.Errorf("runtimeinputs: module dir: %w", err)
	}
	if len(entries) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		path, err := materializePath(abs, entry.pathID)
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
	if err := jsonrecord.DecodeSingleValue("runtimeinputs: parse manifest", b, &m); err != nil {
		return manifest{}, err
	}
	if err := validateManifest(m); err != nil {
		return manifest{}, err
	}
	sortManifest(&m)
	canonical, err := json.Marshal(m)
	if err != nil {
		return manifest{}, err
	}
	if !jsonrecord.CanonicalEqual(canonical, b, false) {
		return manifest{}, fmt.Errorf("runtimeinputs: non-canonical manifest encoding")
	}
	return m, nil
}

// validEntryDigest is the per-input digest shape: 32 lowercase hex characters
// (a truncated SHA-256), exactly as the combined digest renders.
func validEntryDigest(d string) bool {
	if len(d) != 32 {
		return false
	}
	for _, r := range d {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func validateManifest(m manifest) error {
	if m.Version != manifestVersion {
		return fmt.Errorf("runtimeinputs: unsupported manifest version %d", m.Version)
	}
	if (m.Outcome == "") != (len(m.Subjects) == 0) || m.Outcome != "" && m.Outcome != outcome.Method {
		return errors.New("runtimeinputs: unsupported or incomplete outcome evidence")
	}
	if m.Outcome == outcome.Method && len(m.Paths) != 0 {
		return errors.New("runtimeinputs: immutable-environment support carries path inputs")
	}
	for _, subject := range m.Subjects {
		if len(subject) != 64 || !validEntryDigest(subject[:32]) || !validEntryDigest(subject[32:]) {
			return errors.New("runtimeinputs: invalid outcome subject identity")
		}
	}
	for i, entry := range m.Env {
		name := entry.Name
		if name == "" || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\r\n") {
			return fmt.Errorf("runtimeinputs: invalid env name %q", name)
		}
		if !validEntryDigest(entry.Digest) {
			return fmt.Errorf("runtimeinputs: invalid env input digest for %q", name)
		}
		// Each array is a set once per IDENTITY: entries compact only when
		// byte-identical, so a duplicate identity with a differing digest
		// would otherwise survive into an accepted manifest.
		if i > 0 && m.Env[i-1].Name == name {
			return fmt.Errorf("runtimeinputs: duplicate env identity %q", name)
		}
	}
	for i, entry := range m.Paths {
		if !validEntryDigest(entry.Digest) {
			return fmt.Errorf("runtimeinputs: invalid path input digest for %q", entry.Path)
		}
		if i > 0 && m.Paths[i-1].pathID == entry.pathID {
			return fmt.Errorf("runtimeinputs: duplicate path identity %q", entry.Path)
		}
	}
	for _, entry := range m.Paths {
		if err := validatePathID(entry.pathID); err != nil {
			return err
		}
	}
	for _, reason := range m.Unverifiable {
		if reason == "" || !utf8.ValidString(reason) || strings.ContainsAny(reason, "\x00\r\n") {
			return fmt.Errorf("runtimeinputs: invalid unverifiable reason %q", reason)
		}
	}
	return nil
}

// validatePathID is the canonical manifest path grammar, independent of any
// module location or filesystem state.
func validatePathID(id pathID) error {
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
	return nil
}

func fprintf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}
