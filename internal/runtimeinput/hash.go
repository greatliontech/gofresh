package runtimeinput

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/greatliontech/gofresh/internal/guard"
)

// machineFactIdentities are the allowlisted stable-machine-fact files:
// their raw bytes and stat metadata are volatile on every read (cpu MHz
// lines, available-memory counters, proc mtimes stamped at stat time),
// while everything a subject could branch on is the stable projection
// REQ-guard-machine defines — so they digest as that projection's
// fingerprint, never as content, and revalidation recomputes the same
// projection: equal on the same machine, moved exactly when the
// hardware or kernel actually changed (REQ-inputs-machine-identity).
// The allowlist derives from the guard's own source list, so a fact
// source added to the gatherer is allowlisted by construction — the two
// sets cannot diverge.
var machineFactIdentities = func() map[string]bool {
	m := make(map[string]bool, len(guard.MachineFactSources))
	for _, p := range guard.MachineFactSources {
		m[p] = true
	}
	return m
}()

// machineProjected is the value-kind decision shared by eligibility, bracket
// admission and hashing; the projection's source census stays with its owner.
func machineProjected(id pathID) bool { return id.Kind == pathAbs && machineFactIdentities[id.Path] }

type runtimeTestHookSet struct {
	machineFacts   func() (guard.MachineFacts, error)
	statPath       func(string) (os.FileInfo, error)
	lstatPath      func(string) (os.FileInfo, error)
	walkDirectory  func(string, fs.WalkDirFunc) error
	beforeRoots    func()
	congruenceStat func(string) (os.FileInfo, error)
	classifyStat   func(string) (os.FileInfo, error)
}

var (
	runtimeTestHooksMu sync.Mutex
	runtimeTestHooks   atomic.Pointer[runtimeTestHookSet]
)

// currentMachineFacts is the projection source, consulting runtimeTestHooks so
// the ungatherable arm is testable while production calls the guard directly.
func currentMachineFacts() (guard.MachineFacts, error) {
	if h := runtimeTestHooks.Load(); h != nil && h.machineFacts != nil {
		return h.machineFacts()
	}
	return guard.CurrentMachineFacts()
}

// statRuntimePath and lstatRuntimePath let tests vary lookup availability
// independently of directory-entry observations without changing metadata.
func statRuntimePath(p string) (os.FileInfo, error) {
	if h := runtimeTestHooks.Load(); h != nil && h.statPath != nil {
		return h.statPath(p)
	}
	return os.Stat(p)
}

func lstatRuntimePath(p string) (os.FileInfo, error) {
	if h := runtimeTestHooks.Load(); h != nil && h.lstatPath != nil {
		return h.lstatPath(p)
	}
	return os.Lstat(p)
}

// walkRuntimeDirectory uses the standard filesystem walk unless a test hook
// isolates a listing failure without changing observed object metadata.
func walkRuntimeDirectory(root string, visit fs.WalkDirFunc) error {
	if h := runtimeTestHooks.Load(); h != nil && h.walkDirectory != nil {
		return h.walkDirectory(root, visit)
	}
	return filepath.WalkDir(root, visit)
}

// fireProducerBeforeRoots lets tests land a cancellation between the facade's
// entry check and classification-root resolution.
func fireProducerBeforeRoots() {
	if h := runtimeTestHooks.Load(); h != nil && h.beforeRoots != nil {
		h.beforeRoots()
	}
}

// congruenceProbe is the traversal verifier's filesystem probe, a seam so
// tests can assert which paths it touches; production uses Lstat — the
// final component must be judged as itself, never through a link.
func congruenceProbe(p string) (os.FileInfo, error) {
	if h := runtimeTestHooks.Load(); h != nil && h.congruenceStat != nil {
		return h.congruenceStat(p)
	}
	return os.Lstat(p)
}

// classifyProbe is the classification-time filesystem probe, a seam so
// tests can assert the no-probe property of volatile-OS paths
// (REQ-inputs-volatile-os-roots): production code calls os.Stat.
func classifyProbe(p string) (os.FileInfo, error) {
	if h := runtimeTestHooks.Load(); h != nil && h.classifyStat != nil {
		return h.classifyStat(p)
	}
	return os.Stat(p)
}

// hashPath writes the digest stream for one path identity. A non-nil skip
// filters directory-walk entries by their slash-form path relative to the walk
// root; identity-level hashing is unaffected by it.
// existenceBindsExternalDirs distinguishes the two hashing consumers:
// manifest entries bind an external directory's existence
// (REQ-inputs-external-dir-existence), while a value-binding bracket
// root must fingerprint content — an existence-bound root would hold
// still while everything beneath it churns — so a bracket's absolute
// directory root walks its tree exactly as a module-relative one does
// (REQ-inputs-bracket-coverage): declaring it is the caller's
// mutation-free assertion over the whole tree, an external replace
// module as one surface.
func hashPath(ctx context.Context, h hash.Hash, id pathID, p, moduleRoot string, skip func(rel string) bool, visit func(rel string), existenceBindsExternalDirs, metadata bool, observed *pathFacts) (bool, string, error) {
	if err := ctx.Err(); err != nil {
		return false, "", err
	}
	if machineProjected(id) {
		facts, err := currentMachineFacts()
		if err != nil {
			fprintf(h, "path %s %s machine-unhashable\n", id.Kind, id.Path)
			return true, "unhashable runtime input: " + id.displayPath(), nil
		}
		fprintf(h, "path %s %s machine %s\n", id.Kind, id.Path, facts.Fingerprint())
		// Every allowlisted source gathers the same complete projection. Its
		// bracket comparison key is source-independent; its root retains source
		// attribution and exclusions. Manifest framing above stays path-specific.
		observed.put("", machineFact, facts.Fingerprint())
		return false, "", nil
	}
	var preResolved string
	if observed != nil {
		if r, _, ok, complete := chainResolveObservedComplete(ctx, p, observed); ok && complete {
			preResolved = r
		}
		if err := ctx.Err(); err != nil {
			return false, "", err
		}
	}
	info, err := statRuntimePath(p)
	if os.IsNotExist(err) {
		observed.put(p, followedStatFact, "missing")
		fprintf(h, "path %s %s missing\n", id.Kind, id.Path)
		return false, "", nil
	}
	if err != nil {
		fprintf(h, "path %s %s unhashable\n", id.Kind, id.Path)
		return true, "unhashable runtime input: " + id.displayPath(), nil
	}
	observed.stat(p, followedStatFact, info, metadata)
	target := p
	if id.Kind == pathRel {
		var external bool
		target, external, err = resolvedTarget(p, moduleRoot, preResolved)
		if err != nil {
			fprintf(h, "path %s %s unhashable-target\n", id.Kind, id.Path)
			return true, "unhashable runtime input: " + id.displayPath(), nil
		}
		if external {
			if info.IsDir() {
				fprintf(h, "path %s %s external-dir\n", id.Kind, id.Path)
				return true, "external directory input: " + id.displayPath() + attributionSeparator + resolvedTargetAttribution(id.Path, target), nil
			}
			fprintf(h, "path %s %s external-target\n", id.Kind, id.Path)
			return true, "external runtime input target: " + id.displayPath() + attributionSeparator + resolvedTargetAttribution(id.Path, target), nil
		}
	} else if info.IsDir() && !existenceBindsExternalDirs {
		// An absolute directory bracket root walks its resolved
		// position: the walk lstats its root, so an unresolved link
		// would hash the link itself while coverage reads the tree
		// beneath its target (REQ-inputs-value-binding's full-chain
		// rule for absolute roots). The volatile-OS refusal the
		// declaration passed lexically is re-judged over the target — a
		// link into a volatile tree walks nothing.
		if preResolved != "" {
			target = preResolved
		} else if target, err = filepath.EvalSymlinks(p); err != nil {
			fprintf(h, "path %s %s unhashable-target\n", id.Kind, id.Path)
			return true, "unhashable runtime input: " + id.displayPath(), nil
		}
		if volatileOSPath(target) {
			fprintf(h, "path %s %s volatile-target\n", id.Kind, id.Path)
			return true, "bracket root resolves into a volatile OS root: " + p, nil
		}
		if reason := containsVolatileOSRoot(target); reason != "" {
			fprintf(h, "path %s %s volatile-target\n", id.Kind, id.Path)
			return true, "bracket root resolves to a tree that " + reason + ": " + p, nil
		}
	}
	mode := info.Mode()
	switch {
	case mode.IsRegular():
		writeStat(h, info, metadata)
		sum, err := fileHash(ctx, target)
		if err != nil {
			fprintf(h, "path %s %s unhashable\n", id.Kind, id.Path)
			return true, "unhashable runtime input: " + id.displayPath(), nil
		}
		fprintf(h, "path %s %s file %x\n", id.Kind, id.Path, sum)
		observed.put(p, contentFact, hex.EncodeToString(sum[:]))
		return false, "", nil
	case info.IsDir() && (id.Kind == pathRel || !existenceBindsExternalDirs):
		sum, unv, reason, err := dirHashFiltered(ctx, target, id.displayPath(), skip, visit, metadata, observed)
		if err != nil {
			return false, "", err
		}
		fprintf(h, "path %s %s dir %x\n", id.Kind, id.Path, sum)
		return unv, reason, nil
	case info.IsDir():
		// An absolute external directory binds existence alone as a
		// manifest entry: ancestor stats from path-creation machinery
		// consume only "exists as a directory"; listing and metadata
		// dependence beyond that are outside the admitted observation
		// set. Existing external dirs never mint identities —
		// classifyPath refuses them at parse time — so entries reaching
		// this arm are stat-admitted or since-materialized within the
		// ingest's own classify-to-digest window, the clause's accepted
		// residual (REQ-inputs-external-dir-existence). A bracket root
		// took the walk above.
		fprintf(h, "path %s %s direxists\n", id.Kind, id.Path)
		return false, "", nil
	default:
		fprintf(h, "path %s %s unhashable-mode %s\n", id.Kind, id.Path, mode.String())
		return true, "unhashable runtime input: " + id.displayPath(), nil
	}
}

func resolveModuleRoot(moduleDir string) string {
	if resolved, err := filepath.EvalSymlinks(moduleDir); err == nil {
		return resolved
	}
	return moduleDir
}

func resolvedTarget(path, moduleRoot, preResolved string) (string, bool, error) {
	resolved := preResolved
	if resolved == "" {
		var err error
		resolved, err = filepath.EvalSymlinks(path)
		if err != nil {
			return "", false, err
		}
	}
	if _, ok := relUnder(moduleRoot, resolved); !ok {
		return resolved, true, nil
	}
	return resolved, false, nil
}

func writeStat(h hash.Hash, info os.FileInfo, metadata bool) {
	if metadata {
		fprintf(h, "stat %d %x %d %t\n", info.Size(), uint64(info.Mode()), info.ModTime().UnixNano(), info.IsDir())
		return
	}
	// A subject that only ever opened this object cannot observe its
	// modification time; binding it would pin the record to the checkout
	// that measured it (the dropped field guards nothing a subject could
	// observe — the same rationale the directory walk states for a
	// directory object's own size and mtime).
	fprintf(h, "stat %d %x %t\n", info.Size(), uint64(info.Mode()), info.IsDir())
}

func fileHash(ctx context.Context, path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()
	h := sha256.New()
	buffer := make([]byte, 32*1024)
	for {
		if err := ctx.Err(); err != nil {
			return [32]byte{}, err
		}
		n, readErr := f.Read(buffer)
		if n != 0 {
			_, _ = h.Write(buffer[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return [32]byte{}, readErr
		}
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// dirHashFiltered digests a directory tree under a skip predicate over
// the slash-form path of each entry relative to root; a skipped
// directory's subtree contributes nothing to the digest. A nil skip
// digests the complete tree. A non-nil
// visit receives each digested entry's slash-form rel (the root's own "."
// included), letting a bracket capture retain the walked membership without
// a second walk that could diverge from the hashing semantics.
// dirHashFiltered walks the directory at root — the resolved position
// of the identity whose clause spelling is display — hashing its
// membership and content; a member it cannot hash is named in the
// refusal under the identity's spelling (display, then the member's
// walk-relative path), never under the walked absolute position, so
// the clause is the same from any checkout
// (REQ-inputs-refusal-attribution's spelling rule).
func dirHashFiltered(ctx context.Context, root, display string, skip func(rel string) bool, visit func(rel string), metadata bool, observed *pathFacts) ([32]byte, bool, string, error) {
	h := sha256.New()
	// A failed listing withholds completeness, not the names it did expose.
	var listings map[string][]string
	var failedListings map[string]bool
	if observed != nil {
		listings = map[string][]string{}
		failedListings = map[string]bool{}
	}
	unverifiable := false
	reason := ""
	member := func(path string) string {
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." {
			return display
		}
		if display == "." {
			return filepath.ToSlash(rel)
		}
		return display + "/" + filepath.ToSlash(rel)
	}
	err := walkRuntimeDirectory(root, func(path string, d fs.DirEntry, err error) error {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		if skip != nil {
			if rel, relErr := filepath.Rel(root, path); relErr == nil {
				if s := filepath.ToSlash(rel); s != "." && skip(s) {
					if err == nil && d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
			}
		}
		if err != nil {
			if observed != nil {
				failedListings[path] = true
			}
			unverifiable = true
			if reason == "" {
				reason = "unhashable runtime directory: " + representableReasonName(member(path))
			}
			return nil
		}
		if observed != nil {
			// WalkDir exposes os.DirEntry's namespace type before Info may
			// fail. The OS's unknown d_type is resolved by os before an entry
			// is returned (or the listing reports an error); Type()==0 on a
			// returned entry means regular, not fabricated full stat evidence.
			observed.put(path, namespaceFact, fmt.Sprintf("type %x", uint32(d.Type())))
			if path != root {
				parent := filepath.Dir(path)
				listings[parent] = append(listings[parent], filepath.Base(path))
			}
			if d.IsDir() {
				listings[path] = nil
			}
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
				reason = "unhashable runtime directory: " + representableReasonName(member(path))
			}
			return nil
		}
		if visit != nil {
			visit(rel)
		}
		observed.stat(path, namespaceStatFact, info, metadata)
		switch {
		case d.IsDir():
			// A directory object contributes its membership (the walk's
			// entry lines) and its mode; never its size or mtime, which
			// count only the churn of entries created and deleted within
			// the span. Nothing in the admitted observation set can read a
			// directory's own metadata (metadata methods block), so the
			// dropped fields guard nothing a subject could observe, and
			// keeping them would make a completed process's own restored
			// scratch churn indistinguishable from real drift.
			fprintf(h, "dir %s/ mode %x\n", rel, uint64(info.Mode()))
		case info.Mode().IsRegular():
			writeStat(h, info, metadata)
			sum, err := fileHash(ctx, path)
			if err != nil {
				unverifiable = true
				if reason == "" {
					reason = "unhashable runtime directory file: " + representableReasonName(member(path))
				}
				return nil
			}
			fprintf(h, "file %s %x\n", rel, sum)
			observed.put(path, contentFact, hex.EncodeToString(sum[:]))
		case info.Mode()&os.ModeSymlink != 0:
			writeStat(h, info, metadata)
			target, err := os.Readlink(path)
			if err != nil {
				unverifiable = true
				if reason == "" {
					reason = "unhashable runtime directory symlink: " + representableReasonName(member(path))
				}
				return nil
			}
			fprintf(h, "symlink %s %s\n", rel, target)
			observed.put(path, linkFact, target)
		default:
			unverifiable = true
			if reason == "" {
				reason = "unhashable runtime directory entry: " + representableReasonName(member(path))
			}
			fprintf(h, "unhashable %s %s\n", rel, info.Mode().String())
		}
		return nil
	})
	if err != nil {
		return [32]byte{}, false, "", err
	}
	for path, names := range listings {
		if err := ctx.Err(); err != nil {
			return [32]byte{}, false, "", err
		}
		offset, err := filepath.Rel(root, path)
		if err != nil {
			return [32]byte{}, false, "", err
		}
		observed.listing(path, filepath.ToSlash(offset), names, !failedListings[path])
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, unverifiable, reason, nil
}
