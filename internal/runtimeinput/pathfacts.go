package runtimeinput

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
)

type pathFactKind uint8

const (
	followedStatFact pathFactKind = iota
	namespaceStatFact
	contentFact
	linkFact
	namespaceFact // a nonfollowed type, or the explicit value "missing"
	resolutionFact
	machineFact
)

type pathFact struct {
	path string
	kind pathFactKind
}

// pathFacts retains independently established facts from a hashing pass. An
// absent key means unknown, not an absent object. A known absent object has an
// explicit stat value. Thus a failed read never erases a successful stat or a
// sibling's content, and gaining or losing knowledge alone proves no movement.
// Followed-object and nonfollowed namespace stats have distinct keys: an alias
// may expose both at the same path, but they describe different objects.
// Every observed value is retained, including contradictions within one pass.
// Brackets own these maps and seal values, availability and listing scope.
type pathFacts struct {
	values   map[pathFact][]string
	listings map[string][]directoryListing
}

// A partial listing establishes its names, never absence. A complete listing
// establishes absence only outside its root's exclusions; offset retains that
// root-relative scope even when the walked directory is reached through a link.
type directoryListing struct {
	offset   string
	names    []string
	complete bool
}

func newPathFacts() *pathFacts {
	return &pathFacts{values: map[pathFact][]string{}, listings: map[string][]directoryListing{}}
}

func (f *pathFacts) put(path string, kind pathFactKind, value string) {
	if f != nil {
		key := pathFact{path, kind}
		values := f.values[key]
		if !slices.Contains(values, value) {
			values = append(values, value)
			sort.Strings(values)
			f.values[key] = values
		}
	}
}

func (f *pathFacts) knows(path string, kind pathFactKind) bool {
	return f != nil && len(f.values[pathFact{path, kind}]) != 0
}

func (f *pathFacts) listing(directory, offset string, names []string, complete bool) {
	if f == nil {
		return
	}
	names = slices.Clone(names)
	sort.Strings(names)
	names = slices.Compact(names)
	for _, old := range f.listings[directory] {
		if old.offset == offset && old.complete == complete && slices.Equal(old.names, names) {
			return
		}
	}
	rows := append(f.listings[directory], directoryListing{offset, names, complete})
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].offset != rows[j].offset {
			return rows[i].offset < rows[j].offset
		}
		if rows[i].complete != rows[j].complete {
			return !rows[i].complete
		}
		return slices.Compare(rows[i].names, rows[j].names) < 0
	})
	f.listings[directory] = rows
}

func (f *pathFacts) stat(path string, kind pathFactKind, info os.FileInfo, metadata bool) {
	if f == nil {
		return
	}
	h := sha256.New()
	if info.IsDir() {
		// Directory metadata outside membership and mode is deliberately not
		// observed: restored scratch churn must not become span movement.
		fprintf(h, "dir mode %x\n", uint64(info.Mode()))
	} else {
		writeStat(h, info, metadata)
	}
	f.put(path, kind, hex.EncodeToString(h.Sum(nil)))
}

func (f *pathFacts) seal(h hash.Hash) {
	if f == nil {
		return
	}
	keys := make([]pathFact, 0, len(f.values))
	for key := range f.values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].path != keys[j].path {
			return keys[i].path < keys[j].path
		}
		return keys[i].kind < keys[j].kind
	})
	for _, key := range keys {
		for _, value := range f.values[key] {
			fprintf(h, "fact %q %d %q\n", key.path, key.kind, value)
		}
	}
	directories := make([]string, 0, len(f.listings))
	for directory := range f.listings {
		directories = append(directories, directory)
	}
	sort.Strings(directories)
	for _, directory := range directories {
		for _, listing := range f.listings[directory] {
			fprintf(h, "listing %q offset %q complete %t\n", directory, listing.offset, listing.complete)
			for _, name := range listing.names {
				fprintf(h, "name %q\n", name)
			}
			fprintf(h, "end-listing\n")
		}
	}
}

// movedBracketRoot compares one observation account across all declared roots
// and both endpoints. Root provenance is retained for attribution and for each
// complete listing's exclusion scope. Scalar comparison preserves observation
// meaning. Namespace existence is shared by direct namespace observations and
// listing names: either can contradict explicit namespace absence or complete,
// non-excluded listing absence. Followed-object stats supply no namespace claim.
// Conflicts within an endpoint are retained too.
func movedBracketRoot(ctx context.Context, before, after []bracketRoot, exclusions []pathID) (int, error) {
	type scalarObservation struct {
		root  int
		value string
	}
	type listingObservation struct {
		root    int
		listing directoryListing
	}
	type presenceObservation struct {
		root int
		name string
	}
	values := map[pathFact][]scalarObservation{}
	listings := map[string][]listingObservation{}
	presences := map[string][]presenceObservation{}
	moved := make([]bool, len(before))
	for _, roots := range [][]bracketRoot{before, after} {
		for i, root := range roots {
			if err := ctx.Err(); err != nil {
				return -1, err
			}
			if root.facts == nil {
				continue
			}
			for key, observed := range root.facts.values {
				if err := ctx.Err(); err != nil {
					return -1, err
				}
				for _, value := range observed {
					if err := ctx.Err(); err != nil {
						return -1, err
					}
					values[key] = append(values[key], scalarObservation{i, value})
					if key.kind == namespaceFact && value != "missing" {
						parent := filepath.Dir(key.path)
						if parent != key.path {
							presences[parent] = append(presences[parent], presenceObservation{i, filepath.Base(key.path)})
						}
					}
				}
			}
			for directory, observed := range root.facts.listings {
				if err := ctx.Err(); err != nil {
					return -1, err
				}
				for _, listing := range observed {
					listings[directory] = append(listings[directory], listingObservation{i, listing})
					for _, name := range listing.names {
						if err := ctx.Err(); err != nil {
							return -1, err
						}
						presences[directory] = append(presences[directory], presenceObservation{i, name})
					}
				}
			}
		}
	}
	for _, observations := range values {
		if err := ctx.Err(); err != nil {
			return -1, err
		}
		conflict := false
		for _, observed := range observations {
			if err := ctx.Err(); err != nil {
				return -1, err
			}
			if observed.value != observations[0].value {
				conflict = true
			}
		}
		if conflict {
			for _, observed := range observations {
				if err := ctx.Err(); err != nil {
					return -1, err
				}
				moved[observed.root] = true
			}
		}
	}
	for directory, names := range presences {
		// Only namespace absence belongs here. A missing followed object can
		// coexist with its present dangling link and is a different fact.
		for _, presence := range names {
			if err := ctx.Err(); err != nil {
				return -1, err
			}
			key := pathFact{filepath.Join(directory, presence.name), namespaceFact}
			for _, absence := range values[key] {
				if err := ctx.Err(); err != nil {
					return -1, err
				}
				if absence.value == "missing" {
					moved[absence.root], moved[presence.root] = true, true
				}
			}
		}
		for _, absence := range listings[directory] {
			if err := ctx.Err(); err != nil {
				return -1, err
			}
			if !absence.listing.complete {
				continue
			}
			for _, presence := range names {
				if err := ctx.Err(); err != nil {
					return -1, err
				}
				if _, found := slices.BinarySearch(absence.listing.names, presence.name); found {
					continue
				}
				identity := walkIdentity(before[absence.root].id, path.Join(absence.listing.offset, presence.name))
				if excludesIdentity(exclusions, identity) {
					continue
				}
				moved[absence.root], moved[presence.root] = true, true
			}
		}
	}
	// Canonical root order, rather than map iteration order, chooses attribution.
	for i, conflict := range moved {
		if conflict {
			return i, nil
		}
	}
	return -1, ctx.Err()
}
