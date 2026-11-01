package gofresh

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// ParseVouchEntry maps one reviewed spelling, IMPORT-PATH:VARIABLE, to
// the canonical dotted identity the engine judges under
// (REQ-vouch-input): the import path carries no space or control
// character and the variable is one Go identifier — a vouch names
// exactly one variable, never a package or a pattern.
func ParseVouchEntry(entry string) (string, error) {
	pkg, name, ok := strings.Cut(entry, ":")
	if !ok || pkg == "" || name == "" {
		return "", fmt.Errorf("vouch %q is not IMPORT-PATH:VARIABLE", entry)
	}
	for _, r := range pkg {
		if r <= ' ' || r == 0x7f || unicode.IsControl(r) {
			return "", fmt.Errorf("vouch package %q carries a control or space character", pkg)
		}
	}
	for i, r := range name {
		letter := unicode.IsLetter(r) || r == '_'
		if (i == 0 && !letter) || (i > 0 && !letter && !unicode.IsDigit(r)) {
			return "", fmt.Errorf("vouch variable %q is not one Go identifier", name)
		}
	}
	return pkg + "." + name, nil
}

// ParseVouchEntries maps reviewed spellings to the engine's vouch SET:
// each entry parsed by ParseVouchEntry, the identities deduplicated and
// sorted — a repeated entry is one acceptance, and the set an engine
// receives is one whatever order the entries came in (REQ-vouch-input).
// A malformed entry refuses the whole set, fail-closed.
func ParseVouchEntries(entries []string) ([]string, error) {
	identities := make([]string, 0, len(entries))
	for _, entry := range entries {
		identity, err := ParseVouchEntry(entry)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	slices.Sort(identities)
	return slices.Compact(identities), nil
}
