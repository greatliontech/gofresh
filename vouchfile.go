package gofresh

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"unicode"
)

// RepositoryVouchFile is the reviewed standing dynamic-state vouch set's
// file at the root the engine is opened at, the one home every consumer
// judging that tree shares: one IMPORT-PATH:VARIABLE per line, `#` comments and
// blank lines ignored, an absent file the empty set, a malformed line a
// refusal of the engine naming the file and line (REQ-vouch-input).
const RepositoryVouchFile = "vouches"

// ReadVouchFile reads a vouch file into canonical dotted identities,
// sorted and deduplicated; a missing file is the empty set, and a
// malformed line refuses naming the file and line, fail-closed — a vouch
// suppresses an unverifiable verdict, so a set that cannot be read
// whole is never partly honored (REQ-vouch-input).
func ReadVouchFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("vouch file %s: %w", path, err)
	}
	defer f.Close()
	var identities []string
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		identity, err := ParseVouchEntry(text)
		if err != nil {
			return nil, fmt.Errorf("vouch file %s:%d: %w", path, line, err)
		}
		identities = append(identities, identity)
	}
	// A file that cannot be read whole (a directory at the path, a line
	// past the scanner's token size, an interrupted read) refuses with
	// nothing honored: the lines read so far are never a partial set.
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("vouch file %s: %w", path, err)
	}
	slices.Sort(identities)
	return slices.Compact(identities), nil
}

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
