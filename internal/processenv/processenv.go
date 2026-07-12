// Package processenv validates and queries complete process environments.
package processenv

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// ForCommand returns env with PWD derived from dir, matching the environment
// go/packages gives a Go command run under packages.Config.Dir.
func ForCommand(env []string, dir string) ([]string, error) {
	if dir == "" {
		return Normalize(env)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	normalized, err := Normalize(env)
	if err != nil {
		return nil, err
	}
	command := make([]string, 0, len(normalized)+1)
	for _, entry := range normalized {
		name, _, _ := split(entry)
		if !equalKey(name, "PWD") {
			command = append(command, entry)
		}
	}
	return Normalize(append(command, "PWD="+abs))
}

// Normalize returns a deterministic owned copy of env. Entries must use the
// exec.Cmd key=value form, and duplicate keys are refused rather than resolved
// by platform-dependent first- or last-entry behavior.
func Normalize(env []string) ([]string, error) {
	normalized := make([]string, len(env))
	seen := make(map[string]bool, len(env))
	for i, entry := range env {
		if strings.IndexByte(entry, 0) >= 0 {
			return nil, fmt.Errorf("environment entry %d contains NUL", i)
		}
		key, _, ok := split(entry)
		if !ok {
			return nil, fmt.Errorf("environment entry %d is malformed: expected non-empty key=value", i)
		}
		identity := key
		if runtime.GOOS == "windows" {
			identity = strings.ToUpper(key)
		}
		if seen[identity] {
			return nil, fmt.Errorf("environment contains duplicate key %q", key)
		}
		seen[identity] = true
		normalized[i] = entry
	}
	sort.Slice(normalized, func(i, j int) bool {
		left, _, _ := split(normalized[i])
		right, _, _ := split(normalized[j])
		if runtime.GOOS == "windows" {
			left = strings.ToUpper(left)
			right = strings.ToUpper(right)
		}
		if left == right {
			return normalized[i] < normalized[j]
		}
		return left < right
	})
	return normalized, nil
}

// ForGoPackages returns a normalized environment that cannot delegate source
// selection to an external package driver. The ordinary Go loader is the source
// model freshness analysis represents.
func ForGoPackages(env []string) ([]string, error) {
	normalized, err := Normalize(env)
	if err != nil {
		return nil, err
	}
	if driver, ok := Lookup(normalized, "GOPACKAGESDRIVER"); ok {
		if driver != "" && driver != "off" {
			return nil, fmt.Errorf("GOPACKAGESDRIVER=%q is unsupported because freshness analysis requires Go package loading", driver)
		}
	}
	pinned := make([]string, 0, len(normalized)+1)
	for _, entry := range normalized {
		name, _, _ := split(entry)
		if !equalKey(name, "GOPACKAGESDRIVER") {
			pinned = append(pinned, entry)
		}
	}
	return Normalize(append(pinned, "GOPACKAGESDRIVER=off"))
}

// Lookup returns key's value from a normalized complete environment.
func Lookup(env []string, key string) (string, bool) {
	for _, entry := range env {
		name, value, ok := split(entry)
		if ok && equalKey(name, key) {
			return value, true
		}
	}
	return "", false
}

// EqualKey reports whether two environment names identify the same variable on
// the current platform.
func EqualKey(left, right string) bool { return equalKey(left, right) }

func split(entry string) (string, string, bool) {
	equals := strings.IndexByte(entry, '=')
	if equals > 0 {
		return entry[:equals], entry[equals+1:], true
	}
	if runtime.GOOS == "windows" && equals == 0 {
		// Windows carries hidden per-drive working-directory entries such as
		// =C:=C:\path in an otherwise ordinary process environment.
		if second := strings.IndexByte(entry[1:], '='); second > 0 {
			second++
			return entry[:second], entry[second+1:], true
		}
	}
	return "", "", false
}

func equalKey(left, right string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}
