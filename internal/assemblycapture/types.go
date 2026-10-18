// Package assemblycapture acquires current Go assembly inputs at the actual
// tool-execution boundary. Its packets are observations, not implementation
// proofs. The caller retains source/build hold-still obligations: inotify does
// not observe mmap writes, remote filesystem writes, or mount substitution and
// does not establish universal absence of mutation-and-restore. Those remain
// under the caller's source/build exclusion; local notified mutations and
// observable post-snapshot drift invalidate the acquisition.
package assemblycapture

import (
	"context"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Limits bounds one acquisition, including all providers and response files.
// Zero fields select finite defaults. Negative values refuse the request.
type Limits struct {
	Bytes, Tokens, Files, Actions, Watches, Events, Depth int
	Duration                                              time.Duration
}

func (l Limits) normalized() (Limits, error) {
	values := []*int{&l.Bytes, &l.Tokens, &l.Files, &l.Actions, &l.Watches, &l.Events, &l.Depth}
	defaults := []int{512 << 20, 4 << 20, 32768, 32768, 65536, 1 << 20, 100}
	for i, p := range values {
		if *p < 0 {
			return l, fmt.Errorf("assembly capture: negative resource bound")
		}
		if *p == 0 {
			*p = defaults[i]
		}
	}
	if l.Duration < 0 {
		return l, fmt.Errorf("assembly capture: negative duration bound")
	}
	if l.Duration == 0 {
		l.Duration = 10 * time.Minute
	}
	return l, nil
}

type meter struct {
	ctx                                            context.Context
	limits                                         Limits
	mu                                             sync.Mutex
	bytes, tokens, files, actions, watches, events int
	inputBytes                                     map[string]int
}

func (m *meter) readBytes(path string, n int) error {
	if err := m.charge("bytes", n); err != nil {
		return fmt.Errorf("%w while reading %s", err, path)
	}
	// Cost attribution is advisory, never a selection or acceptance rule.
	kind := "other"
	name := filepath.Base(path)
	switch {
	case name == "go" || name == "compile" || name == "asm" || name == "preprofile":
		kind = "tools"
	case strings.HasSuffix(name, ".pgo") || name == "pgo.preprofile":
		kind = "profiles"
	case filepath.Ext(name) == ".go":
		kind = "Go-source"
	case filepath.Ext(name) == ".s" || filepath.Ext(name) == ".h":
		kind = "assembly-source"
	case name == "importcfg" || name == "embedcfg" || name == "symabis" || name == "coveragecfg" || name == "go.mod" || name == "go.sum" || name == "go.work" || name == "go.work.sum":
		kind = "configuration"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inputBytes == nil {
		m.inputBytes = map[string]int{}
	}
	m.inputBytes[kind] += n
	return nil
}

func (m *meter) charge(kind string, n int) error {
	if err := m.ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var used *int
	var max int
	switch kind {
	case "bytes":
		used, max = &m.bytes, m.limits.Bytes
	case "tokens":
		used, max = &m.tokens, m.limits.Tokens
	case "files":
		used, max = &m.files, m.limits.Files
	case "actions":
		used, max = &m.actions, m.limits.Actions
	case "watches":
		used, max = &m.watches, m.limits.Watches
	case "events":
		used, max = &m.events, m.limits.Events
	default:
		return fmt.Errorf("assembly capture: unknown resource %q", kind)
	}
	if n < 0 || n > max-*used {
		return fmt.Errorf("assembly capture: %s bound exhausted (used %d, requested %d, limit %d)", kind, *used, n, max)
	}
	*used += n
	return nil
}

// Line is one expanded assembly line. Tokens retain lexical boundaries; Text
// is a whitespace-normalized rendering. File and Line name the physical source
// occurrence, including the invocation site of an expanded macro.
type Line struct {
	File   string
	Line   int
	Text   string
	Tokens []string
}

// Invocation is the observed process boundary, before response expansion and
// with the effective parsed assembly operands beside it. Env is the raw tool
// environment, not a replacement inferred from go env.
type Invocation struct {
	Tool, CWD, Package, Instance                           string
	Args, Env, ExpandedArgs, Sources, IncludeDirs, Defines []string
	Output                                                 string
}

// Provider is a caller-owned projection of a completely preprocessed selected
// provider. Its original source and every included file remain owned by Packet.
type Provider struct {
	Source     string
	Lines      []Line
	Invocation Invocation
}

// Lookup records a successful include resolution and each preceding failed
// candidate, in search order. Failed candidates were observed absent, not
// guessed from a directory name or diagnostic listing.
type Lookup struct {
	Name, Selected string
	Failed         []string
}

// Packet is sealed only after successful final actions, complete provider and
// compiler agreement, protected input-use intervals, and closing validation.
// No public constructor accepts preprocessed text or an asserted completion.
type Packet struct {
	selection *Selection
	instance  string
	providers []Provider
	files     map[string][]byte
	lookups   []Lookup
	compilers []Invocation
	usage     Usage
}

// Usage is the cumulative acquisition observation cost, including agreement
// reads and all action intervals. It does not count the driver's internal work;
// the acquisition context bounds that work.
type Usage struct {
	Bytes, Tokens, Files, Actions, Watches, Events int
	InputBytes                                     map[string]int
}

// Usage returns the retained cumulative observation account.
func (p *Packet) Usage() Usage {
	if p == nil {
		return Usage{}
	}
	u := p.usage
	u.InputBytes = maps.Clone(u.InputBytes)
	return u
}

// BoundTo checks exact selection ownership, not equal content or package names.
func (p *Packet) BoundTo(s *Selection, instance string) bool {
	return p != nil && s != nil && p.selection == s && p.instance == instance && len(p.providers) != 0
}

// Providers returns independent copies of the complete provider projections.
func (p *Packet) Providers() []Provider {
	if p == nil {
		return nil
	}
	out := slices.Clone(p.providers)
	for i := range out {
		out[i].Invocation = cloneInvocation(out[i].Invocation)
		out[i].Lines = slices.Clone(out[i].Lines)
		for j := range out[i].Lines {
			out[i].Lines[j].Tokens = slices.Clone(out[i].Lines[j].Tokens)
		}
	}
	return out
}

// Files returns the captured source, include and response-file bytes.
func (p *Packet) Files() map[string][]byte {
	if p == nil {
		return nil
	}
	return copyFiles(p.files)
}

// Lookups returns the protected include-search evidence.
func (p *Packet) Lookups() []Lookup {
	if p == nil {
		return nil
	}
	out := slices.Clone(p.lookups)
	for i := range out {
		out[i].Failed = slices.Clone(out[i].Failed)
	}
	return out
}

// Environment returns the selected go environment, including effective defaults
// absent from the raw process environment (for example GOARCH).
func (p *Packet) Environment() map[string]string {
	if p == nil || p.selection == nil {
		return nil
	}
	return maps.Clone(p.selection.goenv)
}

func copyFiles(in map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(in))
	for k, v := range in {
		out[k] = slices.Clone(v)
	}
	return out
}

func cloneInvocation(v Invocation) Invocation {
	v.Args = slices.Clone(v.Args)
	v.Env = slices.Clone(v.Env)
	v.ExpandedArgs = slices.Clone(v.ExpandedArgs)
	v.Sources = slices.Clone(v.Sources)
	v.IncludeDirs = slices.Clone(v.IncludeDirs)
	v.Defines = slices.Clone(v.Defines)
	return v
}
