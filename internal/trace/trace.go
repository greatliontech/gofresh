// Package trace provides structured, zero-disabled-cost diagnostic tracing
// across gofresh's toolchain, closure, view, and session subsystems.
//
// Tracing is activated either via the GOFRESH_TRACE environment variable
// (writing to os.Stderr or GOFRESH_TRACE_FILE) or programmatically in tests
// via WithSink / WithFilteredSink and Recorder.
package trace

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Environment variable names governing diagnostic trace activation and output.
const (
	EnvTrace     = "GOFRESH_TRACE"
	EnvTraceFile = "GOFRESH_TRACE_FILE"
)

// Domain identifies a structured gofresh tracing subsystem.
type Domain string

const (
	DomainToolchain    Domain = "toolchain"
	DomainClosure      Domain = "closure"
	DomainDynstate     Domain = "dynstate"
	DomainRuntimeInput Domain = "runtimeinput"
	DomainCache        Domain = "cache"
	DomainView         Domain = "view"
	DomainSession      Domain = "session"
)

// FieldKind discriminates the value carried by a Field.
type FieldKind uint8

const (
	KindString FieldKind = iota + 1
	KindInt
	KindBool
	KindStrings
)

// Field is a key-value attribute attached to a trace Event.
type Field struct {
	Key   string
	Kind  FieldKind
	Str   string
	Int   int64
	Bool  bool
	Slice []string
	err   error
}

func (f Field) stringValue() string {
	if f.Str != "" || f.err == nil {
		return f.Str
	}
	return f.err.Error()
}

// String constructs a string-valued Field.
func String(key, val string) Field {
	return Field{Key: key, Kind: KindString, Str: val}
}

// Int constructs an integer-valued Field.
func Int(key string, val int) Field {
	return Field{Key: key, Kind: KindInt, Int: int64(val)}
}

// Int64 constructs an int64-valued Field.
func Int64(key string, val int64) Field {
	return Field{Key: key, Kind: KindInt, Int: val}
}

// Uint32 constructs a uint32-valued Field stored as int64.
func Uint32(key string, val uint32) Field {
	return Field{Key: key, Kind: KindInt, Int: int64(val)}
}

// Bool constructs a boolean-valued Field.
func Bool(key string, val bool) Field {
	return Field{Key: key, Kind: KindBool, Bool: val}
}

// Strings constructs a string-slice-valued Field. The slice is cloned only if
// the event is emitted to an active sink.
func Strings(key string, vals []string) Field {
	return Field{Key: key, Kind: KindStrings, Slice: vals}
}

// Err constructs an "error" Field when err is non-nil, or an empty Field
// omitted during formatting when err is nil. err.Error() is evaluated lazily
// only if the event is emitted or formatted.
func Err(err error) Field {
	if err == nil {
		return Field{}
	}
	return Field{Key: "error", Kind: KindString, err: err}
}

// Event is a single structured diagnostic trace record.
type Event struct {
	Time   time.Time
	PID    int
	Domain Domain
	Name   string
	Target string
	Fields []Field
}

// FieldValue returns the first Field with the given key.
func (e Event) FieldValue(key string) (Field, bool) {
	for _, f := range e.Fields {
		if f.Key == key {
			if f.Kind == KindString {
				f.Str = f.stringValue()
				f.err = nil
			}
			return f, true
		}
	}
	return Field{}, false
}

// StringField returns the string value of key, or "" if absent or not a string.
func (e Event) StringField(key string) string {
	if f, ok := e.FieldValue(key); ok && f.Kind == KindString {
		return f.Str
	}
	return ""
}

// IntField returns the integer value of key.
func (e Event) IntField(key string) (int64, bool) {
	if f, ok := e.FieldValue(key); ok && f.Kind == KindInt {
		return f.Int, true
	}
	return 0, false
}

// BoolField returns the boolean value of key.
func (e Event) BoolField(key string) (bool, bool) {
	if f, ok := e.FieldValue(key); ok && f.Kind == KindBool {
		return f.Bool, true
	}
	return false, false
}

// StringsField returns a copy of the string slice value of key, or nil if absent.
func (e Event) StringsField(key string) []string {
	if f, ok := e.FieldValue(key); ok && f.Kind == KindStrings {
		return slices.Clone(f.Slice)
	}
	return nil
}

// Sink consumes structured trace events. Implementations must be safe for
// concurrent calls from multiple goroutines.
type Sink interface {
	Emit(Event)
}

// filterRule matches a single domain with an optional target substring.
type filterRule struct {
	domain    Domain // "" means any domain
	substring string // "" means any target
}

// filter is a parsed GOFRESH_TRACE specification.
type filter struct {
	all   bool
	rules []filterRule
}

func (f filter) active() bool {
	return f.all || len(f.rules) > 0
}

func (f filter) matches(d Domain, target string) bool {
	if f.all {
		return true
	}
	for _, r := range f.rules {
		if r.domain != "" && r.domain != d {
			continue
		}
		if r.substring == "" || strings.Contains(target, r.substring) {
			return true
		}
	}
	return false
}

// parseFilter parses a comma-separated GOFRESH_TRACE specification.
func parseFilter(spec string) filter {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return filter{}
	}
	var out filter
	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		lower := strings.ToLower(token)
		switch lower {
		case "0", "false", "off", "none":
			continue
		case "1", "true", "all", "*":
			out.all = true
			continue
		}
		domPart, subPart, hasColon := strings.Cut(token, ":")
		domLower := strings.ToLower(strings.TrimSpace(domPart))
		var dom Domain
		switch domLower {
		case "all", "*":
			if !hasColon || subPart == "" {
				out.all = true
				continue
			}
			dom = ""
		case string(DomainToolchain):
			dom = DomainToolchain
		case string(DomainClosure):
			dom = DomainClosure
		case string(DomainDynstate):
			dom = DomainDynstate
		case string(DomainRuntimeInput):
			dom = DomainRuntimeInput
		case string(DomainCache):
			dom = DomainCache
		case string(DomainView):
			dom = DomainView
		case string(DomainSession):
			dom = DomainSession
		default:
			continue
		}
		out.rules = append(out.rules, filterRule{
			domain:    dom,
			substring: subPart,
		})
	}
	return out
}

type filteredSink struct {
	f    filter
	sink Sink
}

type ctxKey struct{}

type ctxSinkNode struct {
	fs      filteredSink
	parent  *ctxSinkNode
	done    <-chan struct{}
	counted *atomic.Bool
}

func (n *ctxSinkNode) decrement() {
	if n.counted.CompareAndSwap(true, false) {
		activeCount.Add(-1)
	}
}

func (n *ctxSinkNode) isActive() bool {
	if n.done != nil {
		select {
		case <-n.done:
			n.decrement()
			return false
		default:
		}
	}
	return true
}

// envConfig is a carrier-free configuration record for the ambient
// GOFRESH_TRACE / GOFRESH_TRACE_FILE sink so package-level globals in package
// trace contain zero interface or function fields.
type envConfig struct {
	spec       string
	filePath   string
	targetPath string
	f          filter
	jsonl      bool
}

var (
	// activeCount is the process-wide count of active trace sinks (at most 1
	// ambient environment sink plus any live context sinks). When <= 0,
	// Enabled and Emit return immediately after a single atomic load.
	activeCount atomic.Int32

	envMu  sync.Mutex
	envCfg atomic.Pointer[envConfig]
)

// Refresh synchronizes the ambient environment trace sink with explicit
// GOFRESH_TRACE and GOFRESH_TRACE_FILE values.
func Refresh(spec, filePath string) {
	envMu.Lock()
	defer envMu.Unlock()

	cur := envCfg.Load()
	if cur != nil && spec == cur.spec && filePath == cur.filePath {
		if filePath == "" {
			return
		}
		if cur.targetPath != "" {
			if _, err := os.Stat(cur.targetPath); err == nil {
				return
			}
		}
	}

	f := parseFilter(spec)
	if !f.active() {
		prev := envCfg.Swap(nil)
		if prev != nil {
			activeCount.Add(-1)
		}
		return
	}

	var (
		targetPath string
		jsonl      bool
	)
	if filePath != "" {
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err == nil {
			_ = file.Close()
			targetPath = filePath
			lowerPath := strings.ToLower(filePath)
			jsonl = strings.HasSuffix(lowerPath, ".jsonl") || strings.HasSuffix(lowerPath, ".json")
		}
	}

	next := &envConfig{
		spec:       spec,
		filePath:   filePath,
		targetPath: targetPath,
		f:          f,
		jsonl:      jsonl,
	}
	prev := envCfg.Swap(next)
	if prev == nil {
		activeCount.Add(1)
	}
}

func emitEnv(cfg *envConfig, ev Event) {
	var line []byte
	if cfg.jsonl {
		line = FormatJSONL(ev)
	} else {
		line = FormatText(ev)
	}
	envMu.Lock()
	defer envMu.Unlock()
	if cfg.targetPath != "" {
		if f, err := os.OpenFile(cfg.targetPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			_, _ = f.Write(line)
			_ = f.Close()
			return
		}
	}
	_, _ = os.Stderr.Write(line)
}

// WithSink attaches sink to ctx, receiving all trace events across all domains
// for operations using ctx.
func WithSink(ctx context.Context, sink Sink) context.Context {
	return WithFilteredSink(ctx, "all", sink)
}

// WithFilteredSink attaches sink to ctx with a GOFRESH_TRACE filter
// specification (for example "toolchain,closure:MySubject").
func WithFilteredSink(ctx context.Context, spec string, sink Sink) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if sink == nil {
		return ctx
	}
	f := parseFilter(spec)
	if !f.active() {
		return ctx
	}
	var parent *ctxSinkNode
	if existing, ok := ctx.Value(ctxKey{}).(*ctxSinkNode); ok {
		parent = existing
	}
	counted := new(atomic.Bool)
	counted.Store(true)
	node := &ctxSinkNode{
		fs:      filteredSink{f: f, sink: sink},
		parent:  parent,
		done:    ctx.Done(),
		counted: counted,
	}
	activeCount.Add(1)
	if ctx.Done() != nil {
		context.AfterFunc(ctx, node.decrement)
	}
	runtime.AddCleanup(node, func(c *atomic.Bool) {
		if c.CompareAndSwap(true, false) {
			activeCount.Add(-1)
		}
	}, counted)
	return context.WithValue(ctx, ctxKey{}, node)
}

// AnyEnabled reports whether any trace sink (ambient environment or context) is
// currently active in the process. It executes a single atomic load.
func AnyEnabled() bool {
	return activeCount.Load() > 0
}

// Enabled reports whether any active sink (ambient environment or ctx) matches
// domain and target. When tracing is disabled, Enabled executes a single
// atomic load and returns false.
func Enabled(ctx context.Context, domain Domain, target string) bool {
	if activeCount.Load() <= 0 {
		return false
	}
	return enabledSlow(ctx, domain, target)
}

func enabledSlow(ctx context.Context, domain Domain, target string) bool {
	if es := envCfg.Load(); es != nil && es.f.matches(domain, target) {
		return true
	}
	if ctx != nil {
		if node, ok := ctx.Value(ctxKey{}).(*ctxSinkNode); ok {
			for n := node; n != nil; n = n.parent {
				if n.isActive() && n.fs.f.matches(domain, target) {
					return true
				}
			}
		}
	}
	return false
}

// Emit dispatches a structured trace event to all matching active sinks. When
// tracing is disabled, Emit returns after a single atomic load.
func Emit(ctx context.Context, domain Domain, name, target string, fields ...Field) {
	if activeCount.Load() <= 0 {
		return
	}
	emitSlow(ctx, domain, name, target, fields)
}

func emitSlow(ctx context.Context, domain Domain, name, target string, fields []Field) {
	es := envCfg.Load()
	envMatch := es != nil && es.f.matches(domain, target)

	var ctxNode *ctxSinkNode
	ctxMatch := false
	if ctx != nil {
		if node, ok := ctx.Value(ctxKey{}).(*ctxSinkNode); ok {
			ctxNode = node
			for n := node; n != nil; n = n.parent {
				if n.isActive() && n.fs.f.matches(domain, target) {
					ctxMatch = true
					break
				}
			}
		}
	}
	if !envMatch && !ctxMatch {
		return
	}

	filtered := make([]Field, 0, len(fields))
	for _, f := range fields {
		if f.Key == "" {
			continue
		}
		if f.Kind == KindString {
			f.Str = f.stringValue()
			f.err = nil
		} else if f.Kind == KindStrings && f.Slice != nil {
			f.Slice = slices.Clone(f.Slice)
		}
		filtered = append(filtered, f)
	}

	ev := Event{
		Time:   time.Now().UTC(),
		PID:    os.Getpid(),
		Domain: domain,
		Name:   name,
		Target: target,
		Fields: filtered,
	}

	if envMatch {
		emitEnv(es, ev)
	}
	if ctxMatch {
		for n := ctxNode; n != nil; n = n.parent {
			if n.isActive() && n.fs.f.matches(domain, target) {
				n.fs.sink.Emit(ev)
			}
		}
	}
}

// writerSink formats events into single-line buffers and writes them atomically
// under a mutex.
type writerSink struct {
	mu    sync.Mutex
	w     io.Writer
	jsonl bool
}

// NewWriterSink returns a Sink that writes formatted trace lines to w. When
// jsonl is true, each event is formatted as JSON Lines; otherwise the
// line-oriented key-value format is used.
func NewWriterSink(w io.Writer, jsonl bool) Sink {
	return &writerSink{w: w, jsonl: jsonl}
}

func (s *writerSink) Emit(e Event) {
	var line []byte
	if s.jsonl {
		line = FormatJSONL(e)
	} else {
		line = FormatText(e)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.w.Write(line)
}

// FormatText formats e in the single-line key-value wire format:
//
//	gofresh/trace pid=<pid> domain=<d> event=<e> [target=<t>] <k>=<v> ...\n
func FormatText(e Event) []byte {
	var b bytes.Buffer
	b.Grow(128)
	b.WriteString("gofresh/trace pid=")
	b.WriteString(strconv.Itoa(e.PID))
	b.WriteString(" domain=")
	b.WriteString(formatTextValue(string(e.Domain)))
	b.WriteString(" event=")
	b.WriteString(formatTextValue(e.Name))
	if e.Target != "" {
		b.WriteString(" target=")
		b.WriteString(formatTextValue(e.Target))
	}
	for _, f := range e.Fields {
		if f.Key == "" {
			continue
		}
		b.WriteByte(' ')
		b.WriteString(f.Key)
		b.WriteByte('=')
		switch f.Kind {
		case KindString:
			b.WriteString(formatTextValue(f.stringValue()))
		case KindInt:
			b.WriteString(strconv.FormatInt(f.Int, 10))
		case KindBool:
			b.WriteString(strconv.FormatBool(f.Bool))
		case KindStrings:
			b.WriteString(formatTextValue(strings.Join(f.Slice, ",")))
		}
	}
	b.WriteByte('\n')
	return b.Bytes()
}

func formatTextValue(s string) string {
	if s == "" || needsQuoting(s) {
		return strconv.Quote(s)
	}
	return s
}

func needsQuoting(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c >= 0x7f || c == '"' || c == '=' || c == '\\' {
			return true
		}
	}
	return false
}

type jsonlEvent struct {
	TS     string         `json:"ts"`
	PID    int            `json:"pid"`
	Domain string         `json:"domain"`
	Event  string         `json:"event"`
	Target string         `json:"target,omitempty"`
	Fields map[string]any `json:"fields"`
}

// FormatJSONL formats e as a single newline-terminated JSON object:
//
//	{"ts":"<RFC3339Nano>","pid":<pid>,"domain":"<d>","event":"<e>","target":"<t>","fields":{...}}\n
func FormatJSONL(e Event) []byte {
	fields := make(map[string]any, len(e.Fields))
	for _, f := range e.Fields {
		if f.Key == "" {
			continue
		}
		switch f.Kind {
		case KindString:
			fields[f.Key] = f.stringValue()
		case KindInt:
			fields[f.Key] = f.Int
		case KindBool:
			fields[f.Key] = f.Bool
		case KindStrings:
			if f.Slice == nil {
				fields[f.Key] = []string{}
			} else {
				fields[f.Key] = f.Slice
			}
		}
	}
	payload := jsonlEvent{
		TS:     e.Time.UTC().Format(time.RFC3339Nano),
		PID:    e.PID,
		Domain: string(e.Domain),
		Event:  e.Name,
		Target: e.Target,
		Fields: fields,
	}
	var b bytes.Buffer
	b.Grow(160)
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(payload)
	return b.Bytes()
}

// Recorder is a concurrency-safe in-memory Sink for tests.
type Recorder struct {
	mu     sync.Mutex
	events []Event
}

// NewRecorder returns an empty Recorder.
func NewRecorder() *Recorder {
	return &Recorder{}
}

// Emit appends a deep copy of e to the recorder.
func (r *Recorder) Emit(e Event) {
	clonedFields := make([]Field, len(e.Fields))
	for i, f := range e.Fields {
		if f.Kind == KindString {
			f.Str = f.stringValue()
			f.err = nil
		} else if f.Kind == KindStrings && f.Slice != nil {
			f.Slice = slices.Clone(f.Slice)
		}
		clonedFields[i] = f
	}
	e.Fields = clonedFields

	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

// Events returns a snapshot of all recorded events in emission order.
func (r *Recorder) Events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, len(r.events))
	for i, e := range r.events {
		e.Fields = slices.Clone(e.Fields)
		out[i] = e
	}
	return out
}

// ByDomain returns all recorded events matching domain d.
func (r *Recorder) ByDomain(d Domain) []Event {
	all := r.Events()
	var out []Event
	for _, e := range all {
		if e.Domain == d {
			out = append(out, e)
		}
	}
	return out
}

// ByName returns all recorded events with Event.Name == name.
func (r *Recorder) ByName(name string) []Event {
	all := r.Events()
	var out []Event
	for _, e := range all {
		if e.Name == name {
			out = append(out, e)
		}
	}
	return out
}

// Reset clears all recorded events.
func (r *Recorder) Reset() {
	r.mu.Lock()
	r.events = nil
	r.mu.Unlock()
}
