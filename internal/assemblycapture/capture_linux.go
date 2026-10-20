//go:build linux && !android

package assemblycapture

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/buildflags"
	"golang.org/x/sys/unix"
)

//go:embed shim/main.go.txt
var shimSource []byte

type boundaryStart struct {
	Token, Tool, CWD string
	PID              int
	Args, Env        []string
}
type boundaryReply struct {
	Observe bool
	Error   string
}
type boundaryFinish struct {
	Exit, Signal int
	Error        string
}

type capturedAction struct {
	inv       Invocation
	parsed    parsedTool
	providers []Provider
	lookups   []Lookup
	inputs    map[string]fileObservation
	output    []byte // preprofile output, captured before namespace release
}

type captureServer struct {
	ctx         context.Context
	cancel      context.CancelFunc
	selection   *Selection
	provider    Package
	m           *meter
	token       string
	listener    *net.UnixListener
	mu          sync.Mutex
	err         error
	actions     []*capturedAction
	connections map[*net.UnixConn]bool
	wg          sync.WaitGroup
	acceptDone  chan struct{}
}

// Acquire forces current actions of the original roots. Only cache execution
// policy and the private output destination change. The generated output is
// discarded and can never substitute for an independently inspected image.
func Acquire(ctx context.Context, s *Selection, instance string, limits Limits) (result *Packet, resultErr error) {
	if ctx == nil {
		return nil, fmt.Errorf("assembly capture: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || !s.sealed {
		return nil, fmt.Errorf("assembly capture: missing sealed load-time selection")
	}
	p, ok := s.packages[instance]
	if !ok || len(p.Assembly) == 0 {
		return nil, fmt.Errorf("assembly capture: exact provider instance absent or has no assembly")
	}
	if len(p.Opaque) != 0 {
		return nil, fmt.Errorf("assembly capture: competing opaque package inputs: %s", instance)
	}
	limits, err := limits.normalized()
	if err != nil {
		return nil, err
	}
	bounded, stop := context.WithTimeout(ctx, limits.Duration)
	defer stop()
	work, cancel := context.WithCancel(bounded)
	defer cancel()
	m := &meter{ctx: work, limits: limits}
	if err = s.validateMetadata(work); err != nil {
		return nil, err
	}
	temp, err := os.MkdirTemp("", "gofresh-assembly-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := os.RemoveAll(temp); err != nil {
			result = nil
			resultErr = errors.Join(resultErr, fmt.Errorf("assembly capture: private namespace cleanup: %w", err))
		}
		if err := ctx.Err(); err != nil {
			result, resultErr = nil, err
		} else if err := bounded.Err(); err != nil {
			result, resultErr = nil, fmt.Errorf("assembly capture: acquisition duration/context bound: %w", err)
		}
	}()
	shim, err := buildShim(work, s, temp)
	if err != nil {
		return nil, err
	}
	// Protect source/build paths before the final agreement. Watching an
	// ancestor filters by relevant child name, not unrelated directory traffic.
	guard, err := newInputSet(work, m)
	if err != nil {
		return nil, err
	}
	defer guard.close()
	for path, want := range s.files {
		got, err := guard.read(path)
		if err != nil {
			return nil, err
		}
		if !sameObservation(want, got) {
			return nil, fmt.Errorf("assembly capture: owner input drift: %s", path)
		}
	}
	for dir := range s.directories {
		if err = guard.watch.addPath(dir); err != nil {
			return nil, err
		}
	}
	if err = s.validateMetadata(work); err != nil {
		return nil, err
	}
	if err = guard.validate(); err != nil {
		return nil, fmt.Errorf("assembly capture: before-build owner validation: %w", err)
	}
	server, err := startServer(work, cancel, s, p, m, temp)
	if err != nil {
		return nil, err
	}
	defer server.close()
	args := []string{"build"}
	if s.request.Tests {
		args = []string{"test", "-c"}
	}
	args = append(args, s.request.Flags...)
	output := filepath.Join(temp, "output")
	directoryOutput := s.request.Tests
	rootCount := 0
	for _, root := range s.packages {
		if root.Root {
			rootCount++
			directoryOutput = directoryOutput || root.Name == "main"
		}
	}
	if directoryOutput {
		if err = os.Mkdir(output, 0700); err != nil {
			return nil, err
		}
		output += string(filepath.Separator)
	} else if rootCount > 1 {
		// The Go driver accepts the null output for several library roots;
		// those roots otherwise have no single materialized archive output.
		output = os.DevNull
	}
	boundary, err := buildflags.Join([]string{shim, server.listener.Addr().String(), server.token})
	if err != nil {
		return nil, fmt.Errorf("assembly capture: encode private tool boundary: %w", err)
	}
	args = append(args, "-a", "-o", output, "-toolexec="+boundary)
	args = append(args, s.request.Roots...)
	_, runErr := s.runner.Run(work, s.request.Dir, s.request.Env, args...)
	server.close()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = bounded.Err(); err != nil {
		return nil, fmt.Errorf("assembly capture: acquisition duration/context bound: %w", err)
	}
	if server.err != nil {
		return nil, server.err
	}
	if runErr != nil {
		return nil, runErr
	}
	if err = s.validateMetadata(work); err != nil {
		return nil, err
	}
	if err = guard.validate(); err != nil {
		return nil, fmt.Errorf("assembly capture: after-build owner validation: %w", err)
	}
	packet, err := server.finish()
	if err != nil {
		return nil, err
	}
	if err = work.Err(); err != nil {
		return nil, err
	}
	return packet, nil
}

func buildShim(ctx context.Context, s *Selection, dir string) (string, error) {
	source := filepath.Join(dir, "main.go")
	target := filepath.Join(dir, "boundary")
	if err := os.WriteFile(source, shimSource, 0600); err != nil {
		return "", err
	}
	env := slices.Clone(s.request.Env)
	for key, value := range map[string]string{"GOFLAGS": "", "GOWORK": "off", "GO111MODULE": "off", "GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH, "CGO_ENABLED": "0"} {
		env = gotool.SetEnv(env, key, value)
	}
	_, err := s.runner.Run(ctx, dir, env, "build", "-a", "-trimpath", "-pgo=off", "-o", target, source)
	if err != nil {
		return "", fmt.Errorf("assembly capture: build private boundary: %w", err)
	}
	return target, nil
}

func startServer(ctx context.Context, cancel context.CancelFunc, s *Selection, p Package, m *meter, temp string) (*captureServer, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(temp, "capture.sock"), Net: "unix"})
	if err != nil {
		return nil, err
	}
	c := &captureServer{ctx: ctx, cancel: cancel, selection: s, provider: p, m: m, token: hex.EncodeToString(token[:]), listener: listener, connections: map[*net.UnixConn]bool{}, acceptDone: make(chan struct{})}
	go func() {
		defer close(c.acceptDone)
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			c.mu.Lock()
			c.connections[conn] = true
			c.wg.Add(1)
			c.mu.Unlock()
			go func() {
				defer c.wg.Done()
				defer conn.Close()
				defer func() { c.mu.Lock(); delete(c.connections, conn); c.mu.Unlock() }()
				if err := c.handle(conn); err != nil {
					c.fail(err)
				}
			}()
		}
	}()
	return c, nil
}

func (c *captureServer) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.mu.Unlock()
	c.cancel()
}

func (c *captureServer) close() {
	_ = c.listener.Close()
	<-c.acceptDone
	c.mu.Lock()
	for conn := range c.connections {
		_ = conn.Close()
	}
	c.mu.Unlock()
	c.wg.Wait()
}

func (c *captureServer) handle(conn *net.UnixConn) error {
	stop := context.AfterFunc(c.ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := c.ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	var first [1]byte
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, flags, _, err := conn.ReadMsgUnix(first[:], oob)
	if err != nil {
		return err
	}
	if n != 1 || first[0] != 1 || flags&unix.MSG_CTRUNC != 0 {
		return fmt.Errorf("assembly capture: incomplete directory-handle handshake")
	}
	control, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return err
	}
	var fds []int
	for _, message := range control {
		rights, err := unix.ParseUnixRights(&message)
		if err != nil {
			return err
		}
		fds = append(fds, rights...)
	}
	defer func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}()
	if len(fds) != 1 {
		return fmt.Errorf("assembly capture: missing actual working-directory handle")
	}
	unix.CloseOnExec(fds[0])
	directory := os.NewFile(uintptr(fds[0]), "captured working directory")
	// os.File owns this descriptor from here; avoid a later finalizer closing a
	// reused descriptor after the explicit close.
	fds = nil
	defer directory.Close()
	dec := json.NewDecoder(io.LimitReader(conn, 8<<20))
	enc := json.NewEncoder(conn)
	var start boundaryStart
	if err = dec.Decode(&start); err != nil {
		return err
	}
	if start.Token != c.token || start.PID <= 0 {
		return fmt.Errorf("assembly capture: foreign boundary handshake")
	}
	var peer *unix.Ucred
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var peerErr error
	if err = raw.Control(func(fd uintptr) { peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return err
	}
	if peerErr != nil || peer == nil || int(peer.Pid) != start.PID || int(peer.Uid) != os.Getuid() {
		return fmt.Errorf("assembly capture: boundary peer identity mismatch")
	}
	info, err := directory.Stat()
	if err != nil {
		return err
	}
	named, err := os.Stat(start.CWD)
	if err != nil {
		return err
	}
	if !info.IsDir() || !os.SameFile(info, named) {
		return fmt.Errorf("assembly capture: actual working directory differs from boundary path")
	}
	if err = c.m.charge("actions", 1); err != nil {
		return err
	}
	for _, v := range append(slices.Clone(start.Args), start.Env...) {
		if err = c.m.charge("bytes", len(v)); err != nil {
			return err
		}
	}
	instance, _ := gotool.LookupEnv(start.Env, "TOOLEXEC_IMPORTPATH")
	tool := filepath.Base(start.Tool)
	inv := Invocation{Tool: start.Tool, CWD: start.CWD, Args: slices.Clone(start.Args), Env: slices.Clone(start.Env), Instance: instance}
	version := len(start.Args) == 1 && (start.Args[0] == "-V" || strings.HasPrefix(start.Args[0], "-V="))
	_, selected := c.selection.packages[instance]
	observe := !version && (tool == "compile" && selected || tool == "asm" && instance == c.provider.ID || tool == "preprofile")
	if !observe {
		return enc.Encode(boundaryReply{})
	}
	if !filepath.IsAbs(start.Tool) || filepath.Clean(start.Tool) != filepath.Join(c.selection.goenv["GOTOOLDIR"], tool) {
		return fmt.Errorf("assembly capture: unexpected real tool %s", start.Tool)
	}
	inputs, err := newInputSet(c.ctx, c.m)
	if err != nil {
		return err
	}
	defer inputs.close()
	inv, parsed, err := parseInvocation(inputs, inv)
	if err != nil {
		return err
	}
	if tool == "asm" && (parsed.last("gensymabis") == "true" || parsed.last("V") != "") {
		return enc.Encode(boundaryReply{})
	}
	if err = c.checkEnvironment(inv); err != nil {
		return err
	}
	action := &capturedAction{inv: inv, parsed: parsed}
	if err = c.prepare(action, inputs); err != nil {
		return err
	}
	if err = action.validateInputs(inputs, "before-tool"); err != nil {
		return err
	}
	if err = enc.Encode(boundaryReply{Observe: true}); err != nil {
		return err
	}
	var finish boundaryFinish
	if err = dec.Decode(&finish); err != nil {
		return err
	}
	if err = action.validateInputs(inputs, "after-tool"); err != nil {
		return err
	}
	if tool == "preprofile" && finish.Exit == 0 && finish.Signal == 0 && finish.Error == "" {
		// Output is not an input until now; protect and independently copy it
		// while the preprocessor's namespace is still held by the shim.
		o, err := inputs.read(inv.Output)
		if err != nil {
			return err
		}
		if o.absent {
			return fmt.Errorf("assembly capture: profile output missing")
		}
		action.output = slices.Clone(o.data)
		if err = action.validateInputs(inputs, "preprofile-output"); err != nil {
			return err
		}
	}
	if finish.Exit != 0 || finish.Signal != 0 || finish.Error != "" {
		// Preserve the actual failure disposition; no successful packet will
		// be constructed from a failed outer build.
		return enc.Encode(boundaryReply{})
	}
	action.inputs = maps.Clone(inputs.files)
	c.mu.Lock()
	c.actions = append(c.actions, action)
	c.mu.Unlock()
	return enc.Encode(boundaryReply{})
}

func (a *capturedAction) validateInputs(inputs *inputSet, phase string) error {
	if err := inputs.validate(); err != nil {
		return fmt.Errorf("assembly capture: action instance %q, tool %q, directory %q, output %q, validation phase %s: %w", a.inv.Instance, a.inv.Tool, a.inv.CWD, a.inv.Output, phase, err)
	}
	return nil
}

func (c *captureServer) checkEnvironment(inv Invocation) error {
	if _, err := gotool.NormalizeEnv(inv.Env); err != nil {
		return err
	}
	for _, entry := range c.selection.request.Env {
		key, value, _ := strings.Cut(entry, "=")
		if key == "PWD" || key == "TERM" || key == "TOOLEXEC_IMPORTPATH" {
			continue
		}
		got, ok := gotool.LookupEnv(inv.Env, key)
		if !ok || got != value && got != c.selection.goenv[key] {
			return fmt.Errorf("assembly capture: boundary environment differs for %s", key)
		}
	}
	return nil
}

func (c *captureServer) prepare(a *capturedAction, inputs *inputSet) error {
	tool := filepath.Base(a.inv.Tool)
	if tool == "preprofile" {
		path := absolute(a.inv.CWD, a.parsed.last("i"))
		want, ok := c.selection.files[path]
		got, err := inputs.read(path)
		if err != nil {
			return err
		}
		if !ok || want.absent || !sameObservation(want, got) {
			return fmt.Errorf("assembly capture: profile input does not belong to selected owner: %s", path)
		}
		return nil
	}
	p := c.selection.packages[a.inv.Instance]
	if err := c.selection.checkExplicitOptions(p, a.inv, a.parsed, inputs); err != nil {
		return err
	}
	// The driver-qualified object namespace is the source import path. The
	// separate TOOLEXEC_IMPORTPATH retains the exact test/PGO build instance.
	wantPackage := p.Path
	if p.Name == "main" {
		wantPackage = "main"
	}
	if a.inv.Package != wantPackage {
		return fmt.Errorf("assembly capture: qualified package differs: %s != %s", a.inv.Package, wantPackage)
	}
	if tool == "asm" {
		selectedDir, dirErr := os.Stat(p.Dir)
		actualDir, cwdErr := os.Stat(a.inv.CWD)
		if dirErr != nil || cwdErr != nil || !selectedDir.IsDir() || !actualDir.IsDir() || !os.SameFile(selectedDir, actualDir) {
			return fmt.Errorf("assembly capture: assembler working directory differs from selected provider")
		}
		if len(a.inv.Sources) != 1 {
			return fmt.Errorf("assembly capture: final assembler action has ambiguous source operands")
		}
		for _, source := range a.inv.Sources {
			if !slices.Contains(p.Assembly, source) {
				return fmt.Errorf("assembly capture: foreign assembly provider %s", source)
			}
			o, err := inputs.read(source)
			if err != nil {
				return err
			}
			if !sameObservation(c.selection.files[source], o) {
				return fmt.Errorf("assembly capture: provider bytes changed")
			}
			provider, lookups, err := preprocess(inputs, a.inv, source)
			if err != nil {
				return err
			}
			a.providers = append(a.providers, provider)
			a.lookups = append(a.lookups, lookups...)
		}
		return nil
	}
	if len(a.inv.Sources) != len(p.GoFiles) {
		return fmt.Errorf("assembly capture: compiler source membership differs: %s", p.ID)
	}
	remaining := map[string]bool{}
	for _, path := range p.GoFiles {
		remaining[path] = true
	}
	for _, path := range a.inv.Sources {
		o, err := inputs.read(path)
		if err != nil {
			return err
		}
		if o.absent {
			return fmt.Errorf("assembly capture: compiler source absent")
		}
		key := path
		if !remaining[key] && strings.HasSuffix(p.ID, ".test") && filepath.Base(path) == "_testmain.go" {
			// go list owns a cache copy of generated test-main bytes; the cold
			// action owns its transient copy. Equality is checked, never inferred.
			for candidate := range remaining {
				if bytes.Equal(c.selection.files[candidate].data, o.data) {
					key = candidate
					break
				}
			}
		}
		if !remaining[key] || !bytes.Equal(c.selection.files[key].data, o.data) {
			return fmt.Errorf("assembly capture: compiler inputs disagree with typed owner: %s (%s)", path, p.ID)
		}
		delete(remaining, key)
	}
	for _, key := range []string{"importcfg", "embedcfg", "symabis", "pgoprofile", "coveragecfg"} {
		if value := a.parsed.last(key); value != "" {
			o, err := inputs.read(absolute(a.inv.CWD, value))
			if err != nil {
				return err
			}
			if o.absent {
				return fmt.Errorf("assembly capture: compiler %s input absent", key)
			}
		}
	}
	return nil
}

func (c *captureServer) finish() (*Packet, error) {
	packet := &Packet{selection: c.selection, instance: c.provider.ID, files: map[string][]byte{}}
	roster := map[string]int{}
	compilers := map[string]*capturedAction{}
	outputs := map[string]string{}
	profiles := map[string][]byte{}
	for _, a := range c.actions {
		if err := c.ctx.Err(); err != nil {
			return nil, err
		}
		for path, observation := range a.inputs {
			if err := c.ctx.Err(); err != nil {
				return nil, err
			}
			if observation.absent {
				continue
			}
			if previous, ok := packet.files[path]; ok && !bytes.Equal(previous, observation.data) {
				return nil, fmt.Errorf("assembly capture: inconsistent compiler/provider input bytes: %s", path)
			}
			packet.files[path] = slices.Clone(observation.data)
		}
		switch filepath.Base(a.inv.Tool) {
		case "compile":
			if compilers[a.inv.Instance] != nil {
				return nil, fmt.Errorf("assembly capture: duplicate compiler action for %s", a.inv.Instance)
			}
			compilers[a.inv.Instance] = a
			outputs[a.inv.Output] = a.inv.Instance
		case "preprofile":
			profiles[a.inv.Output] = a.output
		case "asm":
			for _, p := range a.providers {
				roster[p.Source]++
				packet.providers = append(packet.providers, p)
			}
			packet.lookups = append(packet.lookups, a.lookups...)
		}
	}
	if len(roster) != len(c.provider.Assembly) {
		return nil, fmt.Errorf("assembly capture: missing final assembler actions (cache or incomplete roster)")
	}
	for _, path := range c.provider.Assembly {
		if roster[path] != 1 {
			return nil, fmt.Errorf("assembly capture: missing or duplicate final provider action %s", path)
		}
	}
	if compilers[c.provider.ID] == nil {
		return nil, fmt.Errorf("assembly capture: provider compiler action absent")
	}
	for _, a := range compilers {
		p := c.selection.packages[a.inv.Instance]
		if err := checkImports(a, p, outputs, c.selection.packages); err != nil {
			return nil, err
		}
		if profile := a.parsed.last("pgoprofile"); profile != "" {
			path := absolute(a.inv.CWD, profile)
			data, ok := profiles[path]
			if !ok {
				// An explicit compiler profile is already a selected input,
				// whereas a driver-generated preprofile requires its captured
				// derivation from the original selected profile above.
				owned, exists := c.selection.files[path]
				if exists && !owned.absent {
					data, ok = owned.data, true
				}
			}
			if !ok || !bytes.Equal(data, a.inputs[path].data) {
				return nil, fmt.Errorf("assembly capture: compiler profile lacks captured selected-input derivation: %s", a.inv.Instance)
			}
		}
		packet.compilers = append(packet.compilers, cloneInvocation(a.inv))
	}
	slices.SortFunc(packet.providers, func(a, b Provider) int { return strings.Compare(a.Source, b.Source) })
	c.m.mu.Lock()
	packet.usage = Usage{Bytes: c.m.bytes, Tokens: c.m.tokens, Files: c.m.files, Actions: c.m.actions, Watches: c.m.watches, Events: c.m.events}
	packet.usage.InputBytes = maps.Clone(c.m.inputBytes)
	c.m.mu.Unlock()
	return packet, nil
}

func checkImports(a *capturedAction, p Package, outputs map[string]string, selected map[string]Package) error {
	path := a.parsed.last("importcfg")
	if path == "" {
		if len(p.Imports) > 0 {
			return fmt.Errorf("assembly capture: compiler import configuration absent")
		}
		return nil
	}
	data := a.inputs[absolute(a.inv.CWD, path)].data
	imports, remaps := map[string]string{}, map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kind, value, ok := strings.Cut(line, " ")
		if !ok {
			return fmt.Errorf("assembly capture: malformed compiler import configuration")
		}
		key, value, ok := strings.Cut(value, "=")
		if !ok {
			return fmt.Errorf("assembly capture: malformed compiler import entry")
		}
		switch kind {
		case "packagefile":
			if _, dup := imports[key]; dup {
				return fmt.Errorf("assembly capture: duplicate import entry")
			}
			imports[key] = value
		case "importmap":
			if _, dup := remaps[key]; dup {
				return fmt.Errorf("assembly capture: duplicate import mapping")
			}
			remaps[key] = value
		default:
			return fmt.Errorf("assembly capture: unsupported compiler import configuration %s", kind)
		}
	}
	used := map[string]bool{}
	for raw, id := range p.Imports {
		if raw == "unsafe" || raw == "C" {
			continue
		}
		mapped := raw
		if r, ok := remaps[raw]; ok {
			mapped = r
		}
		file, ok := imports[mapped]
		if !ok {
			return fmt.Errorf("assembly capture: selected import missing: %s -> %s", p.ID, raw)
		}
		if outputs[absolute(a.inv.CWD, file)] != id {
			return fmt.Errorf("assembly capture: compiler import instance disagrees: %s -> %s (got %q want %q)", p.ID, raw, outputs[absolute(a.inv.CWD, file)], id)
		}
		used[mapped] = true
	}
	for key := range imports {
		if !used[key] {
			// Compiler-introduced imports need not occur in the source import
			// map. Bind them to a completed action of the complete graph owned
			// before typed loading, at the exact object package namespace. No
			// particular package name or familiar archive location is exempt.
			id := outputs[absolute(a.inv.CWD, imports[key])]
			dependency, ok := selected[id]
			if !ok || dependency.Path != key {
				return fmt.Errorf("assembly capture: unowned compiler import %s in %s", key, p.ID)
			}
			used[key] = true
		}
	}
	for raw, mapped := range remaps {
		if _, ok := p.Imports[raw]; !ok || !used[mapped] {
			return fmt.Errorf("assembly capture: unowned compiler import mapping")
		}
	}
	return nil
}
