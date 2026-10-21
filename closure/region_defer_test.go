package closure

import (
	"context"
	"errors"
	"fmt"
	"go/constant"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	progpkg "github.com/greatliontech/gofresh/closure/internal/program"
	"github.com/greatliontech/gofresh/gotool"
)

var regionDeferCases = []struct{ name, source string }{
	{"named-result", `func F()(r int){defer func(){r+=2}();return 3}`},
	{"scalar-versus-cell", `func F()(r int){x:=1;defer func(v int){r=(r<<3)+(r<<1)+v}(x);defer func(){r=(r<<3)+(r<<1)+x}();x=2;return}`},
	{"pointer-current-heap", `func F()(r int){x:=1;defer func(p *int){r=*p}(&x);x=7;return}`},
	{"callable-reassignment", `func F()(r int){f:=func(){r=1};defer f();f=func(){r=9};f();return}`},
	{"lifo-and-nested", `func F()(r int){defer func(){defer func(){r=(r<<3)+(r<<1)+3}();r=(r<<3)+(r<<1)+1}();defer func(){r=(r<<3)+(r<<1)+2}();return}`},
	{"discard-result", `func F()(r int){defer func()int{r=8;return 9}();return}`},
	{"false-panic", `func F()(r int){defer func(b bool){if b{panic(1)};r=3}(false);return}`},
	{"recover-nil", `func F()(r int){if recover()!=nil{panic(1)};defer func(){if recover()!=nil{panic(2)};defer func(){if recover()!=nil{panic(3)};r++}();r++}();return}`},
	{"argument-evaluation", `func F()(r int){x:=1;value:=func()int{x=4;return x};defer func(v int){r=v+x}(value());x=6;return}`},
	{"receiver", `type deferReceiver struct{n int};func(p *deferReceiver)put(v int){p.n=v};func F()int{p:=&deferReceiver{};func(){defer p.put(4);p=&deferReceiver{8}}();return p.n}`},
	{"interface-receiver", `type deferInterface interface{put(int)};type deferConcrete struct{n int};func(p *deferConcrete)put(v int){p.n=v};func F()int{p:=&deferConcrete{};q:=&deferConcrete{8};func(){var i deferInterface=p;defer i.put(4);i=q}();return p.n+q.n}`},
}

func deferKernel(ctx context.Context, in regionInput, owner *regionOccurrenceOwner, limits regionLimits) (*regionKernel, error) {
	k, err := newRegionContextKernel(in, newRegionCallSession(ctx, in, limits), regionInvocation{}, true)
	if err == nil && owner != nil {
		k.trace = &regionEffectTrace{owner: owner, seen: map[regionEffectOccurrence]bool{}}
	}
	return k, err
}

func proveDefer(ctx context.Context, in regionInput, finite bool, limits regionLimits) (*checkedRegion, *regionProposal, *regionOccurrenceOwner, error) {
	var owner *regionOccurrenceOwner
	if finite {
		owner = &regionOccurrenceOwner{}
	}
	k, err := deferKernel(ctx, in, owner, limits)
	if err != nil {
		return nil, nil, owner, err
	}
	p, err := proposeRegionKernel(k)
	if err != nil {
		return nil, nil, owner, err
	}
	in, p, err = regionCapture(in, p, limits)
	if err != nil {
		return nil, p, owner, err
	}
	k, err = deferKernel(ctx, in, owner, limits)
	if err != nil {
		return nil, p, owner, err
	}
	packet, err := checkRegionKernel(k, p)
	return packet, p, owner, err
}

// Compile and execute the literal fixtures with Go. This oracle shares no SSA
// execution, defer, capture, heap or control implementation with the checker.
func TestRegionDeferGoExecutionOracle(t *testing.T) {
	if testing.Short() {
		t.Skip("compile and execute literal Go oracle")
	}
	var program strings.Builder
	program.WriteString("package main\nimport \"fmt\"\n")
	for i, tc := range regionDeferCases {
		program.WriteString(strings.Replace(tc.source, "func F()", fmt.Sprintf("func case%d()", i), 1) + "\n")
	}
	program.WriteString(`func outer() (r int) {defer func(){if recover()!=nil{r=7}}();defer func(){defer func(){if recover()!=nil{r=99}}()}();panic(1)}`)
	program.WriteString("\nfunc main(){\n")
	for i := range regionDeferCases {
		fmt.Fprintf(&program, "fmt.Println(case%d())\n", i)
	}
	program.WriteString("fmt.Println(outer())\n}\n")
	file := filepath.Join(t.TempDir(), "main.go")
	if err := os.WriteFile(file, []byte(program.String()), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(t.Context(), "go", "run", file).CombinedOutput()
	if err != nil {
		t.Fatalf("Go oracle: %v\n%s", err, output)
	}
	lines := strings.Fields(string(output))
	if len(lines) != len(regionDeferCases)+1 || lines[len(lines)-1] != "7" {
		t.Fatalf("Go oracle outer-panic semantics: %s", output)
	}
	t.Logf("literal Go oracle results: %s", strings.TrimSpace(string(output)))
	for i, tc := range regionDeferCases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := strconv.ParseInt(lines[i], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			for _, finite := range []bool{false, true} {
				in := occurrenceFixture(t, tc.source)
				in.unwind = regionNoActiveUnwind
				packet, _, _, err := proveDefer(t.Context(), in, finite, defaultRegionLimits())
				if err != nil {
					t.Fatalf("finite=%v: %v", finite, err)
				}
				if len(packet.observations) != 1 {
					t.Fatal("missing complete returned state")
				}
				out := packet.observations[0]
				got, exact := regionInt(out.value)
				if !exact || got != want || !out.state.pending.known || len(out.state.pending.captures) != 0 {
					t.Fatalf("finite=%v result=%v want=%d stack=%+v", finite, out.value, want, out.state.pending)
				}
				if packet.input.unwind != in.unwind {
					t.Fatal("entry unwind condition disappeared")
				}
				for _, proof := range packet.calls {
					if proof.unwind != in.unwind || !proof.initial.pending.known || len(proof.initial.pending.captures) != 0 {
						t.Fatal("child borrowed parent stack or lost scope")
					}
					if _, deferred := proof.at.(*ssa.Defer); deferred && (proof.drain == nil || proof.registration.instruction != proof.at) {
						t.Fatal("deferred invocation has no actual registration/drain")
					}
				}
				if finite && regionNativeControl(packet) == nil {
					t.Fatal("source-only control gained native authority")
				}
			}
		})
	}
}

// The selected 386 runtime rejects the payload extent before calling its
// allocator. Never execute this source with the host's possibly 64-bit layout.
// This is an independent counterexample, not an approved-runtime summary.
func TestRegionDeferChannelAllocationGo386Oracle(t *testing.T) {
	if testing.Short() {
		t.Skip("compile and execute selected 386 Go oracle")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires Linux x86 execution of a 386 binary")
	}
	const child = `func child()int{n:=1<<30;c:=make(chan [1024]byte,n);return cap(c)}`
	const direct = `func F()(r int){defer func(){if recover()!=nil{r=-1}}();n:=1<<30;c:=make(chan [1024]byte,n);return cap(c)}`
	const caller = `func G()(r int){defer func(){if recover()!=nil{r=-1}}();return child()}`
	file := filepath.Join(t.TempDir(), "main.go")
	program := "package main\nimport(\"fmt\";\"runtime\")\n" + child + "\n" + direct + "\n" + caller + "\nfunc main(){fmt.Println(runtime.Version(),runtime.GOARCH,F(),G())}\n"
	if err := os.WriteFile(file, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), filepath.Join(runtime.GOROOT(), "bin", "go"), "run", file)
	cmd.Env = os.Environ()
	for key, value := range map[string]string{"GOARCH": "386", "GOOS": "linux", "CGO_ENABLED": "0", "GOROOT": runtime.GOROOT(), "GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "GOFLAGS": ""} {
		cmd.Env = gotool.SetEnv(cmd.Env, key, value)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("selected 386 Go oracle: %v\n%s", err, output)
	}
	if got, want := strings.TrimSpace(string(output)), runtime.Version()+" 386 -1 -1"; got != want {
		t.Fatalf("actual allocation unwind = %q; want %q", got, want)
	}
	t.Logf("actual selected Go oracle: %s", strings.TrimSpace(string(output)))
	source := relationFixture(t, child+";"+direct+";"+caller, 32)
	checkActivationChannelCover(t, source, "F", 1<<30, false)
	checkActivationChannelCover(t, source, "G", 1<<30, true)
	input := func(name string) regionInput {
		root := source.prog.Roots["F"].Pkg.Func(name)
		return regionInput{owner: root.Prog, selection: source.prog, root: root, entry: regionPoint{root.Blocks[0], 0}, unwind: regionNoActiveUnwind,
			premises: []string{"conditional ordinary entry; selected 32-bit typed source; no allocation-success assertion"}}
	}
	// The child has no defer: its conditional postcondition remains correct even
	// though this selected execution never returns normally from that child.
	normal := input("child")
	normal.normalReturns = true
	post, _, _, err := proveDefer(t.Context(), normal, false, defaultRegionLimits())
	if err != nil || post == nil || !post.input.normalReturns || len(post.observations) != 1 {
		t.Fatalf("normal-return child postcondition: %v", err)
	}
	localEffectInteger(t, post.observations[0].value, 1<<30)
	for _, name := range []string{"F", "G", "child"} {
		for _, finite := range []bool{false, true} {
			packet, _, _, err := proveDefer(t.Context(), input(name), finite, defaultRegionLimits())
			if packet != nil || err == nil || !strings.Contains(err.Error(), "channel allocation outcomes") {
				t.Errorf("%s finite=%v strict allocation proof=%v, error=%v; actual recovering caller returns -1", name, finite, packet != nil, err)
			}
		}
	}
}

func TestRegionChannelStrictAllocationBoundary(t *testing.T) {
	for _, capacity := range []int{0, 1, 1 << 30} {
		for _, finite := range []bool{false, true} {
			in := occurrenceFixture(t, fmt.Sprintf(`func F()int{n:=%d;c:=make(chan [1024]byte,n);return cap(c)}`, capacity))
			packet, _, _, err := proveDefer(t.Context(), in, finite, defaultRegionLimits())
			if packet != nil || err == nil || !strings.Contains(err.Error(), "channel allocation outcomes") {
				t.Fatalf("capacity=%d finite=%v unsupported allocation admitted: %v", capacity, finite, err)
			}
		}
	}
	for _, text := range []string{
		`func F()int{var c chan int;return cap(c)+len(c)}`,
		`func F()int{n:=1<<30;if n==0{c:=make(chan [1024]byte,n);return cap(c)};var c chan int;return cap(c)}`,
	} {
		for _, finite := range []bool{false, true} {
			packet, _, _, err := proveDefer(t.Context(), occurrenceFixture(t, text), finite, defaultRegionLimits())
			if err != nil {
				t.Fatal(err)
			}
			if len(packet.observations) != 1 {
				t.Fatal("missing allocation-free return")
			}
			localEffectInteger(t, packet.observations[0].value, 0)
			if finite && len(packet.trace.allocations) != 0 {
				t.Fatal("unreachable construction emitted an allocation")
			}
		}
	}
}

func TestRegionDeferStrictRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		scope      regionUnwindScope
	}{
		{"body-panic", `func F(){defer func(){recover()}();panic(1)}`, regionNoActiveUnwind},
		{"deferred-panic", `func F(){defer func(){recover()}();defer func(){panic(1)}()}`, regionNoActiveUnwind},
		{"argument-panic", `func F(){defer func(){recover()}();f:=func()int{panic(1)};defer func(int){}(f())}`, regionNoActiveUnwind},
		{"nil-target", `func F(){var f func();defer f()}`, regionNoActiveUnwind},
		{"unknown-target", `var unknown func();func F(){defer unknown()}`, regionNoActiveUnwind},
		{"unknown-call", `var unknown func();func F(){defer func(){unknown()}()}`, regionNoActiveUnwind},
		{"opaque-leaf", `func native();func F(){defer native()}`, regionNoActiveUnwind},
		{"Goexit-name", `func Goexit();func F(){defer Goexit()}`, regionNoActiveUnwind},
		{"nil-dereference", `func F(){defer func(p *int){*p=1}(nil)}`, regionNoActiveUnwind},
		{"uncertain-bounds", `var i int;func F(){defer func(){a:=[1]int{};_ = a[i]}()}`, regionNoActiveUnwind},
		{"uncertain-division", `var d int;func F(){defer func(){_ = 1/d}()}`, regionNoActiveUnwind},
		{"possible-panic", `var b bool;func F(){defer func(){if b{panic(1)}}()}`, regionNoActiveUnwind},
		{"unknown-unwind", `func F(){defer func(){recover()}()}`, regionUnknownUnwind},
		{"unknown-root-recover", `func F(){recover()}`, regionUnknownUnwind},
		{"recursion", `func F(){defer F()}`, regionNoActiveUnwind},
		{"recurrent-registration", `func F(){for i:=0;i<2;i++{defer func(){}()}}`, regionNoActiveUnwind},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, finite := range []bool{false, true} {
				in := occurrenceFixture(t, tc.text)
				in.unwind = tc.scope
				if packet, _, _, err := proveDefer(t.Context(), in, finite, defaultRegionLimits()); err == nil || packet != nil {
					t.Fatalf("finite=%v unsupported control accepted", finite)
				}
			}
		})
	}
	for _, text := range []string{`func F(){defer func(){}()}`, `func F(){go func(){}()}`} {
		in := occurrenceFixture(t, text)
		in.normalReturns = true
		if _, _, _, err := proveDefer(t.Context(), in, false, defaultRegionLimits()); err == nil || !strings.Contains(err.Error(), "normal-return scope") {
			t.Fatalf("legacy exclusion changed: %v", err)
		}
	}
}

func TestRegionDeferRetainsAllStrictSuccessors(t *testing.T) {
	in := occurrenceFixture(t, `var b bool;func F()(r int){defer func(){r=(r<<3)+(r<<1)}();defer func(){if b{r=3}else{r=4}}();return}`)
	packet, _, _, err := proveDefer(t.Context(), in, false, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	var got []int64
	for _, out := range packet.observations {
		n, exact := regionInt(out.value)
		if !exact {
			t.Fatal("lost branch relation")
		}
		got = append(got, n)
	}
	slices.Sort(got)
	if !slices.Equal(got, []int64{30, 40}) {
		t.Fatalf("drain discarded checked successor: %v", got)
	}
}

func TestRegionDeferContinuation(t *testing.T) {
	source := relationFixture(t, `var result int;func Stop(){};func F(){result=1;defer func(){if recover()!=nil{panic(1)};result=(result<<3)+(result<<1)+2}();Stop();result=3;Stop()}`, 64)
	root := source.prog.Roots["F"]
	calls := localEffectCalls(t, root, "Stop")
	first, err := checkSourceOperandPrefix(t.Context(), source, root, calls[0], defaultRegistrationLimits(), regionNoActiveUnwind)
	if err != nil {
		t.Fatal(err)
	}
	second, err := checkSourceOperandContinuation(t.Context(), first, calls[1], nil)
	if err != nil {
		t.Fatal(err)
	}
	var returned *ssa.Return
	for _, ins := range calls[1].Block().Instrs {
		if r, ok := ins.(*ssa.Return); ok {
			returned = r
		}
	}
	complete, err := checkSourceReturnContinuation(t.Context(), second, returned, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []*sourceOperandPrefix{first, second} {
		p := prefix.checkedPacket()
		if p == nil || len(p.observations[0].state.pending.captures) != 1 || p.input.unwind != regionNoActiveUnwind {
			t.Fatal("continuation lost pending capture or original condition")
		}
	}
	packet := complete.checkedPacket()
	if packet == nil || packet.input.unwind != regionNoActiveUnwind {
		t.Fatal("completion lost original condition")
	}
	global := root.Pkg.Members["result"].(*ssa.Global)
	got, exact := regionInt(packet.observations[0].state.memory[regionObject{kind: regionGlobal, site: global}])
	if !exact || got != 32 {
		t.Fatalf("pending capture lost, replayed, or used stale heap: %d", got)
	}
	deferred := 0
	for _, proof := range packet.calls {
		if _, ok := proof.at.(*ssa.Defer); ok {
			deferred++
		}
	}
	if deferred != 1 {
		t.Fatalf("deferred applications=%d", deferred)
	}
	if regionNativeControl(packet) == nil {
		t.Fatal("native consumer accepted source control")
	}
	old := packet.input.unwind
	packet.input.unwind = regionUnknownUnwind
	if complete.checkedPacket() != nil {
		t.Fatal("forged erased unwind scope retained continuation authority")
	}
	packet.input.unwind = old
}

func TestRegionDeferForgedEvidence(t *testing.T) {
	for _, finite := range []bool{false, true} {
		for _, corruption := range []string{"omit-call", "argument", "current-heap", "registration", "drain", "unwind", "empty-stack", "reorder", "captured-argument", "owner"} {
			t.Run(fmt.Sprintf("%v/%s", finite, corruption), func(t *testing.T) {
				in := occurrenceFixture(t, `var flag bool;func F()(r int){defer func(v int){r=(r<<3)+(r<<1)+v}(1);defer func(v int){r=(r<<3)+(r<<1)+v}(2);if r==0{r=3};return}`)
				in.unwind = regionNoActiveUnwind
				_, p, owner, err := proveDefer(t.Context(), in, finite, defaultRegionLimits())
				if err != nil {
					t.Fatal(err)
				}
				proof := p.calls[0]
				switch corruption {
				case "omit-call":
					p.calls = p.calls[1:]
				case "argument":
					proof.arguments[0] = regionValue{typ: types.Typ[types.Int], kind: regionConstant, scalar: constant.MakeInt64(99)}
				case "current-heap":
					clear(proof.initial.memory)
				case "registration":
					proof.registration.ordinal++
				case "drain":
					proof.drain = nil
				case "unwind":
					proof.unwind = regionUnknownUnwind
				case "owner":
					p.input.owner = computationFixture(t, `func F(){}`).prog.Prog
				default:
					changed := false
					edit := func(s *regionState) {
						if changed || len(s.pending.captures) != 2 {
							return
						}
						s.pending.captures = slices.Clone(s.pending.captures)
						switch corruption {
						case "empty-stack":
							s.pending = regionDeferStack{known: true}
						case "reorder":
							slices.Reverse(s.pending.captures)
						case "captured-argument":
							s.pending.captures[0].arguments = slices.Clone(s.pending.captures[0].arguments)
							s.pending.captures[0].arguments[0] = regionValue{typ: types.Typ[types.Int], kind: regionConstant, scalar: constant.MakeInt64(99)}
						}
						changed = true
					}
					if finite {
						for i := range p.occurrences.nodes {
							edit(&p.occurrences.nodes[i].entry)
						}
					} else {
						for b, states := range p.entries {
							for i := range states {
								edit(&states[i])
							}
							p.entries[b] = states
						}
					}
					if !changed {
						t.Fatal("fixture has no pending-stack invariant")
					}
				}
				in, p, err = regionCapture(in, p, defaultRegionLimits())
				if err != nil {
					return
				}
				k, err := deferKernel(t.Context(), in, owner, defaultRegionLimits())
				if err != nil {
					t.Fatal(err)
				}
				if packet, err := checkRegionKernel(k, p); err == nil || packet != nil {
					t.Fatal("forged defer evidence accepted")
				}
			})
		}
	}
}

func TestRegionDeferEntryAndBounds(t *testing.T) {
	in := occurrenceFixture(t, `func F(){defer func(){}()}`)
	var drain *ssa.RunDefers
	for _, ins := range in.root.Blocks[0].Instrs {
		if x, ok := ins.(*ssa.RunDefers); ok {
			drain = x
		}
	}
	if drain == nil {
		t.Fatal("no drain")
	}
	in.entry = regionPoint{drain.Block(), slices.Index(drain.Block().Instrs, ssa.Instruction(drain))}
	for _, known := range []bool{false, true} {
		in.initial.pending = regionDeferStack{known: known}
		if packet, _, _, err := proveDefer(t.Context(), in, false, defaultRegionLimits()); err == nil || packet != nil {
			t.Fatal("mid-body absence forged an empty stack")
		}
	}
	// An explicit retained conditional control antecedent is not prefix proof.
	in.pendingAntecedent = true
	packet, _, _, err := proveDefer(t.Context(), in, false, defaultRegionLimits())
	if err != nil || !packet.input.pendingAntecedent {
		t.Fatalf("conditional empty-stack antecedent: %v", err)
	}
	in = occurrenceFixture(t, regionDeferCases[4].source)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, _, err := proveDefer(ctx, in, true, defaultRegionLimits()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	counted := &regionCallCountingContext{Context: t.Context()}
	if _, _, _, err := proveDefer(counted, in, true, defaultRegionLimits()); err != nil {
		t.Fatal(err)
	}
	interrupted := &regionCallCountingContext{Context: t.Context(), stop: counted.checks / 2}
	if packet, _, _, err := proveDefer(interrupted, in, true, defaultRegionLimits()); packet != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted nested defer check: %v", err)
	}
	for _, dimension := range []string{"work", "nodes", "depth", "states", "locations"} {
		limits := defaultRegionLimits()
		switch dimension {
		case "work":
			limits.work = 8
		case "nodes":
			limits.nodes = 2
		case "depth":
			limits.depth = 1
		case "states":
			limits.states = 2
		case "locations":
			limits.locations = 2
		}
		if packet, _, _, err := proveDefer(t.Context(), in, true, limits); err == nil || packet != nil {
			t.Fatalf("%s bound supplied partial proof", dimension)
		}
	}
}

func TestRegionDeferRegistrationDoesNotExecute(t *testing.T) {
	for _, text := range []string{
		`func Stop(){};func F(){var f func();defer f();Stop()}`,
		`var f func();func Stop(){};func F(){defer f();Stop()}`,
		`func Stop(){};func F(){defer func(){panic(1)}();Stop()}`,
	} {
		source, prefix := localEffectPrefix(t, text)
		packet := prefix.checkedPacket()
		if packet == nil || len(packet.calls) != 0 || len(packet.observations[0].state.pending.captures) != 1 {
			t.Fatal("registration executed or dropped captured invocation")
		}
		var returned *ssa.Return
		for _, ins := range prefix.call.Block().Instrs {
			if x, ok := ins.(*ssa.Return); ok {
				returned = x
			}
		}
		if returned == nil || returned.Parent() != source.prog.Roots["F"] {
			t.Fatal("missing normal return")
		}
		if complete, err := checkSourceReturnContinuation(t.Context(), prefix, returned, nil); err == nil || complete != nil {
			t.Fatal("drain ignored unsupported captured invocation")
		}
	}
}

// Range-over-function lowering registers this defer on the enclosing frame,
// not the yield callback's frame. Starting at the actual defer deliberately
// omits the earlier ssa:deferstack operation: its refusal cannot protect a cut.
func TestRegionDeferAlternateStackRefuses(t *testing.T) {
	source := relationFixture(t, `func Stop(){};func iter(yield func()bool){yield()};func F(){for range iter {defer func(){}();Stop()}}`, 64)
	var site *ssa.Defer
	var find func(*ssa.Function)
	find = func(fn *ssa.Function) {
		for _, block := range fn.Blocks {
			for _, instruction := range block.Instrs {
				if d, ok := instruction.(*ssa.Defer); ok && d.DeferStack != nil {
					if site != nil {
						t.Fatal("ambiguous alternate-stack fixture")
					}
					site = d
				}
			}
		}
		for _, child := range fn.AnonFuncs {
			find(child)
		}
	}
	find(source.prog.Roots["F"])
	if site == nil || site.Parent() == source.prog.Roots["F"] {
		t.Fatal("fixture lacks actual alternate-stack callback defer")
	}
	root := site.Parent()
	stop := localEffectCalls(t, root, "Stop")[0]
	if stop.Block() != site.Block() {
		t.Fatal("fixture cut is not in the registration block")
	}
	entry := regionPoint{site.Block(), slices.Index(site.Block().Instrs, ssa.Instruction(site))}
	use := regionUse{at: regionPoint{stop.Block(), slices.Index(stop.Block().Instrs, ssa.Instruction(stop))}, operand: stop.Call.Value}
	if entry.index >= use.at.index {
		t.Fatal("fixture cut does not follow registration")
	}
	t.Logf("frontend %s: actual %s in %s; cut before %s", runtime.Version(), site, root, stop)
	in := regionInput{owner: root.Prog, selection: source.prog, root: root, entry: entry, use: use,
		initial: regionState{pending: regionDeferStack{known: true}}, pendingAntecedent: true,
		premises: []string{"conditional mid-body entry with an empty LOCAL pending stack; alternate target and omitted prefix are unproved"}}
	refused := func(t *testing.T, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "alternate defer stack") {
			t.Errorf("wanted alternate-stack refusal, got %v", err)
		}
	}
	t.Run("registration", func(t *testing.T) {
		p, err := proposeRegion(t.Context(), in, defaultRegionLimits())
		if p != nil {
			t.Error("proposer retargeted alternate-stack defer to local stack")
		}
		refused(t, err)
		// Supply the exact entry invariant independently of the proposer so the
		// checker's registration transfer must enforce the same boundary itself.
		candidate := &regionProposal{input: in, entries: map[*ssa.BasicBlock][]regionState{entry.block: {in.initial}}}
		packet, err := checkRegion(t.Context(), in, candidate, defaultRegionLimits())
		if packet != nil {
			t.Errorf("checker admitted local pending=%d for alternate-stack defer", len(packet.observations[0].state.pending.captures))
		}
		refused(t, err)
	})
	t.Run("retained-capture", func(t *testing.T) {
		// Begin after registration: this path executes no Defer instruction.
		// The retained capture must itself refuse the unsupported target stack.
		incoming := in
		incoming.entry = use.at
		k, err := newRegionKernel(t.Context(), incoming, defaultRegionLimits())
		if err != nil {
			t.Fatal(err)
		}
		callable, args, err := k.callOperands(site, incoming.initial)
		if err != nil {
			t.Fatal(err)
		}
		incoming.initial.pending.captures = []regionDeferredCall{{site: site,
			registration: regionEffectOccurrence{instruction: site}, callable: callable, arguments: args}}
		refused(t, k.validateDefers(incoming.initial.pending))
		candidate := &regionProposal{input: incoming, entries: map[*ssa.BasicBlock][]regionState{incoming.entry.block: {incoming.initial}}}
		packet, err := checkRegion(t.Context(), incoming, candidate, defaultRegionLimits())
		if packet != nil {
			t.Error("conditional input forged a retained alternate-stack capture as local work")
		}
		refused(t, err)
	})
	t.Run("operand-bound", func(t *testing.T) {
		count := len(site.Operands(nil))
		if count < 2 || !regionBoundedOperands(site, count) || regionBoundedOperands(site, count-1) {
			t.Fatalf("defer operand cap omitted actual target-stack operand: actual=%d", count)
		}
	})
}

func TestRegionDeferSelectedInitialization(t *testing.T) {
	in, main, use := startupFixture(t, map[string][]string{"main": {`package main;var X int;func init(){defer func(){X=2}();X=1};func consume(int){};func main(){consume(X)}`}})
	entry, err := prepareSourceEntry(t.Context(), in, main, use, registrationLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if got := startupScalar(t, entry).ExactString(); got != "2" {
		t.Fatalf("selected initialization ignored deferred effects: %s", got)
	}
}

func TestRegionDeferRuntimeGoexitRefuses(t *testing.T) {
	if testing.Short() {
		t.Skip("actual selected runtime source load")
	}
	dir := t.TempDir()
	const path = "example.com/defergoexit"
	for name, text := range map[string]string{"go.mod": "module " + path + "\n\ngo 1.27.0\n", "p.go": `package p;import "runtime";func F(){defer runtime.Goexit()}`} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := progpkg.Load(t.Context(), dir, append(os.Environ(), "GOWORK=off", "GOPACKAGESDRIVER=off"), nil, path)
	if err != nil {
		t.Fatal(err)
	}
	root := loaded.Roots["F"]
	in := regionInput{owner: loaded.Prog, root: root, entry: regionPoint{root.Blocks[0], 0}, unwind: regionNoActiveUnwind, premises: []string{"actual selected runtime source; conditional ordinary entry; native applicability open"}}
	packet, _, _, err := proveDefer(t.Context(), in, false, defaultRegionLimits())
	if packet != nil || err == nil {
		t.Fatal("runtime.Goexit gained implicit primitive authority")
	}
	t.Logf("actual selected runtime.Goexit refusal: %v", err)
	abrupt := regionActivationInput{owner: root.Prog, root: root, unwind: regionNoActiveUnwind, premises: slices.Clone(in.premises)}
	if p, err := proposeRegionActivation(t.Context(), abrupt, defaultRegionLimits()); err == nil || p != nil {
		t.Fatal("activation outcome arm granted runtime.Goexit a named theorem")
	}
}

func TestRegionDeferWideningAndCaptureOwnership(t *testing.T) {
	in := occurrenceFixture(t, `var b bool;func F()(r int){if b{defer func(){r=1}()}else{defer func(){r=2}()};return}`)
	limits := defaultRegionLimits()
	limits.alternatives = 1
	if packet, _, _, err := proveDefer(t.Context(), in, false, limits); err == nil || packet != nil || !strings.Contains(err.Error(), "deferred control") {
		t.Fatalf("incompatible stacks widened: %v", err)
	}
	in = occurrenceFixture(t, `func F()(r int){defer func(v int){r=v}(7);if r==0{r=1};return}`)
	_, p, _, err := proveDefer(t.Context(), in, false, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	// The public checker captures the proposal before invoking caller context.
	in.use = p.input.use
	ctx := &regionMutatingContext{Context: t.Context(), mutate: func() {
		for _, states := range p.entries {
			for _, s := range states {
				for i := range s.pending.captures {
					s.pending.captures[i].arguments[0] = regionValue{typ: types.Typ[types.Int], kind: regionConstant, scalar: constant.MakeInt64(99)}
				}
			}
		}
	}}
	ownedIn, ownedP, err := regionCapture(in, p, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	k, err := deferKernel(ctx, ownedIn, nil, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	packet, err := checkRegionKernel(k, ownedP)
	if err != nil {
		t.Fatal(err)
	}
	n, ok := regionInt(packet.observations[0].value)
	if !ok || n != 7 {
		t.Fatal("captured arguments borrowed proposer slices")
	}
}

// Extend the adjacent call/capture grammar with actual Go deferred execution as
// the independent oracle. Inputs vary value captures, cell mutation and nested
// activation order; the generator is bounded and does not claim exhaustive proof.
func FuzzRegionDeferCaptureOracle(f *testing.F) {
	f.Add(int8(1), int8(2), true)
	f.Add(int8(-7), int8(11), false)
	f.Fuzz(func(t *testing.T, a, b int8, nested bool) {
		oracle := func() (r int) {
			x := int(a)
			defer func(v int) { r = (r << 3) + v }(x)
			defer func() {
				if nested {
					defer func() { r += 3 }()
				}
				r = x
			}()
			x = int(b)
			return
		}
		text := fmt.Sprintf(`func F()(r int){x:=%d;defer func(v int){r=(r<<3)+v}(x);defer func(){if %t{defer func(){r+=3}()};r=x}();x=%d;return}`, a, nested, b)
		in := occurrenceFixture(t, text)
		packet, _, _, err := proveDefer(t.Context(), in, true, defaultRegionLimits())
		if err != nil {
			t.Fatal(err)
		}
		got, exact := regionInt(packet.observations[0].value)
		if want := oracle(); !exact || got != int64(want) {
			t.Fatalf("got %d/%v, actual Go %d", got, exact, want)
		}
		// The same capture grammar now also crosses an abrupt body exit. The
		// directly dispatched defer recovers before updating the shared cell;
		// its own normally drained defer cannot recover the parent again.
		abruptOracle := func() (r int) {
			x := int(a)
			defer func(v int) { r = (r << 3) + v }(x)
			defer func() {
				if nested {
					defer func() {
						if recover() != nil {
							r = 999
						}
						r += 3
					}()
				}
				recover()
				r = x
			}()
			x = int(b)
			panic(1)
		}
		abrupt := fmt.Sprintf(`func F()(r int){x:=%d;defer func(v int){r=(r<<3)+v}(x);defer func(){if %t{defer func(){if recover()!=nil{r=999};r+=3}()};recover();r=x}();x=%d;panic(1)}`, a, nested, b)
		completed, _ := proveActivation(t, abrupt)
		// Vary the suspension boundary as well as the source capture grammar.
		// The literal Go closure remains the independent semantic oracle.
		cut := uint64(uint8(a)^uint8(b))%(completed.snapshot.transitions-1) + 1
		_, continued := activationPartition(t, completed.input, cut)
		equalActivations(t, completed, continued)
		completed = continued
		if len(completed.outcomes) != 1 || completed.outcomes[0].kind != activationNormal {
			t.Fatal("abrupt capture grammar lost normal recovery")
		}
		got, exact = regionInt(completed.outcomes[0].value)
		if want := abruptOracle(); !exact || got != int64(want) {
			t.Fatalf("abrupt got %d/%v, actual Go %d", got, exact, want)
		}
		// Repeated registrations at one actual SSA site capture distinct values,
		// while each dispatch reads the current cell, not an old heap snapshot.
		n := int(uint8(a)%3) + 1
		loopOracle := func() (r int) {
			x := int(a)
			for i := 0; i < n; i++ {
				defer func(v int) { r = r*10 + v + x }(i)
			}
			x = int(b)
			return
		}
		loop := fmt.Sprintf(`func F()(r int){x:=%d;for i:=0;i<%d;i++{defer func(v int){r=r*10+v+x}(i)};x=%d;return}`, a, n, b)
		finite, _ := proveActivation(t, loop)
		_, resumed := activationPartition(t, finite.input, uint64(uint8(b))%(finite.snapshot.transitions-1)+1)
		equalActivations(t, finite, resumed)
		got, exact = regionInt(resumed.outcomes[0].value)
		if want := loopOracle(); !exact || got != int64(want) {
			t.Fatalf("finite captures got %d/%v, actual Go %d", got, exact, want)
		}
	})
}
