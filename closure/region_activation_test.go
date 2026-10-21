package closure

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/constant"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

var regionActivationCases = []struct{ name, source string }{
	{"recovered", `func F()(r int){defer func(){if recover()!=nil{r=7}}();panic(1)}`},
	{"escaping", `func F()int{panic(1)}`},
	{"nested-escaping", `func F()int{defer func(){panic(2)}();panic(1)}`},
	{"named-lifo", `func F()(r int){defer func(){r+=10}();defer func(){if recover()!=nil{r+=2}}();r=3;panic(1)}`},
	{"before-return-stores", `func F()(r int){defer func(){if recover()!=nil{r+=2}}();r=3;return func()int{panic(1)}()}`},
	{"after-return-stores", `func F()(r int){defer func(){if recover()!=nil{r++}}();defer func(){panic(1)}();return 7}`},
	{"unnamed-return-stores", `func F()int{defer func(){recover()}();defer func(){panic(1)}();return 7}`},
	{"argument-before-registration", `func F()(r int){r=1;defer func(){if recover()!=nil{r+=10}}();defer func(int){r=99}(func()int{panic(2)}());return}`},
	{"ordinary-helper", `func F()(r int){h:=func()any{return recover()};defer func(){if recover()!=nil{r+=7}}();defer func(){if h()!=nil{r=99}else{r=1}}();panic(1)}`},
	{"nested-normal-defer", `func F()(r int){defer func(){if recover()!=nil{r+=7}}();defer func(){defer func(){if recover()!=nil{r=99}else{r=1}}()}();panic(1)}`},
	{"recover-once", `func F()(r int){defer func(){if recover()!=nil{r=3};if recover()!=nil{r=99}}();panic(1)}`},
	{"nested-restores-parent", `func F()(r int){defer func(){if recover()!=nil{r+=100}}();defer func(){defer func(){if recover()!=nil{r+=10}}();panic(2)}();panic(1)}`},
	{"nested-abandons-parent", `func F()(r int){defer func(){if recover()!=nil{r=99}else{r++}}();defer func(){if recover()!=nil{r=7}}();defer func(){panic(2)}();panic(1)}`},
	{"recover-then-panic", `func F()(r int){defer func(){if recover()!=nil{r=99}}();defer func(){recover();defer func(){recover();r=7}();panic(2)}();panic(1)}`},
	{"child-recovers-resumes", `func F()int{child:=func()(r int){defer func(){if recover()!=nil{r=3}}();panic(1)};return child()+4}`},
	{"caller-recovers-no-resume", `func F()(r int){defer func(){if recover()!=nil{r+=7}}();child:=func(){r=3;panic(1)};child();r=99;return}`},
	{"typed-nil-payload", `func F()(r int){defer func(){if recover()!=nil{r=7}}();var p *int;panic(p)}`},
	{"heap-survives-child", `func F()(r int){x:=1;defer func(){if recover()!=nil{r=x}}();child:=func(p *int){*p=8;panic(1)};child(&x);return}`},
	{"helper-nested-panic-restores-eligibility", `func F()(r int){defer func(){h:=func(){defer func(){recover()}();panic(2)};h();if recover()!=nil{r=7}}();panic(1)}`},
}

func activationInput(source computationSource, name string) regionActivationInput {
	root := source.prog.Roots["F"].Pkg.Func(name)
	return regionActivationInput{owner: root.Prog, selection: source.prog, root: root, unwind: regionNoActiveUnwind,
		premises: []string{"conditional fresh ordinary activation; faithful implicit language lowering; interference and native applicability separate"}}
}

func proveActivation(t testing.TB, text string) (*checkedRegionActivation, *regionActivationProposal) {
	t.Helper()
	source := relationFixture(t, text, 64)
	in := activationInput(source, "F")
	proposal, err := proposeRegionActivation(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	packet, err := checkRegionActivation(t.Context(), in, proposal, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	return packet, proposal
}

// Literal compiled Go supplies the oracle; no region transfer, heap or control
// implementation participates in its execution. Escaping panics are observed by
// a separate outer activation, not silently treated as normally returned zero.
func TestRegionActivationGoOracle(t *testing.T) {
	if testing.Short() {
		t.Skip("compile and execute literal Go activation oracle")
	}
	var text strings.Builder
	text.WriteString("package main\nimport \"fmt\"\n")
	for i, tc := range regionActivationCases {
		text.WriteString(strings.Replace(tc.source, "func F()", fmt.Sprintf("func case%d()", i), 1) + "\n")
	}
	text.WriteString(`func observe(f func()int)(r int,p bool,payload int){defer func(){if v:=recover();v!=nil{p=true;payload=v.(int)}}();r=f();return}`)
	text.WriteString("\nfunc main(){\n")
	for i := range regionActivationCases {
		fmt.Fprintf(&text, "fmt.Println(observe(case%d))\n", i)
	}
	text.WriteString("}\n")
	file := filepath.Join(t.TempDir(), "main.go")
	if err := os.WriteFile(file, []byte(text.String()), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(t.Context(), "go", "run", file).CombinedOutput()
	if err != nil {
		t.Fatalf("Go oracle: %v\n%s", err, output)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != len(regionActivationCases) {
		t.Fatalf("oracle results: %s", output)
	}
	for i, tc := range regionActivationCases {
		t.Run(tc.name, func(t *testing.T) {
			fields := strings.Fields(lines[i])
			if len(fields) != 3 {
				t.Fatal(lines[i])
			}
			want, err := strconv.ParseInt(fields[0], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			panics, err := strconv.ParseBool(fields[1])
			if err != nil {
				t.Fatal(err)
			}
			packet, _ := proveActivation(t, tc.source)
			// The same independently compiled result must hold after a suspended
			// invocation, not only when the complete machine runs in one pass.
			_, partitioned := activationPartition(t, packet.input, packet.snapshot.transitions/2)
			equalActivations(t, packet, partitioned)
			packet = partitioned
			if len(packet.outcomes) != 1 {
				t.Fatalf("unexpected terminal alternatives: %+v", packet.outcomes)
			}
			out := packet.outcomes[0]
			if panics {
				if out.kind != activationPanicking || out.panic == nil || out.panic.payload.kind != regionInterface {
					t.Fatal("escaping panic lost its payload or became a return")
				}
				wantPayload, err := strconv.ParseInt(fields[2], 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				gotPayload, exact := regionInt(out.panic.payload.elements[0])
				if !exact || gotPayload != wantPayload {
					t.Fatalf("escaped payload=%v; Go=%d", out.panic.payload, wantPayload)
				}
				if _, err := packet.projectNormal(t.Context(), regionUnknownValue(types.Typ[types.Int])); err == nil {
					t.Fatal("vacuous normal projection")
				}
			} else {
				got, exact := regionInt(out.value)
				if out.kind != activationNormal || !exact || got != want || !out.state.store.pending.known || len(out.state.store.pending.captures) != 0 {
					t.Fatalf("result kind=%v value=%+v, Go=%d", out.kind, out.value, want)
				}
				if _, err := packet.projectNormal(t.Context(), out.value); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestRegionActivationCompleteAlternatives(t *testing.T) {
	packet, proposal := proveActivation(t, `var B bool;func F()int{if B{return 3};panic(1)}`)
	if len(packet.outcomes) != 2 || packet.outcomes[0].kind != activationNormal || packet.outcomes[1].kind != activationPanicking {
		t.Fatal("branch alternatives were truncated")
	}
	if _, err := packet.projectNormal(t.Context(), regionValue{typ: types.Typ[types.Int], kind: regionConstant, scalar: constant.MakeInt64(3)}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"unknown-call", "Goexit", "loop"} {
		text := map[string]string{
			"unknown-call": `var B bool;var f func();func F()int{if B{return 3};f();return 4}`,
			"Goexit":       `var B bool;func Goexit();func F()int{if B{return 3};Goexit();return 4}`,
			"loop":         `var B bool;func F()int{if B{return 3};for{} }`,
		}[bad]
		source := relationFixture(t, text, 64)
		if p, err := proposeRegionActivation(t.Context(), activationInput(source, "F"), defaultRegionLimits()); err == nil || p != nil {
			t.Fatalf("desired normal terminal hid %s", bad)
		}
	}
	// Keep only the desired return's prefix: the checker must still request the
	// second actual branch even though a normal projection could use the first.
	for i, event := range proposal.events {
		if event.rule == activationReturn {
			proposal.events = proposal.events[:i+1]
			break
		}
	}
	if p, err := checkRegionActivation(t.Context(), packet.input, proposal, defaultRegionLimits()); err == nil || p != nil {
		t.Fatal("truncated complete coverage admitted")
	}
}

// Used also by the independently executed 386 regression: exact recovered
// stores, real child/drain applications and the normal construction alternative
// are required. Unknown top containing -1 does not satisfy this qualification.
func checkActivationChannelCover(t testing.TB, source computationSource, name string, capacity int64, child bool) {
	t.Helper()
	in := activationInput(source, name)
	p, err := proposeRegionActivation(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	packet, err := checkRegionActivation(t.Context(), in, p, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	normal, recovered, stopped, drains, recoveryEntries, childCalls := false, false, false, 0, 0, 0
	for _, out := range packet.outcomes {
		if out.kind == activationStopped {
			stopped = true
			if out.state.store.memory != nil || out.value.typ != nil {
				t.Fatal("noncompletion acquired a returned-state theorem")
			}
		}
		if out.kind == activationNormal {
			n, exact := regionInt(out.value)
			normal = normal || exact && n == capacity
			recovered = recovered || exact && n == -1
		}
	}
	for _, event := range packet.events {
		if event.rule == activationRecoveryEntry {
			recoveryEntries++
		}
	}
	for _, call := range packet.calls {
		if _, deferred := call.site.(*ssa.Defer); deferred {
			drains++
			if call.registration.instruction != call.site || call.dispatch == nil {
				t.Fatal("deferred application detached from actual capture/drain")
			}
		} else if call.target.Name() == "child" {
			childCalls++
		}
	}
	if !normal || !recovered || !stopped || drains == 0 || recoveryEntries == 0 || child && childCalls == 0 {
		t.Fatalf("incomplete channel cover: normal=%v recovered=%v stopped=%v drains=%d recovery=%d child=%d", normal, recovered, stopped, drains, recoveryEntries, childCalls)
	}
	want := regionValue{typ: types.Typ[types.Int], kind: regionConstant, scalar: constant.MakeInt64(capacity)}
	if _, err := packet.projectNormal(t.Context(), want); err == nil {
		t.Fatal("normal projection ignored recovered allocation failure")
	}
	for i, event := range p.events {
		if event.rule == activationBeginPanic {
			p.events = append(slices.Clone(p.events[:i]), p.events[i+1:]...)
			break
		}
	}
	if got, err := checkRegionActivation(t.Context(), in, p, defaultRegionLimits()); err == nil || got != nil {
		t.Fatal("channel panic alternative could be omitted")
	}
}

func TestRegionActivationChannelFrameAndCoverage(t *testing.T) {
	for _, capacity := range []int64{0, 1, 1 << 30} {
		text := fmt.Sprintf(`func child()int{c:=make(chan [1024]byte,%d);return cap(c)};func F()(r int){defer func(){if recover()!=nil{r=-1}}();return child()};func G()(r int){defer func(){if recover()!=nil{r=-1}}();c:=make(chan [1024]byte,%d);return cap(c)}`, capacity, capacity)
		source := relationFixture(t, text, 32)
		checkActivationChannelCover(t, source, "F", capacity, true)
		checkActivationChannelCover(t, source, "G", capacity, false)
	}
	packet, _ := proveActivation(t, `func F()(r int){x:=3;defer func(){recover();r=x}();n:=func()int{x=8;return 1};c:=make(chan int,n());return cap(c)}`)
	for _, out := range packet.outcomes {
		if out.kind == activationNormal {
			localEffectInteger(t, out.value, 8)
		}
	}
	if _, err := packet.projectNormal(t.Context(), regionValue{typ: types.Typ[types.Int], kind: regionConstant, scalar: constant.MakeInt64(8)}); err != nil {
		t.Fatal(err)
	}
}

func TestRegionActivationRefusals(t *testing.T) {
	for _, text := range []string{
		`func F(){panic(nil)}`,
		`func F(){defer recover();panic(1)}`,
		`func F(){defer panic(1)}`,
		`func F(){defer F()}`,
		`func F(){for{defer func(){}()}}`,
		`func F(){go func(){}()}`,
		`func native();func F(){defer native();panic(1)}`,
		`func F(){var f func();defer f();panic(1)}`,
		`func F(){defer func(){var p *int;*p=1}();panic(1)}`,
	} {
		source := relationFixture(t, text, 64)
		in := activationInput(source, "F")
		if p, err := proposeRegionActivation(t.Context(), in, defaultRegionLimits()); err == nil || p != nil {
			t.Fatalf("unsupported activation admitted: %s", text)
		}
	}
	source := relationFixture(t, `func F(){recover()}`, 64)
	in := activationInput(source, "F")
	in.unwind = regionUnknownUnwind
	if p, err := proposeRegionActivation(t.Context(), in, defaultRegionLimits()); err == nil || p != nil {
		t.Fatal("fresh local stack invented no-active-unwind scope")
	}
}

func TestRegionActivationEvidenceOwnershipAndBounds(t *testing.T) {
	packet, proposal := proveActivation(t, `func F()(r int){defer func(){if recover()!=nil{r+=100}}();defer func(){defer func(){if recover()!=nil{r+=10}}();panic(2)}();panic(1)}`)
	for _, corrupt := range []string{"omit", "duplicate", "relabel", "position", "context", "target", "reorder", "unused", "input", "owner", "unwind"} {
		t.Run(corrupt, func(t *testing.T) {
			_, p, err := captureRegionActivation(packet.input, proposal, defaultRegionLimits())
			if err != nil {
				t.Fatal(err)
			}
			switch corrupt {
			case "omit":
				p.events = p.events[1:]
			case "duplicate":
				p.events = append(p.events[:1:1], p.events...)
			case "relabel":
				p.events[0].rule = activationReturn
			case "position":
				p.events[0].at.index++
			case "context":
				p.events[0].invocation.path = "/forged"
			case "target":
				p.events[0].target = packet.input.root
			case "reorder":
				p.events[0], p.events[1] = p.events[1], p.events[0]
			case "unused":
				p.events = append(p.events, p.events[0])
			case "input":
				p.input.premises = []string{"different"}
			case "owner":
				p.input.owner = nil
			case "unwind":
				p.input.unwind = regionUnknownUnwind
			}
			if checked, err := checkRegionActivation(t.Context(), packet.input, p, defaultRegionLimits()); err == nil || checked != nil {
				t.Fatal("forged activation accepted")
			}
		})
	}
	// Mutating caller containers from Context.Err must be too late to change
	// either the input or transcript used by this checking pass.
	in, p, err := captureRegionActivation(packet.input, proposal, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	ctx := &regionMutatingContext{Context: t.Context(), mutate: func() {
		p.events[0].rule = activationReturn
		p.input.premises[0] = "mutated"
		in.premises[0] = "mutated too"
	}}
	if got, err := checkRegionActivation(ctx, in, p, defaultRegionLimits()); err != nil || got == nil || got.input.premises[0] == "mutated too" {
		t.Fatalf("checking did not own its inputs: %v", err)
	}
	ctxCancel, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := checkRegionActivation(ctxCancel, packet.input, proposal, defaultRegionLimits()); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled check: %v", err)
	}
	counted := &regionCallCountingContext{Context: t.Context()}
	if _, err := checkRegionActivation(counted, packet.input, proposal, defaultRegionLimits()); err != nil {
		t.Fatal(err)
	}
	interrupted := &regionCallCountingContext{Context: t.Context(), stop: counted.checks / 2}
	if got, err := checkRegionActivation(interrupted, packet.input, proposal, defaultRegionLimits()); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-activation cancellation: %v", err)
	}
	for _, dimension := range []string{"work", "nodes", "states", "locations", "depth"} {
		limits := defaultRegionLimits()
		switch dimension {
		case "work":
			limits.work = 8
		case "nodes":
			limits.nodes = 2
		case "states":
			limits.states = 2
		case "locations":
			limits.locations = 2
		case "depth":
			limits.depth = 1
		}
		if got, err := checkRegionActivation(t.Context(), packet.input, proposal, limits); err == nil || got != nil {
			t.Fatalf("%s budget supplied partial evidence", dimension)
		}
	}
}

func TestSourceActivationSelectedBodies(t *testing.T) {
	source := relationFixture(t, `func child(p *int){*p=3;panic(1)};func F()(r int){defer func(){if recover()!=nil{r+=4}}();child(&r);r=99;return}`, 64)
	in := activationInput(source, "F")
	p, err := proposeRegionActivation(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	bound, err := checkSourceActivation(t.Context(), source, in, p, defaultRegistrationLimits().source, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	if bound.root.function != in.root || len(bound.calls) != 2 || len(bound.calls) != len(bound.packet.calls) {
		t.Fatal("missing actual selected root/child/deferred body")
	}
	for _, c := range bound.calls {
		if c.bound.function != c.call.target || c.bound.identity.source == ([32]byte{}) || c.bound.identity.body == ([32]byte{}) {
			t.Fatal("actual call lacks selected body binding")
		}
	}
	localEffectInteger(t, bound.packet.outcomes[0].value, 7)
	other := relationFixture(t, `func F()int{return 7}`, 64)
	if got, err := checkSourceActivation(t.Context(), other, in, p, defaultRegistrationLimits().source, defaultRegionLimits()); err == nil || got != nil {
		t.Fatal("different selected owner supplied bindings")
	}
	// The root binding alone cannot substitute for its actually executed child.
	// Corrupt only that child's source declaration after semantic checking; a
	// fresh binder must reject the detached body even with an intact root.
	child := in.root.Pkg.Func("child")
	child.Syntax().(*ast.FuncDecl).Body = nil
	binder, err := newSelectedSourceBinder(t.Context(), source, in.root, defaultRegistrationLimits().source)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := binder.checkSourceActivation(bound.packet); err == nil || got != nil {
		t.Fatal("actual child body omitted from selected binding")
	}
}

func TestRegionActivationInputHeapOwnership(t *testing.T) {
	source := relationFixture(t, `var X int;func F()int{return X}`, 64)
	in := activationInput(source, "F")
	object := regionObject{kind: regionGlobal, site: in.root.Pkg.Members["X"].(*ssa.Global)}
	value := func(n int64) regionValue {
		return regionValue{typ: types.Typ[types.Int], kind: regionConstant, scalar: constant.MakeInt64(n)}
	}
	in.initial.memory = map[regionObject]regionValue{object: value(42)}
	p, err := proposeRegionActivation(t.Context(), in, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	_, forged, err := captureRegionActivation(in, p, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	forged.input.initial.memory[object] = value(99)
	if got, err := checkRegionActivation(t.Context(), in, forged, defaultRegionLimits()); err == nil || got != nil {
		t.Fatal("forged incoming heap accepted")
	}
	ctx := &regionMutatingContext{Context: t.Context(), mutate: func() {
		in.initial.memory[object] = value(99)
		p.input.initial.memory[object] = value(99)
	}}
	got, err := checkRegionActivation(ctx, in, p, defaultRegionLimits())
	if err != nil {
		t.Fatal(err)
	}
	localEffectInteger(t, got.outcomes[0].value, 42)
	want := regionUnknownValue(types.Typ[types.Int])
	want.scalar = constant.MakeInt64(99)
	if projection, err := got.projectNormal(t.Context(), want); err == nil || projection != nil {
		t.Fatal("malformed abstract projection acquired authority")
	}
}
