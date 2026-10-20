package nativeproof

import (
	"encoding/binary"
	"slices"
	"testing"
	"testing/quick"

	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

// The independent byte grammar locates the actual CALL, callee and post-return
// check. Only that CALL is expanded; other calls remain structural candidates.
// No symbol table, function size, kernel label or expected register state is input.
func actualCallTLSLayout(t testing.TB, im *Image, prior dagLayout, callPC uint64) (dagLayout, int, uint64, []int) {
	t.Helper()
	parse := func(pc uint64) to.Decoded {
		raw, err := im.instructionBytes(pc)
		if err != nil {
			t.Fatal(err)
		}
		d, err := to.Parse(raw, pc)
		if err != nil {
			t.Fatalf("actual independent parse %#x: %v", pc, err)
		}
		return d
	}
	call := parse(callPC)
	if call.Intent.Operation != to.Call {
		t.Fatal("actual boundary is not direct CALL")
	}
	store := parse(call.Next)
	if store.Intent.Operation != to.StoreImmediate || !store.Intent.FS || store.Intent.SignedDisp != -8 || store.Intent.Immediate != 0x123 {
		t.Fatal("actual FS check store differs")
	}
	load := parse(store.Next)
	compare := parse(load.Next)
	branch := parse(compare.Next)
	if load.Intent.Operation != to.Load || !load.Intent.RIP || compare.Intent.Operation != to.CompareImmediate || compare.Intent.Immediate != 0x123 || branch.Intent.Operation != to.Branch || branch.Intent.Condition != 4 {
		t.Fatal("actual TLS reload/check differs")
	}
	cut := branch.Target
	if parse(cut).Intent.Operation != to.LEARIP {
		t.Fatal("actual next cut is not LEA")
	}
	tls := uint64(int64(load.Next) + load.Intent.SignedDisp)
	x := dagLayout{stateLayout: stateLayout{im: im, digest: im.digest, mappings: slices.Clone(prior.mappings)}, callReturns: map[int]int{}}
	queue := []uint64{im.entry}
	byPC := map[uint64]int{im.entry: 0}
	var targets [][]uint64
	add := func(pc uint64) {
		if _, ok := byPC[pc]; !ok {
			byPC[pc] = len(queue)
			queue = append(queue, pc)
		}
	}
	sysPC, sysNext, retPC := uint64(0), uint64(0), uint64(0)
	for at := 0; at < len(queue); at++ {
		if at >= 1024 {
			t.Fatal("actual candidate discovery bound")
		}
		pc := queue[at]
		raw, err := im.instructionBytes(pc)
		if err != nil {
			t.Fatal(err)
		}
		var d to.Decoded
		var next []uint64
		size := 0
		switch {
		case pc == cut:
			d = parse(pc)
			size = d.Length
			d.Intent = to.Intent{}
		case len(raw) >= 2 && raw[0] == 0xff && raw[1] == 0xd0:
			size = 2 // structurally valid indirect CALL, with no execution rule
		case pc != callPC && len(raw) >= 5 && raw[0] == 0xe8:
			size = 5 // another direct CALL remains unexpanded
		case len(raw) >= 11 && raw[0] == 0xc7 && raw[1] == 0x04 && raw[2] == 0x25:
			// Structural-only absolute MOV32: disp32 plus imm32. Its full
			// bytes are retained; no access or low-memory fault is asserted.
			size = 11
		default:
			d = parse(pc)
			size = d.Length
			switch d.Intent.Operation {
			case to.Call:
				next = []uint64{d.Target}
				add(d.Target)
				add(d.Next)
			case to.Return:
				retPC = pc
			case to.Jump:
				next = []uint64{d.Target}
			case to.Branch:
				next = []uint64{d.Next, d.Target}
			default:
				next = []uint64{d.Next}
			}
			if d.Intent.Operation == to.Syscall {
				sysPC, sysNext = pc, d.Next
			}
		}
		x.pcs = append(x.pcs, pc)
		x.encoded = append(x.encoded, slices.Clone(raw[:size]))
		x.intents = append(x.intents, d.Intent)
		targets = append(targets, next)
		for _, target := range next {
			add(target)
		}
	}
	x.edges = make([][]int, len(targets))
	for j, next := range targets {
		for _, pc := range next {
			x.edges[j] = append(x.edges[j], byPC[pc])
		}
	}
	x.callReturns[byPC[callPC]] = byPC[call.Next]
	if sysPC == 0 || retPC == 0 {
		t.Fatal("actual callee lacks syscall/return inventory")
	}
	return x, byPC[cut], tls, []int{byPC[callPC], byPC[sysPC], byPC[sysNext], byPC[retPC], byPC[call.Next], byPC[cut]}
}

func checkOptimizedCallTLS(t testing.TB, im *Image, face TransitionInterface, prior dagLayout, callPC uint64) {
	t.Helper()
	x, end, tls, cuts := actualCallTLSLayout(t, im, prior, callPC)
	face.Regions = append(slices.Clone(face.Regions), RelativeRegion{RelativeSpan{-56, -48}, true, true}, RelativeRegion{RelativeSpan{-64, -56}, true, true})
	face.ImageRegions = append(slices.Clone(face.ImageRegions), Span{tls, tls + 8})
	face.Conditions.Syscall = LinuxAMD64SyscallModel
	face.Conditions.UserAddressBits = 48
	// The earlier image-prefix relation already requires the larger envelope for
	// its LEA. No read/write permission is added for the unused allocation gap.
	if face.Envelope.Start > -96 {
		face.Envelope.Start = -96
		face.Origin.Min = max(face.Origin.Min, 96)
	}
	p := callInventory(t, x, end)
	proposed, err := ProposeTransition(t.Context(), im, p.Cut, TransitionLimits{}, transitionTestOptions(p))
	if err != nil {
		t.Fatal(err)
	}
	stateSameContextInventory(t, proposed, p)
	flat, err := CheckTransition(t.Context(), im, face, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	var c TransitionCertificate
	for j, cut := range cuts {
		q := callInventory(t, x, cut)
		if j == 0 {
			c, err = CheckTransition(t.Context(), im, face, q, TransitionLimits{})
		} else {
			before := c.checked.bound
			c, err = CheckTransitionContinuation(t.Context(), c, q)
			if err == nil {
				stateInheritedInputs(t, before, c.checked.bound)
			}
		}
		if err != nil {
			t.Fatalf("actual split %#x: %v", q.Cut, err)
		}
	}
	assertCallTLSAlpha(t, flat, c)
	if err := quick.Check(func(first, second [4]uint32, raw [768]byte) bool {
		for class := 0; class < 5; class++ {
			r := initializedReference(face, im.data, x.mappings, raw[:])
			r.outcomes = [][4]uint32{cpuControlClass(first, class), second}
			for _, checked := range []TransitionCertificate{flat, c} {
				callTLSAssert(t, checked, x, end, face, r)
			}
		}
		return true
	}, &quick.Config{MaxCount: 24}); err != nil {
		t.Fatal(err)
	}
	// Independent final byte check: FS-relative and ordinary reads share this
	// storage. The theorem's input did not seed this expected value.
	var bytes [8]byte
	for _, cell := range c.checked.bound.Memory {
		if cell.isImage() && cell.offset >= int64(tls) && cell.offset < int64(tls+8) {
			bytes[cell.offset-int64(tls)] = byte(stateEval(t, cell.Value, nil))
		}
	}
	if binary.LittleEndian.Uint64(bytes[:]) != 0x123 {
		t.Fatal("actual TLS byte result differs")
	}
	t.Logf("conditional actual CALL %#x -> TLS image bytes %#x -> unexecuted LEA %#x; executor/source applicability remains open", callPC, tls, p.Cut)
}
