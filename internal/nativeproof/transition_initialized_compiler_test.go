package nativeproof

import (
	"encoding/binary"
	"testing"
	"testing/quick"

	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

// Extend the independent byte grammar through the read/TEST/JE decision. CALL
// bytes are structural terminals only; the reference executor never models them.
func actualInitializedLayout(t testing.TB, im *Image, load uint64) (dagLayout, int, uint64, uint64) {
	t.Helper()
	parse := func(pc uint64) to.Decoded {
		raw, err := im.instructionBytes(pc)
		if err != nil {
			t.Fatal(err)
		}
		d, err := to.Parse(raw, pc)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	l := parse(load)
	if l.Intent.Operation != to.Load || !l.Intent.RIP || l.Intent.Width != 0 && l.Intent.Width != 64 {
		t.Fatal("candidate is not RIP MOV64")
	}
	address := uint64(int64(l.Next) + l.Intent.SignedDisp)
	test := parse(l.Next)
	if test.Intent.Operation != to.Test || test.Intent.Width != 0 && test.Intent.Width != 64 || test.Intent.Dst != 0 || test.Intent.Src != 0 {
		t.Fatal("candidate is not TEST RAX,RAX")
	}
	branch := parse(test.Next)
	if branch.Intent.Operation != to.Branch || branch.Intent.Condition != 4 {
		t.Fatal("candidate is not JE")
	}
	lea := parse(branch.Target)
	if lea.Intent.Operation != to.LEARIP || lea.Intent.Dst != 7 {
		t.Fatal("candidate is not LEA RDI")
	}
	cut := lea.Next
	raw, err := im.instructionBytes(cut)
	if err != nil || len(raw) < 5 || raw[0] != 0xe8 {
		t.Fatal("candidate next boundary is not direct CALL", err)
	}
	x := dagLayout{stateLayout: stateLayout{im: im, digest: im.digest}}
	queue := []uint64{im.entry}
	byPC := map[uint64]int{im.entry: 0}
	var edges [][]uint64
	dead := uint64(0)
	for at := 0; at < len(queue); at++ {
		if at >= 512 {
			t.Fatal("candidate graph search exhausted")
		}
		pc := queue[at]
		raw, err := im.instructionBytes(pc)
		if err != nil {
			t.Fatal(err)
		}
		x.pcs = append(x.pcs, pc)
		var intent to.Intent
		var next []uint64
		var size int
		if pc == cut {
			size = 5
		} else if len(raw) >= 2 && raw[0] == 0xff && raw[1] == 0xd0 {
			if dead != 0 {
				t.Fatal("multiple candidate indirect calls")
			}
			dead = pc
			size = 2
		} else {
			d := parse(pc)
			intent = d.Intent
			size = d.Length
			if intent.Operation == to.Jump {
				next = []uint64{d.Target}
			} else {
				next = []uint64{d.Next}
				if intent.Operation == to.Branch {
					next = append(next, d.Target)
				}
			}
		}
		x.encoded = append(x.encoded, append([]byte(nil), raw[:size]...))
		x.intents = append(x.intents, intent)
		edges = append(edges, next)
		for _, pc := range next {
			if _, ok := byPC[pc]; !ok {
				byPC[pc] = len(queue)
				queue = append(queue, pc)
			}
		}
	}
	x.edges = make([][]int, len(edges))
	for j, next := range edges {
		for _, pc := range next {
			x.edges[j] = append(x.edges[j], byPC[pc])
		}
	}
	// Read ELF program headers independently of Image.loads and initialization.
	count := int(binary.LittleEndian.Uint16(im.data[56:]))
	off := binary.LittleEndian.Uint64(im.data[32:])
	size := uint64(binary.LittleEndian.Uint16(im.data[54:]))
	for j := 0; j < count; j++ {
		h := im.data[off+uint64(j)*size:]
		if binary.LittleEndian.Uint32(h) != 1 {
			continue
		}
		flags := binary.LittleEndian.Uint32(h[4:])
		va := binary.LittleEndian.Uint64(h[16:])
		mem := binary.LittleEndian.Uint64(h[40:])
		x.mappings = append(x.mappings, interfaceMapping{start: va, end: va + mem, file: binary.LittleEndian.Uint64(h[8:]), filesz: binary.LittleEndian.Uint64(h[32:]), read: flags&4 != 0, write: flags&2 != 0, execute: flags&1 != 0})
	}
	if dead == 0 {
		t.Fatal("missing candidate excluded CALL")
	}
	return x, byPC[cut], address, dead
}

func checkOptimizedInitialized(t testing.TB, im *Image, face TransitionInterface, load uint64) {
	t.Helper()
	x, cut, address, dead := actualInitializedLayout(t, im, load)
	logicalBSS := false
	for _, m := range x.mappings {
		if address >= m.start+m.filesz && address+8 <= m.end && m.read && m.write && !m.execute {
			logicalBSS = true
			t.Logf("target %#x: PT_LOAD va=%#x off=%#x filesz=%#x memsz=%#x BSS=%#x", address, m.start, m.file, m.filesz, m.end-m.start, m.start+m.filesz)
		}
	}
	if !logicalBSS {
		t.Fatal("actual target is not eight writable BSS bytes")
	}
	face.ImageRegions = append(face.ImageRegions, Span{address, address + 8})
	var err error
	face.Initialization, err = CheckImageInitialization(t.Context(), im, StaticELFInitialization)
	if err != nil {
		t.Fatal(err)
	}
	p := x.proposal(cut)
	proposed, err := ProposeTransition(t.Context(), im, p.Cut, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	stateSameInventory(t, proposed, p)
	direct, err := CheckTransition(t.Context(), im, face, p, TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	loadIndex := 0
	for j, pc := range x.pcs {
		if pc == load {
			loadIndex = j
		}
	}
	root, err := CheckTransition(t.Context(), im, face, x.proposal(loadIndex), TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	continued, err := CheckTransitionContinuation(t.Context(), root, p)
	if err != nil {
		t.Fatal(err)
	}
	assertTransitionAlpha(t, direct, continued)
	for _, c := range []TransitionCertificate{direct, continued} {
		if len(c.checked.bound.ExcludedBoundaries) != 1 || c.checked.bound.ExcludedBoundaries[0].PC != dead {
			t.Fatal("actual dead arm not retained")
		}
	}
	if err := quick.Check(func(first, second [4]uint32, raw [512]byte, inactive [32]byte) bool {
		for class := 0; class < 5; class++ {
			initial := initializedReference(face, im.data, x.mappings, raw[:])
			initial.outcomes = [][4]uint32{cpuControlClass(first, class), second}
			for _, c := range []TransitionCertificate{direct, continued} {
				dagAssert(t, c, x, cut, face, initial, inactive[:])
			}
		}
		return true
	}, &quick.Config{MaxCount: 24}); err != nil {
		t.Fatal(err)
	}
	unknown := face
	unknown.Initialization = ImageInitialization{}
	c, err := CheckTransition(t.Context(), im, unknown, p, TransitionLimits{})
	transitionRefused(t, c, err)
	t.Logf("initialized root %#x -> unexecuted live CALL %#x; excluded CALL %#x under checked false BOOL guard; loader/process/source applicability remains conditional", im.entry, p.Cut, dead)
	checkOptimizedCallTLS(t, im, face, x, p.Cut)
}
