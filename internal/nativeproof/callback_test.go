package nativeproof

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"testing"
)

const descriptorAddress = testBase + 0x2000
const callbackEntry = testEntry + 0x80
const callbackFragment = "488b0a488b442410ffd1c3" // MOV [DX],CX; MOV 16(SP),AX; CALL CX; RET boundary

// The readonly descriptor and writable registration-like row have the same
// target bytes. Only actual program-header permissions distinguish them.
func callbackELF(t testing.TB, fragment, callee string) []byte {
	t.Helper()
	code := make([]byte, 0x80)
	copy(code, hexBytes(t, fragment))
	code = append(code, hexBytes(t, callee)...)
	b := elfBytes(code)
	b = append(b, make([]byte, 0x3008-len(b))...)
	binary.LittleEndian.PutUint16(b[56:], 3)
	for j, flags := range []uint32{4, 6} {
		off := 120 + j*56
		binary.LittleEndian.PutUint32(b[off:], 1)
		binary.LittleEndian.PutUint32(b[off+4:], flags)
		binary.LittleEndian.PutUint64(b[off+8:], uint64(0x2000+j*0x1000))
		binary.LittleEndian.PutUint64(b[off+16:], descriptorAddress+uint64(j*0x1000))
		binary.LittleEndian.PutUint64(b[off+32:], 8)
		binary.LittleEndian.PutUint64(b[off+40:], 8)
		binary.LittleEndian.PutUint64(b[off+48:], 4096)
	}
	binary.LittleEndian.PutUint64(b[0x2000:], callbackEntry)
	binary.LittleEndian.PutUint64(b[0x3000:], callbackEntry)
	return b
}

func descriptorConditions() DescriptorConditions {
	return DescriptorConditions{Machine: MachineModel, ReadonlyMapping: true}
}

func callFace() CallInterface {
	return CallInterface{DescriptorRegister: RDX, ContextRegister: RDX,
		Arguments: []ArgumentTransfer{{From: Location{Kind: EntryStackWord, Offset: 16}, To: RAX, Bits: math.MaxUint64}},
		Preserved: Masks{RBP: math.MaxUint64, R14: math.MaxUint64},
		Conditions: CallConditions{Machine: MachineModel, InstructionMapping: true, IsolatedInvocation: true, EntryState: true,
			Stack: CallStack{Pointer: 0x70000000, Region: Span{0x6ffff000, 0x70001000}, Readable: true, Writable: true, Protected: true, NoAliases: true}}}
}

func callbackSetup(t testing.TB, raw []byte, targetFace Interface) (*Image, Certificate, Descriptor) {
	t.Helper()
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	c, err := prove(t, im, callbackEntry, targetFace)
	if err != nil {
		t.Fatal(err)
	}
	d, err := CheckDescriptor(t.Context(), im, descriptorAddress, c, descriptorConditions())
	if err != nil {
		t.Fatal(err)
	}
	return im, c, d
}

func requireCallRefusal(t testing.TB, c CallCertificate, err error, premise string) {
	t.Helper()
	if _, ok := c.Bound(); ok {
		t.Fatal("refusal published call evidence")
	}
	requireRefusal(t, Certificate{}, err, premise)
}

func TestReadonlyDescriptorAndActualCall(t *testing.T) {
	im, _, d := callbackSetup(t, callbackELF(t, callbackFragment, "c3"), face(Masks{RAX: math.MaxUint64}, Masks{}))
	f := callFace()
	c, err := CheckCall(t.Context(), im, testEntry, testEntry+10, d, f, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := c.Bound()
	if !ok || b.Call != testEntry+8 || b.Continuation.Span != (Span{testEntry + 10, testEntry + 11}) || len(b.Instructions) != 3 ||
		b.CalleeStackPointer != f.Conditions.Stack.Pointer-8 || b.RestoredStackPointer != f.Conditions.Stack.Pointer || b.CallWrite != (Span{f.Conditions.Stack.Pointer - 8, f.Conditions.Stack.Pointer}) ||
		b.Descriptor.Target.Entry != callbackEntry || b.Interface.Results != (Masks{}) || b.Descriptor.Word != (Span{descriptorAddress, descriptorAddress + 8}) {
		t.Fatalf("missing conditional transfer facts: %+v", b)
	}
	if !reflect.DeepEqual(b.Interface, f) || b.Rules != CallbackRules || b.Descriptor.Conditions != descriptorConditions() {
		t.Fatal("premises or rules were lost")
	}
	// Owned projections cannot mutate evidence, including nested target spans.
	want, _ := c.Bound()
	b.Instructions[0].Bytes[0] = 0xcc
	b.Continuation.Bytes[0] = 0xcc
	b.Descriptor.Target.Instructions[0].Start = 0
	b.Interface.Arguments[0].Bits = 0
	f.Arguments[0].Bits = 0
	now, _ := c.Bound()
	if !reflect.DeepEqual(want, now) {
		t.Fatal("projection or caller slice mutated checked evidence")
	}
	if _, ok := (Descriptor{}).Bound(); ok {
		t.Fatal("zero descriptor")
	}
	if _, ok := (CallCertificate{}).Bound(); ok {
		t.Fatal("zero call certificate")
	}
}

func TestDirectCallAndRegisterTransport(t *testing.T) {
	// MOV AX,RBX; CALL target; RET. Direct calls still require exact context,
	// argument transport, same-image target and a writable protected CALL slot.
	fragment := []byte{0x48, 0x89, 0xc3, 0xe8, 0, 0, 0, 0, 0xc3}
	binary.LittleEndian.PutUint32(fragment[4:], uint32(callbackEntry-(testEntry+8)))
	raw := callbackELF(t, "", "4889d8c3")
	copy(raw[0x1000:], fragment)
	im, _, d := callbackSetup(t, raw, face(Masks{RBX: math.MaxUint64}, Masks{RAX: math.MaxUint64}))
	f := callFace()
	f.Arguments = []ArgumentTransfer{{From: Location{Kind: EntryRegister, Register: RAX}, To: RBX, Bits: math.MaxUint64}}
	f.Results[RAX] = math.MaxUint64
	if _, err := CheckCall(t.Context(), im, testEntry, testEntry+8, d, f, 0); err != nil {
		t.Fatal(err)
	}
	f.Arguments[0].From.Register = RCX
	c, err := CheckCall(t.Context(), im, testEntry, testEntry+8, d, f, 0)
	requireCallRefusal(t, c, err, "call-argument")
}

func TestDescriptorPermissionsBoundsAndAliases(t *testing.T) {
	for _, tt := range []struct {
		name, premise string
		address       uint64
		change        func([]byte)
	}{
		{"writable-row", "descriptor-mapping", descriptorAddress + 0x1000, nil},
		{"unreadable", "descriptor-mapping", descriptorAddress, func(b []byte) { binary.LittleEndian.PutUint32(b[124:], 0) }},
		{"writable", "descriptor-mapping", descriptorAddress, func(b []byte) { binary.LittleEndian.PutUint32(b[124:], 6) }},
		{"BSS", "descriptor-mapping", descriptorAddress, func(b []byte) { binary.LittleEndian.PutUint64(b[152:], 0) }},
		{"boundary", "descriptor-mapping", descriptorAddress + 1, nil},
		{"overflow", "descriptor-mapping", math.MaxUint64 - 3, nil},
		{"wrong-target", "descriptor-target", descriptorAddress, func(b []byte) { binary.LittleEndian.PutUint64(b[0x2000:], callbackEntry+1) }},
		{"file-page-alias", "descriptor-alias", descriptorAddress, func(b []byte) { binary.LittleEndian.PutUint64(b[184:], 0x2000) }},
		{"BSS-leading-page-alias", "descriptor-alias", descriptorAddress, func(b []byte) {
			binary.LittleEndian.PutUint64(b[184:], 0x2008)
			binary.LittleEndian.PutUint64(b[192:], descriptorAddress+0x1008)
			binary.LittleEndian.PutUint64(b[208:], 0)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw := callbackELF(t, callbackFragment, "c3")
			if tt.change != nil {
				tt.change(raw)
			}
			im, err := NewImage(t.Context(), raw)
			if err != nil {
				t.Fatal(err)
			}
			c, err := prove(t, im, callbackEntry, face(Masks{}, Masks{}))
			if err != nil {
				t.Fatal(err)
			}
			d, err := CheckDescriptor(t.Context(), im, tt.address, c, descriptorConditions())
			if _, ok := d.Bound(); ok {
				t.Fatal("invalid descriptor supplied evidence")
			}
			requireRefusal(t, Certificate{}, err, tt.premise)
		})
	}
}

func TestDescriptorLoaderRejectsEmptyPartialPage(t *testing.T) {
	raw := callbackELF(t, callbackFragment, "c3")
	binary.LittleEndian.PutUint64(raw[184:], 0x2008)
	binary.LittleEndian.PutUint64(raw[192:], descriptorAddress+0x1008)
	binary.LittleEndian.PutUint64(raw[208:], 0)
	binary.LittleEndian.PutUint64(raw[216:], 0)
	im, err := NewImage(t.Context(), raw)
	if im != nil {
		t.Fatal("empty logical load hid a partial-page mapping")
	}
	requireRefusal(t, Certificate{}, err, "image-mapping")
}

func TestCallPremisesAndCompositionRefuse(t *testing.T) {
	im, _, d := callbackSetup(t, callbackELF(t, callbackFragment, "c3"), face(Masks{RAX: math.MaxUint64}, Masks{}))
	for _, tt := range []struct {
		name, premise string
		change        func(*CallInterface)
	}{
		{"machine", "call-premises", func(f *CallInterface) { f.Conditions.Machine = "Go ABI" }},
		{"mapping", "call-premises", func(f *CallInterface) { f.Conditions.InstructionMapping = false }},
		{"isolation", "call-premises", func(f *CallInterface) { f.Conditions.IsolatedInvocation = false }},
		{"provenance", "call-premises", func(f *CallInterface) { f.Conditions.EntryState = false }},
		{"push-not-writable", "call-stack", func(f *CallInterface) { f.Conditions.Stack.Writable = false }},
		{"return-not-readable", "call-stack", func(f *CallInterface) { f.Conditions.Stack.Readable = false }},
		{"unprotected", "call-stack", func(f *CallInterface) { f.Conditions.Stack.Protected = false }},
		{"stack-alias", "call-stack", func(f *CallInterface) { f.Conditions.Stack.NoAliases = false }},
		{"push-underflow", "call-stack", func(f *CallInterface) { f.Conditions.Stack.Pointer = 7 }},
		{"stack-noncanonical", "call-stack", func(f *CallInterface) { f.Conditions.Stack.Region.End = math.MaxUint64 }},
		{"push-outside", "call-stack", func(f *CallInterface) { f.Conditions.Stack.Region.Start = f.Conditions.Stack.Pointer }},
		{"image-overlap", "call-stack", func(f *CallInterface) {
			f.Conditions.Stack.Pointer = testEntry + 8
			f.Conditions.Stack.Region = Span{testEntry, testEntry + 4096}
		}},
		{"wrong-context", "call-context", func(f *CallInterface) { f.ContextRegister = R8 }},
		{"wrong-descriptor-register", "call-memory", func(f *CallInterface) { f.DescriptorRegister = RBX }},
		{"missing-argument", "call-interface", func(f *CallInterface) { f.Arguments = nil }},
		{"argument-outside", "call-interface", func(f *CallInterface) { f.Arguments[0].From.Offset = math.MaxInt64 }},
		{"argument-overlaps-push", "call-interface", func(f *CallInterface) { f.Arguments[0].From.Offset = -8 }},
		{"wrong-argument", "call-memory", func(f *CallInterface) { f.Arguments[0].From.Offset = 24 }},
		{"unproved-result", "call-frame", func(f *CallInterface) { f.Results[RAX] = 1 }},
		{"callee-clobber", "call-frame", func(f *CallInterface) { f.Preserved[RBX] = 1 }},
		{"stack-projection", "call-interface", func(f *CallInterface) { f.Results[RSP] = 1 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := callFace()
			tt.change(&f)
			c, err := CheckCall(t.Context(), im, testEntry, testEntry+10, d, f, 0)
			requireCallRefusal(t, c, err, tt.premise)
		})
	}
	for _, end := range []uint64{testEntry, testEntry + 9, testEntry + 11} {
		c, err := CheckCall(t.Context(), im, testEntry, end, d, callFace(), 0)
		requireCallRefusal(t, c, err, "call-continuation")
	}
	c, err := CheckCall(t.Context(), im, testEntry, testEntry+10, d, callFace(), 1)
	requireCallRefusal(t, c, err, "call-budget")
}

func TestActualCallAndContinuationCoverage(t *testing.T) {
	for _, tt := range []struct {
		name, code, premise string
		end                 uint64
	}{
		{"omitted-call", "488b0a488b44241090c3", "call-instruction", 10},
		{"wrong-indirect-target", "488b0a488b442410ffd3c3", "call-target", 10},
		{"context-clobber", "488b0a488b4424104889c2ffd1c3", "call-context", 13},
		{"frame-write", "488b0a488b4424104889c5ffd1c3", "preserved-register", 13},
		{"memory-store", "48890affd1c3", "call-instruction", 5},
		{"interior-descriptor", "488b4a01488b442410ffd1c3", "call-memory", 11},
		{"indexed-descriptor", "488b0c02488b442410ffd1c3", "call-memory", 11},
		{"invented-target", "48b98010400000000000488b442410ffd0c3", "call-instruction", 17},
		{"indirect-memory-call", "488b442410ff12c3", "call-target", 7},
		{"conditional-path", "7500ffd1c3", "call-instruction", 4},
	} {
		t.Run(tt.name, func(t *testing.T) {
			im, _, d := callbackSetup(t, callbackELF(t, tt.code, "c3"), face(Masks{RAX: math.MaxUint64}, Masks{}))
			c, err := CheckCall(t.Context(), im, testEntry, testEntry+tt.end, d, callFace(), 0)
			requireCallRefusal(t, c, err, tt.premise)
		})
	}
	// Put the fragment after the target so its continuation can be genuinely
	// absent or truncated, not accidentally supplied by zero padding.
	for _, suffix := range []string{"", "48b8"} {
		raw := callbackELF(t, "", "c3")
		code := hexBytes(t, "488b0a488b442410ffd1"+suffix)
		copy(raw[0x1100:], code)
		binary.LittleEndian.PutUint64(raw[96:], uint64(0x100+len(code)))
		binary.LittleEndian.PutUint64(raw[104:], uint64(0x100+len(code)))
		im, _, d := callbackSetup(t, raw, face(Masks{RAX: math.MaxUint64}, Masks{}))
		c, err := CheckCall(t.Context(), im, testEntry+0x100, testEntry+0x10a, d, callFace(), 0)
		premise := "instruction-mapping"
		if suffix != "" {
			premise = "instruction-decode"
		}
		requireCallRefusal(t, c, err, premise)
	}
}

func TestEffectOnlyEntryStillChecksAllPaths(t *testing.T) {
	f := face(Masks{}, Masks{})
	for _, code := range []string{"c3", "4831c0c3", "31c039c07401c3c3"} {
		if _, err := prove(t, image(t, hexBytes(t, code)), testEntry, f); err != nil {
			t.Fatal(err)
		}
	}
	for _, tt := range []struct{ code, premise string }{
		{"90", "instruction-mapping"}, {"7401c3c3", "flag-input-bound"},
		{"4531f6c3", "preserved-register"}, {"488b00c3", "data-memory"},
		{"31c039c07401c3488900c3", "data-memory"},
	} {
		c, err := prove(t, image(t, hexBytes(t, tt.code)), testEntry, f)
		requireRefusal(t, c, err, tt.premise)
	}
}

func TestCallbackOwnershipAndCancellation(t *testing.T) {
	raw := callbackELF(t, callbackFragment, "c3")
	im, target, descriptor := callbackSetup(t, raw, face(Masks{RAX: math.MaxUint64}, Masks{}))
	other, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckDescriptor(t.Context(), other, descriptorAddress, target, descriptorConditions()); err == nil {
		t.Fatal("independent image borrowed target")
	}
	c, err := CheckCall(t.Context(), other, testEntry, testEntry+10, descriptor, callFace(), 0)
	requireCallRefusal(t, c, err, "call-binding")
	count := &imageCallbackContext{Context: t.Context()}
	want, err := CheckCall(count, im, testEntry, testEntry+10, descriptor, callFace(), 0)
	if err != nil {
		t.Fatal(err)
	}
	wantBound, _ := want.Bound()
	for at := 1; at <= count.calls; at++ {
		supplied := *im
		f := callFace()
		ctx := &imageCallbackContext{Context: t.Context(), onErr: func(n int) {
			if n == at {
				supplied = Image{}
				f.Arguments[0].Bits = 0
			}
		}}
		got, err := CheckCall(ctx, &supplied, testEntry, testEntry+10, descriptor, f, 0)
		if err != nil {
			t.Fatal(err)
		}
		bound, _ := got.Bound()
		if !reflect.DeepEqual(bound, wantBound) {
			t.Fatal("context callback changed owned inputs")
		}
		cancelCtx, cancel := context.WithCancel(t.Context())
		ctx = &imageCallbackContext{Context: cancelCtx, onErr: func(n int) {
			if n == at {
				cancel()
			}
		}}
		got, err = CheckCall(ctx, im, testEntry, testEntry+10, descriptor, callFace(), 0)
		cancel()
		if _, ok := got.Bound(); ok || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled call published evidence: %v", err)
		}
	}
	count = &imageCallbackContext{Context: t.Context()}
	if _, err := CheckDescriptor(count, im, descriptorAddress, target, descriptorConditions()); err != nil {
		t.Fatal(err)
	}
	for at := 1; at <= count.calls; at++ {
		supplied := *im
		ctx := &imageCallbackContext{Context: t.Context(), onErr: func(n int) {
			if n == at {
				supplied = Image{}
			}
		}}
		got, err := CheckDescriptor(ctx, &supplied, descriptorAddress, target, descriptorConditions())
		if err != nil {
			t.Fatal(err)
		}
		if got.checked.image.digest != im.digest {
			t.Fatal("descriptor lost image ownership")
		}
		cancelCtx, cancel := context.WithCancel(t.Context())
		ctx = &imageCallbackContext{Context: cancelCtx, onErr: func(n int) {
			if n == at {
				cancel()
			}
		}}
		got, err = CheckDescriptor(ctx, im, descriptorAddress, target, descriptorConditions())
		cancel()
		if _, ok := got.Bound(); ok || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled descriptor published evidence: %v", err)
		}
	}
}

// Fuzz descriptor address arithmetic on a fixed genuine multi-load image. The
// expected positive set is derived independently from the fixture's one word.
func FuzzReadonlyDescriptorExtent(f *testing.F) {
	for _, address := range []uint64{descriptorAddress, descriptorAddress + 1, descriptorAddress + 0x1000, math.MaxUint64 - 3, 0} {
		f.Add(address)
	}
	raw := callbackELF(f, callbackFragment, "c3")
	im, target, _ := callbackSetup(f, raw, face(Masks{}, Masks{}))
	f.Fuzz(func(t *testing.T, address uint64) {
		d, err := CheckDescriptor(t.Context(), im, address, target, descriptorConditions())
		_, ok := d.Bound()
		if address == descriptorAddress {
			if err != nil || !ok {
				t.Fatal(err)
			}
		} else if err == nil || ok {
			t.Fatalf("accepted descriptor outside fixture word at %#x", address)
		}
	})
}

// Vary actual ModRM/REX operands rather than an asserted target summary. The
// deciding rule is exact target flow beside argument/context/frame preservation.
func FuzzCallbackRegisterTransport(f *testing.F) {
	for _, pair := range [][2]uint8{{1, 1}, {1, 3}, {8, 8}, {2, 2}, {0, 0}, {4, 4}, {5, 5}, {14, 14}} {
		f.Add(pair[0], pair[1])
	}
	f.Fuzz(func(t *testing.T, loaded, called uint8) {
		loaded, called = loaded%16, called%16
		loadREX := byte(0x48)
		if loaded >= 8 {
			loadREX |= 4
		}
		code := []byte{loadREX, 0x8b, byte(loaded%8)<<3 | 2, 0x48, 0x8b, 0x44, 0x24, 0x10}
		if called >= 8 {
			code = append(code, 0x41)
		}
		code = append(code, 0xff, 0xd0+called%8)
		continuation := testEntry + uint64(len(code))
		code = append(code, 0xc3)
		raw := callbackELF(t, "", "c3")
		copy(raw[0x1000:], code)
		im, _, descriptor := callbackSetup(t, raw, face(Masks{RAX: math.MaxUint64}, Masks{}))
		c, err := CheckCall(t.Context(), im, testEntry, continuation, descriptor, callFace(), 0)
		_, ok := c.Bound()
		want := loaded == called && loaded != uint8(RAX) && loaded != uint8(RDX) && loaded != uint8(RSP) && loaded != uint8(RBP) && loaded != uint8(R14)
		if want != (err == nil) || want != ok {
			t.Fatalf("load=%d call=%d want=%v evidence=%v err=%v", loaded, called, want, ok, err)
		}
	})
}
