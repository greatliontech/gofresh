package nativeproof

import (
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

// This is a constructor-resource oracle, not the ISA value oracle. It counts
// the expression vocabulary's actual height, including unused destination reads,
// hash-consed identity and literal Boolean rules. It consumes intent/edges only;
// no production transfer, expression builder, decoded graph or returned refusal
// determines an expected frontier. Accepted outputs independently validate these
// height predictions before they can license a depth refusal on a larger scope.
type dagShapeKey struct {
	op    string
	width int
	imm   uint64
	args  [3]int
}
type dagShapes struct {
	keys    []dagShapeKey
	heights []int
	intern  map[dagShapeKey]int
	pc      uint64
	fault   uint64
	fresh   uint64
}

func newDAGShapes() *dagShapes {
	return &dagShapes{keys: []dagShapeKey{{}}, heights: []int{0}, intern: map[dagShapeKey]int{}}
}
func (s *dagShapes) node(op string, w int, imm uint64, args ...int) int {
	k := dagShapeKey{op: op, width: w, imm: imm}
	copy(k.args[:], args)
	h := 1
	for _, a := range args {
		h = max(h, 1+s.heights[a])
	}
	if h > 512 && s.fault == 0 {
		s.fault = s.pc
	}
	if id := s.intern[k]; id != 0 {
		return id
	}
	id := len(s.keys)
	s.intern[k] = id
	s.keys = append(s.keys, k)
	s.heights = append(s.heights, h)
	return id
}
func (s *dagShapes) variable(w int) int           { s.fresh++; return s.node("var", w, s.fresh) }
func (s *dagShapes) constant(w int, v uint64) int { return s.node("const", w, v) }
func (s *dagShapes) literal(a int, v uint64) bool {
	k := s.keys[a]
	return k.op == "const" && k.width == 0 && k.imm == v
}
func (s *dagShapes) not(a int) int {
	if s.literal(a, 0) {
		return s.constant(0, 1)
	}
	if s.literal(a, 1) {
		return s.constant(0, 0)
	}
	return s.node("not", 0, 0, a)
}
func (s *dagShapes) and(a, b int) int {
	if s.literal(a, 0) || s.literal(b, 0) {
		return s.constant(0, 0)
	}
	if s.literal(a, 1) {
		return b
	}
	if s.literal(b, 1) || a == b {
		return a
	}
	return s.node("and", 0, 0, a, b)
}
func (s *dagShapes) or(a, b int) int {
	if s.literal(a, 1) || s.literal(b, 1) {
		return s.constant(0, 1)
	}
	if s.literal(a, 0) {
		return b
	}
	if s.literal(b, 0) || a == b {
		return a
	}
	return s.node("or", 0, 0, a, b)
}
func (s *dagShapes) ite(p, a, b int) int {
	if a == b || s.literal(p, 1) {
		return a
	}
	if s.literal(p, 0) {
		return b
	}
	return s.node("ite", s.keys[a].width, 0, p, a, b)
}
func (s *dagShapes) extract(a, off, w int) int {
	if off == 0 && w == s.keys[a].width {
		return a
	}
	return s.node("extract", w, uint64(off), a)
}

type dagDepthState struct {
	regs   [16]int
	flags  [3]int
	public [6]int
	path   int
	memory map[stateLocation]int
	ptrs   [16]statePointer
}

func (s *dagShapes) read(d *dagDepthState, r uint8, w int, high bool) int {
	off := 0
	if high {
		off = 8
	}
	return s.extract(d.regs[r], off, w)
}
func (s *dagShapes) write(d *dagDepthState, r uint8, w int, high bool, v int) {
	if w == 32 {
		d.regs[r] = s.node("zext", 64, 0, v)
		return
	}
	if w == 64 {
		d.regs[r] = v
		return
	}
	off := 0
	if high {
		off = 8
		v = s.node("concat", 16, 0, s.extract(d.regs[r], 0, 8), v)
	}
	d.regs[r] = s.node("concat", 64, 0, v, s.extract(d.regs[r], off+8, 64-off-8))
}
func (s *dagShapes) predicate(cc uint8, d *dagDepthState) int {
	c, z, l := d.flags[0], d.flags[1], d.flags[2]
	switch cc {
	case 2:
		return c
	case 3:
		return s.not(c)
	case 4:
		return z
	case 5:
		return s.not(z)
	case 6:
		return s.or(c, z)
	case 7:
		return s.not(s.or(c, z))
	case 12:
		return l
	case 13:
		return s.not(l)
	case 14:
		return s.or(z, l)
	case 15:
		return s.not(s.or(z, l))
	}
	panic("condition")
}
func (s *dagShapes) merge(a, b *dagDepthState, keys []stateLocation) *dagDepthState {
	if a == nil {
		return b
	}
	if s.literal(b.path, 0) {
		return a
	}
	if s.literal(a.path, 0) {
		return b
	}
	for r := range a.regs {
		a.regs[r] = s.ite(b.path, b.regs[r], a.regs[r])
		if a.ptrs[r] != b.ptrs[r] {
			a.ptrs[r] = statePointer{}
		}
	}
	for f := range a.flags {
		a.flags[f] = s.ite(b.path, b.flags[f], a.flags[f])
	}
	for f := range a.public {
		if a.public[f] != 0 && b.public[f] != 0 {
			a.public[f] = s.ite(b.path, b.public[f], a.public[f])
		} else {
			a.public[f] = 0
		}
	}
	for _, k := range keys {
		a.memory[k] = s.ite(b.path, b.memory[k], a.memory[k])
	}
	a.path = s.or(a.path, b.path)
	return a
}
func cloneDepthState(d *dagDepthState) *dagDepthState {
	r := *d
	r.memory = map[stateLocation]int{}
	for k, v := range d.memory {
		r.memory[k] = v
	}
	return &r
}

func (s *dagShapes) step(t testing.TB, d *dagDepthState, i to.Intent, next uint64) {
	t.Helper()
	if s.literal(d.path, 0) {
		return
	}
	w := 64
	if i.Width != 0 {
		w = int(i.Width)
	}
	if i.Operation == to.Jump || i.Operation == to.Branch {
		return
	}
	if i.Operation == to.CPUID {
		s.extract(d.regs[0], 0, 32)
		s.extract(d.regs[1], 0, 32)
		for _, r := range []int{0, 3, 1, 2} {
			d.regs[r] = s.node("zext", 64, 0, s.variable(32))
			d.ptrs[r] = statePointer{}
		}
		return
	}
	if i.Operation == to.Load || i.Operation == to.Store || i.Operation == to.StoreImmediate {
		p := d.ptrs[i.Base]
		if i.RIP {
			p = statePointer{valid: true, image: true, off: int64(next)}
		}
		if !p.valid {
			t.Fatal("resource intent lacks delivered pointer")
		}
		key := stateLocation{p.image, p.off + i.SignedDisp}
		if i.Operation == to.Load {
			v := d.memory[key]
			for lane := 1; lane < w/8; lane++ {
				v = s.node("concat", 8*(lane+1), 0, v, d.memory[key.add(int64(lane))])
			}
			s.write(d, i.Dst, w, i.HighDst, v)
			d.ptrs[i.Dst] = statePointer{}
			return
		}
		v := 0
		if i.Operation == to.Store {
			v = s.read(d, i.Src, w, i.HighSrc)
		} else {
			v = s.constant(w, i.Immediate)
		}
		for lane := 0; lane < w/8; lane++ {
			d.memory[key.add(int64(lane))] = s.extract(v, lane*8, 8)
		}
		return
	}
	left := s.read(d, i.Dst, w, i.HighDst)
	if i.Operation == to.LEARIP {
		d.regs[i.Dst] = s.constant(64, next+uint64(i.SignedDisp))
		d.ptrs[i.Dst] = statePointer{valid: true, image: true, off: int64(next) + i.SignedDisp}
		return
	}
	if i.Operation == to.LEA {
		d.regs[i.Dst] = s.node("add", 64, 0, s.constant(64, uint64(i.SignedDisp)), d.regs[i.Base])
		p := d.ptrs[i.Base]
		if p.valid {
			p.off += i.SignedDisp
		}
		d.ptrs[i.Dst] = p
		return
	}
	right := 0
	switch i.Operation {
	case to.MoveRegister, to.Compare, to.Test:
		right = s.read(d, i.Src, w, i.HighSrc)
	default:
		right = s.constant(w, i.Immediate)
	}
	switch i.Operation {
	case to.MoveRegister, to.MoveImmediate, to.MoveImmediate32:
		if i.Operation == to.MoveImmediate32 { // old vocabulary's width is implicit
			s.extract(d.regs[i.Dst], 0, 32)
			right = s.constant(32, i.Immediate)
			w = 32
		}
		s.write(d, i.Dst, w, i.HighDst, right)
		p := statePointer{}
		if i.Operation == to.MoveRegister && w == 64 {
			p = d.ptrs[i.Src]
		}
		d.ptrs[i.Dst] = p
	case to.Compare, to.CompareImmediate:
		d.flags = [3]int{s.node("ult", 0, 0, left, right), s.node("eq", 0, 0, left, right), s.node("slt", 0, 0, left, right)}
		d.public = [6]int{d.flags[0], d.flags[1], 0, 0, 0, 0}
	case to.Test, to.TestImmediate:
		v := s.node("bitand", w, 0, left, right)
		zero := s.constant(w, 0)
		d.flags = [3]int{s.constant(0, 0), s.node("eq", 0, 0, v, zero), s.node("slt", 0, 0, v, zero)}
		d.public = [6]int{d.flags[0], d.flags[1], s.constant(0, 0), d.flags[2], 0, 0}
	default:
		t.Fatal("unsupported resource intent", i)
	}
}

func dagOrder(x dagLayout, cut int) []int {
	queue := []int{0}
	seen := map[int]bool{0: true}
	degree := map[int]int{}
	for at := 0; at < len(queue); at++ {
		j := queue[at]
		if j == cut {
			continue
		}
		for _, k := range x.edges[j] {
			degree[k]++
			if !seen[k] {
				seen[k] = true
				queue = append(queue, k)
			}
		}
	}
	var order []int
	for _, j := range queue {
		if degree[j] == 0 {
			order = append(order, j)
		}
	}
	for at := 0; at < len(order); at++ {
		j := order[at]
		if j == cut {
			continue
		}
		for _, k := range x.edges[j] {
			degree[k]--
			if degree[k] == 0 {
				order = append(order, k)
			}
		}
	}
	return order
}
func dagDepth(t testing.TB, x dagLayout, cut int, initial stateReference) (*dagShapes, *dagDepthState) {
	t.Helper()
	s := newDAGShapes()
	d := &dagDepthState{path: s.constant(0, 1), memory: map[stateLocation]int{}}
	s.constant(0, 0)
	for r := range d.regs {
		d.regs[r] = s.variable(64)
	}
	for f := range d.flags {
		d.flags[f] = s.variable(0)
	}
	d.ptrs[4] = statePointer{valid: true}
	var keys []stateLocation
	for k := range initial.memory {
		keys = append(keys, k)
		d.memory[k] = s.variable(8)
	}
	states := map[int]*dagDepthState{0: d}
	for _, j := range dagOrder(x, cut) {
		s.pc = x.pcs[j]
		d = states[j]
		delete(states, j)
		if j == cut {
			return s, d
		}
		i := x.intents[j]
		s.step(t, d, i, x.pcs[j]+uint64(len(x.encoded[j])))
		if s.fault != 0 {
			return s, nil
		}
		pred := 0
		if i.Operation == to.Branch {
			pred = s.predicate(i.Condition, d)
		}
		for edge, k := range x.edges[j] {
			incoming := cloneDepthState(d)
			if i.Operation == to.Branch {
				p := pred
				if edge == 0 {
					p = s.not(p)
				}
				incoming.path = s.and(d.path, p)
			}
			states[k] = s.merge(states[k], incoming, keys)
			if s.fault != 0 {
				return s, nil
			}
		}
	}
	t.Fatal("resource graph lacks cut")
	return s, nil
}
func assertDAGDepth(t testing.TB, s *dagShapes, d *dagDepthState, c TransitionCertificate) {
	t.Helper()
	memo := map[br.Term]int{}
	for r, v := range c.checked.bound.Registers {
		if stateTermHeight(v.Value, memo) != s.heights[d.regs[r]] {
			t.Fatal("register resource premise differs", r)
		}
	}
	for f, v := range c.checked.flags {
		if stateTermHeight(v, memo) != s.heights[d.flags[f]] {
			t.Fatal("predicate resource premise differs", f)
		}
	}
	for _, v := range c.checked.bound.Memory {
		if stateTermHeight(v.Value, memo) != s.heights[d.memory[stateByteLocation(v)]] {
			t.Fatal("memory resource premise differs")
		}
	}
	if stateTermHeight(c.checked.bound.CutGuard, memo) != s.heights[d.path] {
		t.Fatal("cut resource premise differs")
	}
}
