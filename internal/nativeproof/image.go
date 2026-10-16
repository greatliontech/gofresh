package nativeproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"fmt"
)

type mapping struct {
	va, end, off, filesz uint64
	executable           bool
	readable, writable   bool
}

// Image owns an immutable copy of a fully bound ELF64 little-endian ET_EXEC
// image. Only unambiguous, nonwritable, file-backed executable PT_LOAD bytes
// can be decoded. Symbol and section extents never delimit control flow.
type Image struct {
	data   []byte
	digest [32]byte
	loads  []mapping
}

// snapshot owns the container before any caller callback can replace it. A
// shallow copy suffices: construction owns the data and load backing arrays,
// neither is exposed publicly, and no operation mutates them after construction.
// instructionBytes lends only internal read-only views of that owned data.
func (im *Image) snapshot() *Image {
	if im == nil {
		return nil
	}
	owned := *im
	return &owned
}

// NewImage copies the bytes supplied by an inspected-artifact owner. It rejects
// dynamic loading/relocation, overlapping load ranges (including BSS), integer
// overflow, and addresses outside the low canonical 48-bit address subset.
// The caller must not mutate input concurrently with this call.
func NewImage(ctx context.Context, input []byte) (*Image, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data := make([]byte, len(input))
	h := sha256.New()
	for off := 0; off < len(input); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := min(len(input)-off, 64<<10)
		copy(data[off:off+n], input[off:off+n])
		h.Write(data[off : off+n])
		off += n
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, refuse(0, "image-format", err.Error())
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Machine != elf.EM_X86_64 || f.Type != elf.ET_EXEC {
		return nil, refuse(0, "image-format", "requires ELF64 little-endian x86-64 ET_EXEC")
	}
	im := &Image{data: data}
	copy(im.digest[:], h.Sum(nil))
	for _, s := range f.Sections {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// SHT_RELR (19) is not named by every supported debug/elf release.
		if s.Type == elf.SHT_REL || s.Type == elf.SHT_RELA || s.Type == elf.SectionType(19) {
			return nil, refuse(0, "image-relocation", "relocation sections are unsupported")
		}
	}
	for _, p := range f.Progs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if p.Type == elf.PT_DYNAMIC || p.Type == elf.PT_INTERP {
			return nil, refuse(p.Vaddr, "image-relocation", "dynamic/interpreted images are unsupported")
		}
		if p.Type != elf.PT_LOAD {
			continue
		}
		end, ok := plus(p.Vaddr, p.Memsz)
		fileEnd, fileOK := plus(p.Off, p.Filesz)
		if !ok || !fileOK || p.Filesz > p.Memsz || fileEnd > uint64(len(data)) || end > 1<<47 || p.Vaddr >= 1<<47 {
			return nil, refuse(p.Vaddr, "image-mapping", "overflow, noncanonical address, or unbacked file extent")
		}
		if p.Align > 1 && (p.Align&(p.Align-1) != 0 || p.Vaddr%p.Align != p.Off%p.Align) {
			return nil, refuse(p.Vaddr, "image-mapping", "invalid load alignment")
		}
		if p.Vaddr%4096 != p.Off%4096 {
			return nil, refuse(p.Vaddr, "image-mapping", "load is not congruent under the 4KiB page model")
		}
		// Even a zero-length logical load can map its leading partial page.
		// Do not discard such a mapping and thereby hide a file-page alias.
		if p.Memsz == 0 && p.Vaddr%4096 != 0 {
			return nil, refuse(p.Vaddr, "image-mapping", "empty partial-page load is unsupported")
		}
		for _, old := range im.loads {
			if p.Vaddr&^uint64(4095) < (old.end+4095)&^uint64(4095) && old.va&^uint64(4095) < (end+4095)&^uint64(4095) && p.Memsz != 0 {
				return nil, refuse(p.Vaddr, "image-mapping", "ambiguous overlapping PT_LOAD ranges")
			}
		}
		x := p.Flags&elf.PF_X != 0
		if x && (p.Flags&elf.PF_W != 0 || p.Flags&elf.PF_R == 0) {
			return nil, refuse(p.Vaddr, "image-mapping", "executable load must be readable and nonwritable")
		}
		if p.Memsz != 0 {
			im.loads = append(im.loads, mapping{va: p.Vaddr, end: end, off: p.Off, filesz: p.Filesz, executable: x, readable: p.Flags&elf.PF_R != 0, writable: p.Flags&elf.PF_W != 0})
		}
	}
	if len(im.loads) == 0 {
		return nil, refuse(0, "image-mapping", "no load mapping")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return im, nil
}

func plus(a, b uint64) (uint64, bool) { c := a + b; return c, c >= a }

func relative(pc uint64, rel int64) (uint64, bool) {
	if rel >= 0 {
		return plus(pc, uint64(rel))
	}
	n := uint64(-(rel + 1)) + 1
	return pc - n, pc >= n
}

func (im *Image) instructionBytes(pc uint64) ([]byte, error) {
	if im == nil {
		return nil, refuse(pc, "image-binding", "missing image")
	}
	for _, m := range im.loads {
		if pc < m.va || pc >= m.end {
			continue
		}
		delta := pc - m.va
		if !m.executable || delta >= m.filesz {
			break
		}
		n := min(uint64(15), m.filesz-delta)
		start := m.off + delta // bounded by the validated file extent
		return im.data[start : start+n], nil
	}
	return nil, refuse(pc, "instruction-mapping", fmt.Sprintf("%#x is not executable file-backed code", pc))
}

// readonlyWord uses load permissions and file bounds, never section labels. A
// second mapping of any backing page is refused, even when it is readonly: this
// finite loader model does not establish a shared-page alias relation.
func (im *Image) readonlyWord(address uint64) (uint64, Span, error) {
	end, ok := plus(address, 8)
	if im == nil || !ok || end > 1<<47 {
		return 0, Span{}, refuse(address, "descriptor-mapping", "missing image or descriptor extent overflow")
	}
	for index, m := range im.loads {
		if address < m.va || end > m.end {
			continue
		}
		delta := address - m.va
		if !m.readable || m.writable || delta > m.filesz || m.filesz-delta < 8 {
			return 0, Span{}, refuse(address, "descriptor-mapping", "descriptor must be readable, nonwritable and entirely file-backed")
		}
		start := m.off + delta
		lo, hi := start&^uint64(4095), (start+8+4095)&^uint64(4095)
		for j, alias := range im.loads {
			// A BSS load with an unaligned start can still map the preceding
			// file-page prefix. Its logical Filesz==0 does not remove that alias.
			if j != index && (alias.filesz != 0 || alias.off%4096 != 0) && lo < (alias.off+alias.filesz+4095)&^uint64(4095) && alias.off&^uint64(4095) < hi {
				return 0, Span{}, refuse(address, "descriptor-alias", "descriptor backing page has another PT_LOAD alias")
			}
		}
		return binary.LittleEndian.Uint64(im.data[start : start+8]), Span{m.va, m.end}, nil
	}
	return 0, Span{}, refuse(address, "descriptor-mapping", "descriptor crosses or misses a load boundary")
}

// Identity is ownership, not a digest comparison. Snapshots retain the same
// privately owned byte allocation; an independent reconstruction is another input.
func sameImage(a, b *Image) bool {
	return a != nil && b != nil && len(a.data) != 0 && len(a.data) == len(b.data) && &a.data[0] == &b.data[0]
}
