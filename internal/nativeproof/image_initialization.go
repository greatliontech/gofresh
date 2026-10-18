package nativeproof

import "context"

// StaticELFInitialization identifies a conditional primitive loading relation,
// not an assertion about every Linux loader. It uses ELF64 LE amd64 ET_EXEC,
// zero bias and 4096-byte pages. Each PT_LOAD maps its rounded file prefix
// privately, preserving its owned file bytes, and supplies anonymous zero pages
// for its logical BSS. A writable BSS partial page is cleared before entry or
// entry fails. A nonwritable partial-page clear may fail after partial effects;
// its entire logical BSS remains unknown here. Mapping failures preclude entry.
//
// The only image-affecting operations are those private file maps, local zero
// fills and prefix-accumulated BSS operations: for each header prefix, let F and M
// be its greatest file and memory ends. If F<M, the byte clear can affect
// [F,ceilPage(F)) and anonymous zero mapping [ceilPage(F),ceilPage(M)). Ignored
// failures may partially clear that whole byte extent, never its preceding file
// bytes. The checker excludes facts an interfering operation could overwrite.
// Additional reservations, remappings, backing mutations or pre-entry writes
// touching image pages are outside this identified model, not assumed harmless.
// Establishing that the actual loader implements this relation and that the
// process reached its entry remains a separate applicability obligation.
const StaticELFInitialization = "elf64-le-amd64/static-zero-bias-private-4k-loading@1"

const imageInitializationRules = "gofresh/image-initialization@1;" + StaticELFInitialization + ";" + FrameRules

// ImageInitialization is an opaque partial root-loading relation. Its zero value
// selects arbitrary initial image memory. It grants no access or pointer facts.
type ImageInitialization struct{ checked *checkedImageInitialization }

type initializedRange struct {
	Span
	file   bool
	offset uint64
}

type checkedImageInitialization struct {
	image  *Image
	rules  string
	ranges []initializedRange
}

// CheckImageInitialization derives compact logical file/zero coverage from the
// owned image's validated headers. It never copies image bytes or allocates BSS.
// Unsupported ranges stay unknown without invalidating independent coverage.
// The image container is captured before any caller context callback.
func CheckImageInitialization(ctx context.Context, im *Image, model string) (ImageInitialization, error) {
	im = im.snapshot()
	if ctx == nil || im == nil || len(im.data) == 0 || model != StaticELFInitialization {
		return ImageInitialization{}, refuse(0, "image-initialization", "missing image/context or unsupported loading relation")
	}
	if err := ctx.Err(); err != nil {
		return ImageInitialization{}, err
	}
	k := &checkedImageInitialization{image: im, rules: imageInitializationRules}
	// Every prefix's aggregate operation is checked, not merely the final BSS.
	// NewImage establishes disjoint virtual page operations; validateMemoryMapping
	// checks file-page backing, including zero-filesz unaligned prefixes. Thus a
	// different load's file map/local clear cannot change this load's known bytes.
	var operations []Span
	var fileEnd, memoryEnd uint64
	for _, load := range im.loads {
		if err := ctx.Err(); err != nil {
			return ImageInitialization{}, err
		}
		fileEnd = max(fileEnd, load.va+load.filesz)
		memoryEnd = max(memoryEnd, load.end)
		if fileEnd < memoryEnd {
			operations = append(operations, Span{fileEnd, pages(Span{fileEnd, memoryEnd}).End})
		}
	}
	for _, load := range im.loads {
		if err := ctx.Err(); err != nil {
			return ImageInitialization{}, err
		}
		if !load.readable {
			continue
		}
		r := ByteRegion{Bytes: Span{load.va, load.end}, Image: true, Readable: true, Writable: load.writable}
		if err := im.validateMemoryMapping(load.va, r, ctx.Err); err != nil {
			if err := ctx.Err(); err != nil {
				return ImageInitialization{}, err
			}
			continue // no backing-independence proof for this load
		}
		end := load.va + load.filesz
		candidates := []initializedRange{}
		if load.filesz != 0 {
			candidates = append(candidates, initializedRange{Span{load.va, end}, true, load.off})
		}
		if end < load.end && load.writable && !load.executable {
			candidates = append(candidates, initializedRange{Span{end, load.end}, false, 0})
		}
		for _, candidate := range candidates {
			known := true
			for _, op := range operations {
				if err := ctx.Err(); err != nil {
					return ImageInitialization{}, err
				}
				// An operation contained in this load's BSS changes only already
				// justified zeros. Anything else can clear or replace known bytes.
				if overlap(candidate.Span, op) && (candidate.file || op.Start < end || op.End > pages(Span{load.va, load.end}).End) {
					known = false
				}
			}
			if known {
				k.ranges = append(k.ranges, candidate)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return ImageInitialization{}, err
	}
	return ImageInitialization{k}, nil
}

// admitInitialization binds the root relation to this owned image and charges
// its retained coverage on both root construction and continuation import.
func (m *transitionChecker) admitInitialization() error {
	if k := m.face.Initialization.checked; k != nil {
		if k.rules != imageInitializationRules || !sameImage(k.image, m.im) {
			return refuse(m.pc, "image-initialization", "initialization rules or owned image differ")
		}
		for range k.ranges {
			if !m.tick() {
				return m.err
			}
		}
	}
	return nil
}

func (m *transitionChecker) initialImageByte(address uint64) (byte, bool) {
	k := m.face.Initialization.checked
	if k == nil {
		return 0, false
	}
	for _, r := range k.ranges {
		if !m.tick() {
			return 0, false
		}
		if address >= r.Start && address < r.End {
			if r.file {
				return k.image.data[r.offset+address-r.Start], true
			}
			return 0, true
		}
	}
	return 0, false
}
